/**
 * RavenKnowledgeProvider — Auditor Forense del Camino Rojo (CEP-402 v2)
 *
 * Regla arquitectónica Zero-Trust:
 * - El middleware Express de producción JAMÁS depende de Raven MCP ni de IA.
 * - Raven MCP (`https://raven.stellar.org/mcp`) corre exclusivamente en el
 *   Auditor del Camino Rojo para explicar bloqueos Soroban / SAC / OpenZeppelin Smart Accounts.
 * - Soporta modo LIVE (cuando hay sesión OAuth WorkOS en RAVEN_ACCESS_TOKEN)
 *   y degrada de forma explícita y honesta a VERIFIED SNAPSHOT para que `npm test`
 *   termine siempre en `# fail 0` sin depender de navegador/login interactivo.
 */

export const RAVEN_MCP_URL = 'https://raven.stellar.org/mcp';
export const SNAPSHOT_CAPTURED_AT = '2026-11-24T19:30:00Z';

const VERIFIED_KNOWLEDGE = {
  TX_NOT_FOUND_ON_CHAIN: {
    severity: 'CRITICAL',
    title: 'Liquidación Inexistente en Soroban RPC (Facilitador Comprometido / MITM)',
    cause:
      'El facilitador reportó success=true con un txHash que no existe en Soroban Testnet RPC. Un servidor x402 vanilla habría entregado el recurso gratis.',
    remediation:
      'Mantener cep402Gate() en modo fail-closed antes de paymentMiddleware y nunca confiar en PAYMENT-RESPONSE sin confirmar getTransaction(txHash) === SUCCESS.',
    stellarRef: 'https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/getTransaction',
  },
  REPLAY_COMMITTED: {
    severity: 'HIGH',
    title: 'Ataque de Replay Bloqueado (409 Conflict)',
    cause:
      'El txHash ya fue verificado y liquidado en una petición anterior (registrado en AtomicReplayStore con persistencia NDJSON).',
    remediation:
      'El cliente o agente debe firmar un nuevo SorobanAuthorizationEntry con nonce fresco; nunca reciclar recibos previos.',
    stellarRef: 'https://developers.stellar.org/docs/learn/fundamentals/contract-development/authorization',
  },
  REPLAY_IN_FLIGHT: {
    severity: 'HIGH',
    title: 'Ráfaga de Replay Paralelo Neutralizada (Lock Síncrono 409)',
    cause:
      'Múltiples peticiones concurrentes intentaron consumir el mismo txHash simultáneamente para explotar una race condition (TOCTOU).',
    remediation:
      'AtomicReplayStore.tryAcquireSync() bloquea síncronamente antes del primer await a Soroban RPC, permitiendo exactamente 1 ejecución.',
    stellarRef: 'https://developers.stellar.org/docs/learn/fundamentals/contract-development/authorization',
  },
  WRONG_ASSET_OR_NO_TRANSFER: {
    severity: 'CRITICAL',
    title: 'Contrato SAC Inválido / Token Impostor (Fake-USDC)',
    cause:
      'La transacción no emitió un evento transfer desde el Stellar Asset Contract (SAC) canónico de USDC en Testnet.',
    remediation:
      'Derivar siempre el contractId canónico vía new Asset("USDC", ISSUER).contractId(Networks.TESTNET) y rechazar cualquier otro contrato aunque tenga symbol="USDC".',
    stellarRef: 'https://developers.stellar.org/docs/tokens/stellar-asset-contract',
  },
  UNDERPAID: {
    severity: 'CRITICAL',
    title: 'Pago Insuficiente Detectado en BigInt Stroops',
    cause:
      'El monto neto transferido al comercio en el evento SAC (7 decimales en Stellar) es menor al precio exacto requerido por la ruta x402.',
    remediation:
      'Validar montos exclusivamente en BigInt stroops (0.01 USDC = 100000n) manejando tanto i128 como CAP-67 Map { amount, to_muxed_id }.',
    stellarRef: 'https://developers.stellar.org/docs/tokens/stellar-asset-contract',
  },
  LEDGER_EXPIRED: {
    severity: 'HIGH',
    title: 'Ventana de Frescura de Ledger Excedida (> 60 Ledgers)',
    cause:
      'El txHash pertenece a un ledger antiguo (~>5 min). Aceptarlo permitiría reciclar pagos históricos tras un reinicio o limpieza.',
    remediation:
      'Exigir latestLedger - tx.ledger <= 60 usando los campos atómicos devueltos por getTransaction().',
    stellarRef: 'https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/getTransaction',
  },
  BODY_HASH_MISMATCH: {
    severity: 'CRITICAL',
    title: 'Alteración de Payload Post-Pago Detectada (TAMPERED)',
    cause:
      'El SHA-256 de los bytes crudos recibidos no coincide con response.bodySha256 sellado en el recibo Ed25519 CEP-402.',
    remediation:
      'Rechazar la respuesta por violación de integridad y conservar el recibo CEP-402 firmado como evidencia de no-repudio.',
    stellarRef: 'https://developers.stellar.org/docs/learn/encyclopedia/security/cryptography',
  },
  SMART_ACCOUNT_POLICY_3221: {
    severity: 'HIGH',
    title: 'Smart Account OpenZeppelin (C...) — Diagnóstico CAP-46 & Error #3221',
    cause:
      'Una Smart Account OpenZeppelin en Soroban autoriza transferencias vía __check_auth + Context Rules + SpendingLimitPolicy. Al superar el presupuesto acumulado de la ventana de ledgers, Soroban revierte con HostError Error(Contract, #3221) SpendingLimitExceeded antes de mover fondos.',
    remediation:
      'Verificar que el facilitador firme como Fee Sponsor (G...) mientras C... provee sorobanCredentialsAddress; para ajustar el límite, el CFO/Admin (Rule #0 Default) debe actualizar la SpendingLimitPolicy sin exponer llaves maestras al agente.',
    stellarRef: 'https://docs.openzeppelin.com/stellar-contracts/accounts/smart-account',
  },
};

export class RavenKnowledgeProvider {
  constructor({
    mcpUrl = RAVEN_MCP_URL,
    accessToken = process.env.RAVEN_ACCESS_TOKEN || '',
    timeoutMs = 2500,
    fetchImpl = fetch,
    mode = 'auto', // 'auto' | 'live' | 'snapshot'
  } = {}) {
    this.mcpUrl = mcpUrl;
    this.accessToken = accessToken;
    this.timeoutMs = timeoutMs;
    this.fetchImpl = fetchImpl;
    this.mode = mode;
    this._cooldownUntil = 0;
  }

  async diagnose(errorCode, context = {}) {
    const normalizedCode = VERIFIED_KNOWLEDGE[errorCode] ? errorCode : 'SMART_ACCOUNT_POLICY_3221';
    const snapshot = VERIFIED_KNOWLEDGE[normalizedCode];
    const query = `Stellar Soroban x402 ${normalizedCode} ${context.detail || ''} OpenZeppelin smart account CAP-67 SAC`.trim();

    const shouldTryLive =
      this.mode !== 'snapshot' &&
      Boolean(this.accessToken) &&
      Date.now() >= this._cooldownUntil;

    if (shouldTryLive) {
      try {
        const live = await this._queryLiveMcp(query);
        if (live) {
          return {
            source: 'LIVE_RAVEN_MCP',
            badge: 'RAVEN MCP: LIVE',
            mcpEndpoint: this.mcpUrl,
            errorCode: normalizedCode,
            ...snapshot,
            liveExcerpt: live,
            evaluatedAt: new Date().toISOString(),
          };
        }
      } catch {
        // Circuit-breaker de 5 min si WorkOS OAuth devuelve 401/timeout
        this._cooldownUntil = Date.now() + 5 * 60 * 1000;
      }
    }

    return {
      source: 'VERIFIED_SNAPSHOT',
      badge: `RAVEN VERIFIED SNAPSHOT (${SNAPSHOT_CAPTURED_AT.slice(0, 10)})`,
      mcpEndpoint: this.mcpUrl,
      oauthNote: this.accessToken
        ? 'Fallback automático por timeout/OAuth de Raven MCP.'
        : 'Sin RAVEN_ACCESS_TOKEN en .env — usando snapshot verificado de Raven MCP (conecta https://raven.stellar.org/mcp vía mcp.json para modo live).',
      errorCode: normalizedCode,
      ...snapshot,
      evaluatedAt: new Date().toISOString(),
    };
  }

  async _queryLiveMcp(query) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await this.fetchImpl(this.mcpUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
          Authorization: `Bearer ${this.accessToken}`,
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: {
            name: 'search',
            arguments: { query },
          },
        }),
        signal: controller.signal,
      });

      if (!res.ok) throw new Error(`Raven MCP HTTP ${res.status}`);
      const text = await res.text();
      if (!text.trim()) return null;
      try {
        const parsed = JSON.parse(text);
        const content = parsed?.result?.content?.[0]?.text;
        return typeof content === 'string' ? content.slice(0, 420) : text.slice(0, 420);
      } catch {
        return text.slice(0, 420);
      }
    } finally {
      clearTimeout(timer);
    }
  }
}
