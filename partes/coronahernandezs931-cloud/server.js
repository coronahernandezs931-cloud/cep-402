import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { Keypair, rpc } from '@stellar/stellar-sdk';
import { paymentMiddleware, x402ResourceServer } from '@x402/express';
import { ExactStellarScheme as ExactStellarServerScheme } from '@x402/stellar/exact/server';
import { ExactStellarScheme as ExactStellarClientScheme } from '@x402/stellar/exact/client';
import { createEd25519Signer } from '@x402/stellar';
import { x402Client, wrapFetchWithPayment } from '@x402/fetch';

import {
  USDC_SAC_TESTNET,
  STELLAR_EXPERT_TX_BASE,
  diagnoseSmartAccount,
  verifyOnChainSettlement,
} from './stellar-extractor.js';
import { AtomicReplayStore } from './replay-store.js';
import {
  canonicalize,
  sha256Hex,
  stellarPublicKeyToSpkiBase64,
  verifyReceiptOffline,
  verifyReceiptZeroTrust,
} from './receipt.js';
import { RavenKnowledgeProvider } from './auditor-raven.js';
import { attachCep402AfterSettleHook, createCep402Gate } from './express-gate.js';
import { DualFacilitatorClient, createFacilitatorRouter } from './facilitator.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const NETWORK = 'stellar:testnet';
const DEFAULT_RPC_URL = 'https://soroban-testnet.stellar.org';
const DEFAULT_PRICE = '$0.01'; // 100_000 stroops USDC (7 decimales)

/**
 * Mutex FIFO por llave pública para evitar colisiones `tx_bad_seq` ante doble clic en vivo.
 */
function createAsyncMutex() {
  let chain = Promise.resolve();
  return function runExclusive(fn) {
    const next = chain.then(fn, fn);
    chain = next.catch(() => {});
    return next;
  };
}

/**
 * Construye el payload HTTP 402 firmado (o payload mínimo bajo modo corrupto) para demostraciones
 * sin tener que quemar fondos adicionales al probar ataques contra un facilitador comprometido.
 */
function buildDummyCorruptPaymentHeader(requirements) {
  const payload = {
    x402Version: 2,
    accepted: requirements,
    payload: { transaction: 'AAAA_CORRUPT_FACILITATOR_SIMULATION_ONLY' },
  };
  return Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
}

export async function createCep402App({
  merchantSecret = process.env.MI_SECRETA,
  merchantPublic = process.env.MI_PUBLICA,
  payerSecret = process.env.PAYER_SECRETA || process.env.AMIGO_SECRETA,
  facilitatorSecret = process.env.FACILITATOR_SECRETA || process.env.AGENTE_SECRETA,
  rpcUrl = process.env.SOROBAN_RPC_URL || DEFAULT_RPC_URL,
  rpcServer = null,
  replayStore = null,
  replayFilePath = null,
  inMemoryReplay = false,
  facilitatorClient = null,
  ravenProvider = null,
  price = DEFAULT_PRICE,
  maxLedgerAge = 60,
  pollDelaysMs,
  smartAccountTarget = process.env.SMART_ACCOUNT_C || USDC_SAC_TESTNET,
} = {}) {
  // Generamos llaves efímeras deterministas solo si se corre sin .env (tests offline)
  const merchantKp = merchantSecret
    ? Keypair.fromSecret(merchantSecret)
    : Keypair.fromRawEd25519Seed(Buffer.alloc(32, 7));
  const payTo = merchantPublic || merchantKp.publicKey();
  const effectiveMerchantSecret = merchantKp.secret();

  const effectiveRpc = rpcServer || new rpc.Server(rpcUrl);
  const store =
    replayStore ||
    new AtomicReplayStore({
      filePath: inMemoryReplay ? null : replayFilePath || path.join(process.cwd(), 'cep402-replay.ndjson'),
      inMemory: inMemoryReplay,
    });

  const facilitator =
    facilitatorClient ||
    new DualFacilitatorClient({
      facilitatorSecret: facilitatorSecret || null,
      rpcUrl,
      network: NETWORK,
    });

  const raven = ravenProvider || new RavenKnowledgeProvider();
  const payerMutex = createAsyncMutex();

  const metrics = {
    realPaymentsSettled: 0,
    attacksBlockedByCep402: 0,
    vanillaHacksSuffered: 0,
    cep402UsdcLost: '0.00',
    lastReceipt: null,
    lastRawBody: null,
    recentAuditEvents: [],
  };

  const pushAudit = (ev) => {
    metrics.recentAuditEvents.unshift({ at: new Date().toISOString(), ...ev });
    if (metrics.recentAuditEvents.length > 20) metrics.recentAuditEvents.pop();
    if (ev.type === 'BLOCKED') metrics.attacksBlockedByCep402 += 1;
    if (ev.type === 'VERIFIED') metrics.realPaymentsSettled += 1;
  };

  // --- 1. Servidor x402 VANILLA (confía ciegamente en el facilitador) ---
  const vanillaResourceServer = new x402ResourceServer(facilitator).register(
    NETWORK,
    new ExactStellarServerScheme()
  );
  await vanillaResourceServer.initialize();

  // --- 2. Servidor x402 PROTEGIDO POR CEP-402 (7 invariantes en Soroban RPC) ---
  const cepResourceServer = new x402ResourceServer(facilitator).register(
    NETWORK,
    new ExactStellarServerScheme()
  );
  attachCep402AfterSettleHook(cepResourceServer, {
    rpcServer: effectiveRpc,
    replayStore: store,
    expectedAssetContract: USDC_SAC_TESTNET,
    maxLedgerAge,
    pollDelaysMs,
    onAuditEvent: pushAudit,
  });
  await cepResourceServer.initialize();

  const app = express();
  app.set('etag', false);
  app.use(express.json({ limit: '1mb' }));

  // Anti-caché estricto para /api/* (evita 304 que rompería bodySha256)
  app.use('/api', (_req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    next();
  });

  // --- Facilitador HTTP estándar (mismo origen) ---
  app.use('/facilitator', createFacilitatorRouter(facilitator));

  // --- Ruta 1: x402 VANILLA (sin CEP-402) ---
  app.use(
    paymentMiddleware(
      {
        'GET /api/vanilla/dato': {
          accepts: { scheme: 'exact', price, network: NETWORK, payTo },
          description: 'Endpoint x402 Vanilla (sin verificación independiente en Soroban RPC)',
        },
      },
      vanillaResourceServer,
      undefined,
      undefined,
      false
    )
  );
  app.get('/api/vanilla/dato', (_req, res) => {
    if (facilitator.mode !== 'HONEST') {
      metrics.vanillaHacksSuffered += 1;
    }
    res.json({
      servidor: 'x402 Vanilla (SIN CEP-402)',
      dato: 'Reporte Premium de Liquidez USDC/MXN en Stellar — Entregado',
      confianzaEnFacilitador: 'CIEGA',
      advertencia:
        facilitator.mode !== 'HONEST'
          ? 'PELIGRO: Recurso entregado gratis ante facilitador comprometido ($0.00 USDC recibidos on-chain)'
          : 'Recurso entregado sin recibo criptográfico auditable',
      timestamp: new Date().toISOString(),
    });
  });

  // --- Ruta 2: x402 PROTEGIDO CON CEP-402 (1 línea antes de paymentMiddleware!) ---
  app.use(
    createCep402Gate({
      merchantSecret: effectiveMerchantSecret,
      network: NETWORK,
      isProtected: (req) => req.method === 'GET' && req.path === '/api/cep402/dato',
      onReceiptIssued: (envelope, rawBody) => {
        metrics.lastReceipt = envelope;
        metrics.lastRawBody = rawBody.toString('utf8');
      },
    })
  );
  app.use(
    paymentMiddleware(
      {
        'GET /api/cep402/dato': {
          accepts: { scheme: 'exact', price, network: NETWORK, payTo },
          description: 'Endpoint protegido por CEP-402 (7 invariantes Soroban RPC + recibo Ed25519)',
        },
      },
      cepResourceServer,
      undefined,
      undefined,
      false
    )
  );
  app.get('/api/cep402/dato', (_req, res) => {
    res.json({
      servidor: 'CEP-402 Guard (Zero-Trust Soroban RPC)',
      dato: 'Reporte Premium de Liquidez USDC/MXN en Stellar — Certificado',
      proteccion: '7 invariantes verificadas on-chain + Recibo Ed25519 CEP-402',
      timestamp: new Date().toISOString(),
    });
  });

  // --- Endpoints de Administración, Diagnóstico y Demo Day ---
  app.get('/api/health', (_req, res) => {
    const payerPub = payerSecret ? Keypair.fromSecret(payerSecret).publicKey() : null;
    const facPub = facilitatorSecret ? Keypair.fromSecret(facilitatorSecret).publicKey() : null;
    res.json({
      ok: true,
      project: 'CEP-402 v2',
      track: 'Verificación de pagos',
      network: NETWORK,
      rpcUrl,
      usdcSacTestnet: USDC_SAC_TESTNET,
      merchantPublicKey: payTo,
      merchantSpkiBase64: stellarPublicKeyToSpkiBase64(payTo),
      payerConfigured: Boolean(payerPub),
      payerPublicKey: payerPub,
      facilitatorConfigured: Boolean(facPub),
      facilitatorPublicKey: facPub,
      smartAccountTarget,
      facilitator: facilitator.getState(),
      replayStats: store.stats(),
      metrics: {
        realPaymentsSettled: metrics.realPaymentsSettled,
        attacksBlockedByCep402: metrics.attacksBlockedByCep402,
        vanillaHacksSuffered: metrics.vanillaHacksSuffered,
        cep402UsdcLost: metrics.cep402UsdcLost,
        hasLastReceipt: Boolean(metrics.lastReceipt),
      },
    });
  });

  app.post('/api/admin/mode', (req, res) => {
    try {
      const { mode, lastRealTxHash, underpayTxHash, fakeSacTxHash } = req.body ?? {};
      const state = facilitator.setMode(mode, { lastRealTxHash, underpayTxHash, fakeSacTxHash });
      res.json({ ok: true, facilitator: state });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    }
  });

  app.post('/api/admin/reset-metrics', (_req, res) => {
    facilitator.setMode('HONEST');
    metrics.attacksBlockedByCep402 = 0;
    metrics.vanillaHacksSuffered = 0;
    metrics.recentAuditEvents = [];
    res.json({ ok: true, facilitator: facilitator.getState() });
  });

  app.get('/api/last-receipt', (_req, res) => {
    if (!metrics.lastReceipt) {
      return res.status(404).json({ ok: false, error: 'Aún no se ha emitido ningún recibo CEP-402.' });
    }
    res.json({
      ok: true,
      receipt: metrics.lastReceipt,
      rawBody: metrics.lastRawBody,
    });
  });

  app.post('/api/verify-receipt', async (req, res) => {
    try {
      const { receipt, rawBody, offlineOnly = false } = req.body ?? {};
      const rawBuf = typeof rawBody === 'string' ? Buffer.from(rawBody, 'utf8') : null;
      const result = offlineOnly
        ? verifyReceiptOffline(receipt, rawBuf, payTo)
        : await verifyReceiptZeroTrust(effectiveRpc, receipt, rawBuf, {
            pinnedMerchantPubKey: payTo,
            expectedAssetContract: USDC_SAC_TESTNET,
          });
      const ravenDiag = result.ok ? null : await raven.diagnose(result.code, { detail: result.detail });
      res.json({ ...result, ravenDiagnostic: ravenDiag });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    }
  });

  app.post('/api/smart-account/diagnose', async (req, res) => {
    const target = req.body?.contractId || smartAccountTarget;
    const facPub = facilitatorSecret ? Keypair.fromSecret(facilitatorSecret).publicKey() : payTo;
    const diagnosis = await diagnoseSmartAccount(effectiveRpc, target, {
      simulationSourcePublicKey: facPub,
      expectedAssetContract: USDC_SAC_TESTNET,
    });
    const ravenDiag = await raven.diagnose('SMART_ACCOUNT_POLICY_3221', {
      detail: `contractId=${target} exists=${diagnosis.existsOnTestnet}`,
    });
    res.json({ ...diagnosis, ravenDiagnostic: ravenDiag });
  });

  app.post('/api/raven/diagnose', async (req, res) => {
    const { errorCode = 'TX_NOT_FOUND_ON_CHAIN', detail = '' } = req.body ?? {};
    const diag = await raven.diagnose(errorCode, { detail });
    res.json({ ok: true, diagnostic: diag });
  });

  // Helper interno: obtiene la URL base propia del servidor Express escuchando
  const getBaseUrl = (req) => `${req.protocol}://${req.get('host')}`;

  // --- Acción Demo 1: Duelo Split-Screen con Simulador de Facilitador Comprometido ---
  app.post('/api/demo/corrupt-duel', async (req, res) => {
    const mode = req.body?.mode || 'FAKE_SETTLE';
    const baseUrl = getBaseUrl(req);
    const prevMode = facilitator.mode;
    try {
      facilitator.setMode(mode);

      // Obtenemos el PaymentRequirements real del 402 para armar el header
      const probe = await fetch(`${baseUrl}/api/cep402/dato`);
      const reqHeader = probe.headers.get('payment-required');
      const parsedReq = reqHeader ? JSON.parse(Buffer.from(reqHeader, 'base64').toString('utf8')) : null;
      const accepted = parsedReq?.accepts?.[0];
      const fakeSigHeader = buildDummyCorruptPaymentHeader(accepted);

      const [vanillaRes, cepRes] = await Promise.all([
        fetch(`${baseUrl}/api/vanilla/dato`, { headers: { 'PAYMENT-SIGNATURE': fakeSigHeader } }),
        fetch(`${baseUrl}/api/cep402/dato`, { headers: { 'PAYMENT-SIGNATURE': fakeSigHeader } }),
      ]);

      const [vanillaBody, cepBody] = await Promise.all([vanillaRes.json(), cepRes.json()]);
      const ravenDiag = await raven.diagnose(cepBody?.error || 'TX_NOT_FOUND_ON_CHAIN', {
        detail: cepBody?.detail || '',
      });

      res.json({
        ok: true,
        simulatedMode: mode,
        disclaimer: 'Simulador local explícito de Facilitador Comprometido / MITM.',
        vanilla: {
          status: vanillaRes.status,
          hacked: vanillaRes.status === 200,
          usdcReceivedOnChain: '0.00',
          body: vanillaBody,
        },
        cep402: {
          status: cepRes.status,
          blocked: cepRes.status >= 400,
          usdcLost: '0.00',
          body: cepBody,
        },
        ravenDiagnostic: ravenDiag,
      });
    } finally {
      facilitator.setMode(prevMode);
    }
  });

  // --- Acción Demo 2: Pago REAL en Stellar Testnet vía @x402/fetch ---
  app.post('/api/demo/pay-live', async (req, res) => {
    if (!payerSecret || !facilitatorSecret) {
      return res.status(400).json({
        ok: false,
        error: 'MISSING_TESTNET_KEYS',
        detail: 'Configura PAYER_SECRETA y FACILITATOR_SECRETA en .env para ejecutar pagos live en Stellar Testnet.',
      });
    }

    const baseUrl = getBaseUrl(req);
    const t0 = Date.now();

    try {
      const outcome = await payerMutex(async () => {
        facilitator.setMode('HONEST');
        const signer = createEd25519Signer(payerSecret, NETWORK);
        const client = x402Client.fromConfig({
          schemes: [{ network: 'stellar:*', client: new ExactStellarClientScheme(signer, { url: rpcUrl }) }],
          spendControls: { maxAmountPerPayment: '$0.05' },
        });
        const fetchWithPay = wrapFetchWithPayment(fetch, client);

        const paidRes = await fetchWithPay(`${baseUrl}/api/cep402/dato`);
        const rawText = await paidRes.text();
        const receiptB64 = paidRes.headers.get('x-cep402-receipt');
        const receipt = receiptB64
          ? JSON.parse(Buffer.from(receiptB64, 'base64url').toString('utf8'))
          : null;

        let bodyParsed = null;
        try {
          bodyParsed = JSON.parse(rawText);
        } catch {
          bodyParsed = rawText;
        }

        return {
          status: paidRes.status,
          elapsedMs: Date.now() - t0,
          rawBody: rawText,
          body: bodyParsed,
          receipt,
          txHash: paidRes.headers.get('x-cep402-tx-hash') || receipt?.payload?.txHash || null,
          stellarExpertUrl: receipt?.payload?.stellarExpertUrl || null,
        };
      });

      if (outcome.status !== 200) {
        return res.status(outcome.status).json({ ok: false, ...outcome });
      }
      res.json({ ok: true, ...outcome });
    } catch (err) {
      res.status(502).json({
        ok: false,
        error: 'LIVE_PAYMENT_FAILED',
        detail: err?.message ?? String(err),
        elapsedMs: Date.now() - t0,
      });
    }
  });

  // --- Acción Demo 3: Metralleta de 3 Ataques en <4s ---
  app.post('/api/demo/attack-gauntlet', async (req, res) => {
    const baseUrl = getBaseUrl(req);
    const t0 = Date.now();
    const prevMode = facilitator.mode;

    try {
      const replayTxHash =
        req.body?.txHash ||
        metrics.lastReceipt?.payload?.txHash ||
        facilitator.seeds.lastRealTxHash ||
        'a'.repeat(64);

      const probe = await fetch(`${baseUrl}/api/cep402/dato`);
      const reqHeader = probe.headers.get('payment-required');
      const parsedReq = reqHeader ? JSON.parse(Buffer.from(reqHeader, 'base64').toString('utf8')) : null;
      const accepted = parsedReq?.accepts?.[0];
      const sigHeader = buildDummyCorruptPaymentHeader(accepted);

      // Ataque 1: Ráfaga 5x Replay Paralelo (Promise.all) contra Vanilla y CEP-402
      facilitator.setMode('REPLAY_OLD_TX', { lastRealTxHash: replayTxHash });
      const [vanillaBurst, cepBurst] = await Promise.all([
        Promise.all(
          Array.from({ length: 5 }, () =>
            fetch(`${baseUrl}/api/vanilla/dato`, { headers: { 'PAYMENT-SIGNATURE': sigHeader } }).then(
              (r) => r.status
            )
          )
        ),
        Promise.all(
          Array.from({ length: 5 }, () =>
            fetch(`${baseUrl}/api/cep402/dato`, { headers: { 'PAYMENT-SIGNATURE': sigHeader } }).then(
              async (r) => ({ status: r.status, body: await r.json() })
            )
          )
        ),
      ]);

      // Ataque 2: Tampering de 1 byte en el payload del recibo CEP-402
      let tamperCheck;
      if (metrics.lastReceipt && metrics.lastRawBody) {
        const tamperedBody = `${metrics.lastRawBody.slice(0, -1)} `; // altera exactamente 1 byte
        tamperCheck = verifyReceiptOffline(metrics.lastReceipt, Buffer.from(tamperedBody, 'utf8'), payTo);
      } else {
        tamperCheck = {
          ok: false,
          code: 'BODY_HASH_MISMATCH',
          detail: 'Simulación de alteración de 1 byte (ejecuta primero un Pago Real para probar sobre tu recibo vivo).',
        };
      }

      // Ataque 3: Facilitador corrupto (FAKE_SETTLE) + Forense Smart Account C... + Raven MCP
      facilitator.setMode('FAKE_SETTLE');
      const [fakeVanilla, fakeCep] = await Promise.all([
        fetch(`${baseUrl}/api/vanilla/dato`, { headers: { 'PAYMENT-SIGNATURE': sigHeader } }),
        fetch(`${baseUrl}/api/cep402/dato`, { headers: { 'PAYMENT-SIGNATURE': sigHeader } }),
      ]);
      const fakeCepBody = await fakeCep.json();
      const facPub = facilitatorSecret ? Keypair.fromSecret(facilitatorSecret).publicKey() : payTo;
      const smartDiag = await diagnoseSmartAccount(effectiveRpc, smartAccountTarget, {
        simulationSourcePublicKey: facPub,
      });
      const ravenDiag = await raven.diagnose('SMART_ACCOUNT_POLICY_3221', {
        detail: `gauntlet replay=${replayTxHash.slice(0, 12)} fake=${fakeCepBody.error}`,
      });

      res.json({
        ok: true,
        elapsedMs: Date.now() - t0,
        attack1_parallelReplay5x: {
          txHashReused: replayTxHash,
          vanillaStatuses: vanillaBurst,
          vanillaLootedCount: vanillaBurst.filter((s) => s === 200).length,
          cep402Statuses: cepBurst.map((x) => x.status),
          cep402BlockedCount: cepBurst.filter((x) => x.status === 409 || x.status === 403).length,
          sampleCep402Error: cepBurst[0]?.body?.error || 'REPLAY_COMMITTED',
        },
        attack2_tampering1Byte: tamperCheck,
        attack3_corruptFacilitatorAndSmartAccount: {
          vanillaStatus: fakeVanilla.status,
          cep402Status: fakeCep.status,
          cep402Error: fakeCepBody.error,
          smartAccountForensics: smartDiag,
          ravenDiagnostic: ravenDiag,
        },
      });
    } finally {
      facilitator.setMode(prevMode);
    }
  });

  // --- UI Split-Screen (Single-Origin) ---
  app.use(express.static(path.join(__dirname, 'public')));

  // Error handler JSON (Express 5 — 4 argumentos)
  app.use((err, _req, res, _next) => {
    res.status(err?.status || 500).json({
      ok: false,
      error: 'INTERNAL_SERVER_ERROR',
      detail: err?.message ?? 'Error inesperado',
    });
  });

  return {
    app,
    facilitator,
    replayStore: store,
    rpcServer: effectiveRpc,
    raven,
    merchantPublicKey: payTo,
    closeResources: () => store.close(),
  };
}

export async function startCep402Server(options = {}) {
  const port = options.port ?? Number(process.env.PORT || 3000);
  const ctx = await createCep402App(options);
  const server = await new Promise((resolve) => {
    const s = ctx.app.listen(port, '127.0.0.1', () => resolve(s));
  });
  const addr = server.address();
  const actualPort = typeof addr === 'object' && addr ? addr.port : port;
  const url = `http://127.0.0.1:${actualPort}`;

  const close = async () => {
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(resolve));
    ctx.closeResources();
  };

  return { ...ctx, server, port: actualPort, url, close };
}

// Arranque directo desde CLI: `npm start` o `node --env-file-if-exists=.env partes/.../server.js`
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const srv = await startCep402Server();
  console.log(`\n🛡️  CEP-402 v2 listo en ${srv.url}`);
  console.log(`   • UI Split-Screen:       ${srv.url}/`);
  console.log(`   • x402 Vanilla:          ${srv.url}/api/vanilla/dato`);
  console.log(`   • CEP-402 Protegido:     ${srv.url}/api/cep402/dato`);
  console.log(`   • Facilitador Dual x402: ${srv.url}/facilitator/supported`);
  console.log(`   • Comercio (PAY_TO):     ${srv.merchantPublicKey}`);
  console.log(`   • SAC USDC Testnet:      ${USDC_SAC_TESTNET}\n`);
}
