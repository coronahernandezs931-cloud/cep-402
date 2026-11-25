import {
  rpc,
  xdr,
  Asset,
  Address,
  Contract,
  Networks,
  StrKey,
  TransactionBuilder,
  scValToNative,
} from '@stellar/stellar-sdk';

export const USDC_ISSUER_TESTNET = 'GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5';
export const USDC_SAC_TESTNET = new Asset('USDC', USDC_ISSUER_TESTNET).contractId(Networks.TESTNET);
export const DEFAULT_MAX_LEDGER_AGE = 60; // ~5 minutos en Stellar (~5s/ledger)
export const STELLAR_EXPERT_TX_BASE = 'https://stellar.expert/explorer/testnet/tx/';
export const STELLAR_EXPERT_CONTRACT_BASE = 'https://stellar.expert/explorer/testnet/contract/';

const POLL_DELAYS_MS = [0, 450, 750]; // hasta ~1.2s absorbiendo propagación RPC sin frenar la demo

/**
 * Normaliza XDR de `@stellar/stellar-sdk@17.4.0` (base64, instancia XDR v17 o JSON SEP-0050).
 */
export function toXdrJson(val, Type) {
  if (val == null) return null;
  if (typeof val === 'string') {
    const parsed = Type.fromXDR(val, 'base64');
    return JSON.parse(JSON.stringify(parsed));
  }
  return JSON.parse(JSON.stringify(val));
}

/**
 * Extrae `G...` desde una dirección clásica o muxed (`M...` o objeto muxed) en JSON XDR v17.
 */
export function normalizeStellarAccountAddress(raw) {
  if (!raw) return null;
  if (typeof raw === 'string') {
    if (StrKey.isValidMed25519PublicKey(raw)) {
      const decoded = StrKey.decodeMed25519PublicKey(raw);
      return StrKey.encodeEd25519PublicKey(decoded.subarray(0, 32));
    }
    return raw;
  }
  if (typeof raw === 'object') {
    return raw.ed25519 || raw.account_id || raw.address || null;
  }
  return null;
}

export function inspectSorobanAuthEntries(operations = []) {
  const found = [];
  for (const op of operations) {
    const invoke = op?.body?.invoke_host_function;
    if (!invoke) continue;
    for (const entry of invoke.auth ?? []) {
      const rootFn = entry?.root_invocation?.function?.contract_fn;
      const invokedContract = rootFn?.contract_address ?? null;
      const invokedFn = rootFn?.function_name ?? null;
      const addrCred = entry?.credentials?.address;
      if (addrCred) {
        const addr = addrCred.address ?? null;
        const sigObj = addrCred.signature;
        const signatureScValType =
          sigObj && typeof sigObj === 'object' ? Object.keys(sigObj)[0] || 'unknown' : String(sigObj);
        found.push({
          credentialsType: 'address',
          address: addr,
          isSmartAccount: Boolean(addr && StrKey.isValidContract(addr)),
          nonce: String(addrCred.nonce ?? ''),
          signatureExpirationLedger: Number(addrCred.signature_expiration_ledger ?? 0),
          signatureScValType,
          invokedContract,
          invokedFn,
        });
      } else {
        found.push({
          credentialsType: 'source_account',
          address: null,
          isSmartAccount: false,
          invokedContract,
          invokedFn,
        });
      }
    }
  }
  return found;
}

export function extractEnvelopeInfo(envelopeXdr) {
  const env = toXdrJson(envelopeXdr, xdr.TransactionEnvelope);
  if (!env || typeof env !== 'object') {
    throw new Error('Envelope XDR vacío o inválido');
  }

  let isFeeBump = false;
  let feeSponsor = null;
  let innerTx = null;

  if (env.tx_fee_bump?.tx) {
    isFeeBump = true;
    feeSponsor = normalizeStellarAccountAddress(env.tx_fee_bump.tx.fee_source);
    innerTx = env.tx_fee_bump.tx.inner_tx?.tx?.tx ?? env.tx_fee_bump.tx.inner_tx?.tx ?? null;
  } else if (env.tx?.tx) {
    innerTx = env.tx.tx;
    feeSponsor = normalizeStellarAccountAddress(innerTx.source_account);
  } else if (env.tx_v0?.tx) {
    innerTx = env.tx_v0.tx;
    feeSponsor = normalizeStellarAccountAddress(innerTx.source_account_ed25519);
  } else {
    throw new Error(`Tipo de envelope no soportado: ${Object.keys(env).join(', ')}`);
  }

  const txSource = normalizeStellarAccountAddress(innerTx?.source_account);
  const authEntries = inspectSorobanAuthEntries(innerTx?.operations ?? []);
  return { isFeeBump, feeSponsor, txSource, authEntries };
}

export function extractContractEvents(tx) {
  // Ruta 1 (Preferida RPC Protocol 23+): tx.events.contractEventsXdr es ContractEvent[][]
  const rpcEvents = tx?.events?.contractEventsXdr;
  if (Array.isArray(rpcEvents) && rpcEvents.length > 0) {
    return rpcEvents
      .flat()
      .map((ev) => toXdrJson(ev, xdr.ContractEvent))
      .filter((ev) => ev?.type === 'contract');
  }

  // Ruta 2 (Fallback determinístico): resultMetaXdr V4 (Protocol 23 / CAP-67) o V3
  if (!tx?.resultMetaXdr) return [];
  const meta = toXdrJson(tx.resultMetaXdr, xdr.TransactionMeta);
  if (meta?.v4?.operations) {
    return meta.v4.operations
      .flatMap((opMeta) => opMeta?.events ?? [])
      .filter((ev) => ev?.type === 'contract');
  }
  if (meta?.v3?.soroban_meta?.events) {
    return meta.v3.soroban_meta.events.filter((ev) => ev?.type === 'contract');
  }
  return [];
}

/**
 * Normaliza el campo `data` de un evento SAC `transfer` soportando:
 * - `i128` directo (classic/Soroban estándar): `{ i128: "100000" }` o `{ i128: { hi, lo } }`
 * - CAP-67 Muxed Transfer (`map`): `{ map: [{ key: { symbol: "amount" }, val: { i128: "100000" } }, { key: { symbol: "to_muxed_id" }, val: { u64: "42" } }] }`
 */
export function normalizeCap67Amount(dataJson) {
  const parseI128 = (raw) => {
    if (typeof raw === 'bigint') return raw;
    if (typeof raw === 'string' || typeof raw === 'number') return BigInt(raw);
    if (raw && typeof raw === 'object' && 'hi' in raw && 'lo' in raw) {
      return (BigInt(raw.hi) << 64n) + BigInt.asUintN(64, BigInt(raw.lo));
    }
    throw new Error(`Formato i128 no soportado: ${JSON.stringify(raw)}`);
  };

  if (dataJson && typeof dataJson === 'object' && 'i128' in dataJson) {
    return { amount: parseI128(dataJson.i128), toMuxedId: null, cap67Wrapped: false };
  }

  if (dataJson && typeof dataJson === 'object' && Array.isArray(dataJson.map)) {
    let amount = null;
    let toMuxedId = null;
    for (const entry of dataJson.map) {
      const k = entry?.key?.symbol;
      if (k === 'amount' && entry?.val && 'i128' in entry.val) {
        amount = parseI128(entry.val.i128);
      } else if (k === 'to_muxed_id' && entry?.val) {
        const v = entry.val;
        toMuxedId = String(v.u64 ?? v.bytes ?? v.string ?? v.i128 ?? Object.values(v)[0] ?? '');
      }
    }
    if (amount === null) throw new Error('Evento CAP-67 map no contiene amount i128');
    return { amount, toMuxedId, cap67Wrapped: true };
  }

  throw new Error(`Tipo de data SAC no soportado: ${JSON.stringify(dataJson)}`);
}

export function extractSacTransfers(tx, expectedAssetContract = USDC_SAC_TESTNET) {
  const events = extractContractEvents(tx);
  const transfers = [];
  const observedContracts = new Set();

  for (const ev of events) {
    const contractId = ev?.contract_id;
    if (!contractId) continue;
    observedContracts.add(contractId);
    if (contractId !== expectedAssetContract) continue; // Invariante: SAC USDC canónico

    const topics = ev?.body?.v0?.topics;
    if (!Array.isArray(topics) || topics.length < 3) continue;
    if (topics[0]?.symbol !== 'transfer') continue;
    const from = topics[1]?.address;
    const to = topics[2]?.address;
    if (!from || !to) continue;

    const { amount, toMuxedId, cap67Wrapped } = normalizeCap67Amount(ev.body.v0.data);

    transfers.push({
      contractId,
      from,
      to,
      amount, // BigInt stroops (7 decimales)
      toMuxedId,
      cap67Wrapped,
      payerType: StrKey.isValidContract(from)
        ? 'smart_account'
        : StrKey.isValidEd25519PublicKey(from)
          ? 'classic'
          : 'unknown',
    });
  }

  return { transfers, observedContracts: [...observedContracts] };
}

export function formatStroopsToUsdc(stroops) {
  const n = BigInt(stroops);
  const whole = n / 10_000_000n;
  const frac = (n % 10_000_000n).toString().padStart(7, '0').replace(/0+$/, '') || '0';
  return `${whole}.${frac}`;
}

/**
 * Verifica las 7 invariantes criptográficas on-chain directamente contra Soroban RPC.
 */
export async function verifyOnChainSettlement(
  rpcServer,
  {
    txHash,
    expectedPayTo,
    expectedAmount,
    expectedAssetContract = USDC_SAC_TESTNET,
    expectedPayer = null,
    maxLedgerAge = DEFAULT_MAX_LEDGER_AGE,
    pollDelaysMs = POLL_DELAYS_MS,
  }
) {
  const normalizedHash = String(txHash ?? '').trim().toLowerCase();
  const invariants = {
    txHashFormat: false,
    onChainSuccess: false,
    ledgerFreshness: false,
    canonicalUsdcSac: false,
    recipientMatch: false,
    amountSufficient: false,
    payerSeparated: false,
  };

  if (!/^[0-9a-f]{64}$/.test(normalizedHash)) {
    return {
      ok: false,
      transient: false,
      code: 'INVALID_TX_HASH',
      detail: `Hash inválido (debe ser hex de 64 caracteres): ${txHash}`,
      invariants,
    };
  }
  invariants.txHashFormat = true;

  let tx;
  for (const delay of pollDelaysMs) {
    if (delay > 0) await new Promise((r) => setTimeout(r, delay));
    try {
      tx = await rpcServer.getTransaction(normalizedHash);
    } catch (err) {
      return {
        ok: false,
        transient: true,
        code: 'RPC_UNAVAILABLE',
        detail: err?.message ?? 'Error al consultar Soroban RPC',
        invariants,
      };
    }
    if (tx?.status !== rpc.Api.GetTransactionStatus.NOT_FOUND) break;
  }

  if (!tx || tx.status === rpc.Api.GetTransactionStatus.NOT_FOUND) {
    return {
      ok: false,
      transient: false,
      code: 'TX_NOT_FOUND_ON_CHAIN',
      detail: 'La transacción no existe en Soroban Testnet RPC (posible facilitador comprometido).',
      invariants,
    };
  }

  if (tx.status !== rpc.Api.GetTransactionStatus.SUCCESS) {
    return {
      ok: false,
      transient: false,
      code: 'TX_FAILED_ON_CHAIN',
      detail: `Estado on-chain no confirmado: ${tx.status}`,
      invariants,
    };
  }
  invariants.onChainSuccess = true;

  const txLedger = Number(tx.ledger);
  const latestLedger = tx.latestLedger != null ? Number(tx.latestLedger) : txLedger;
  const ledgerAge = latestLedger - txLedger;
  if (maxLedgerAge !== null && Number.isFinite(ledgerAge) && ledgerAge > maxLedgerAge) {
    return {
      ok: false,
      transient: false,
      code: 'LEDGER_EXPIRED',
      detail: `Transacción expirada: antigüedad ${ledgerAge} ledgers > límite ${maxLedgerAge}.`,
      ledger: txLedger,
      latestLedger,
      invariants,
    };
  }
  invariants.ledgerFreshness = true;

  const envInfo = extractEnvelopeInfo(tx.envelopeXdr);
  const { transfers, observedContracts } = extractSacTransfers(tx, expectedAssetContract);
  if (transfers.length === 0) {
    const fakeHint =
      observedContracts.length > 0
        ? ` Contratos observados: ${observedContracts.join(', ')} (esperado SAC USDC ${expectedAssetContract}).`
        : '';
    return {
      ok: false,
      transient: false,
      code: 'WRONG_ASSET_OR_NO_TRANSFER',
      detail: `No existe evento transfer del SAC USDC canónico.${fakeHint}`,
      observedContracts,
      invariants,
    };
  }
  invariants.canonicalUsdcSac = true;

  const incoming = transfers.filter((t) => t.to === expectedPayTo);
  const outgoing = transfers.filter((t) => t.from === expectedPayTo);
  if (incoming.length === 0) {
    return {
      ok: false,
      transient: false,
      code: 'WRONG_RECIPIENT',
      detail: `Ninguna transferencia fue enviada al comercio ${expectedPayTo}.`,
      invariants,
    };
  }
  invariants.recipientMatch = true;

  const netToMerchant =
    incoming.reduce((acc, t) => acc + t.amount, 0n) - outgoing.reduce((acc, t) => acc + t.amount, 0n);
  const required = BigInt(expectedAmount);
  if (netToMerchant < required) {
    return {
      ok: false,
      transient: false,
      code: 'UNDERPAID',
      detail: `Monto neto ${formatStroopsToUsdc(netToMerchant)} USDC (${netToMerchant} stroops) < requerido ${formatStroopsToUsdc(required)} USDC (${required} stroops).`,
      invariants,
    };
  }
  invariants.amountSufficient = true;

  const primary = incoming[0];
  if (expectedPayer && primary.from !== expectedPayer) {
    return {
      ok: false,
      transient: false,
      code: 'PAYER_MISMATCH',
      detail: `Pagador on-chain ${primary.from} !== pagador declarado ${expectedPayer}.`,
      invariants,
    };
  }
  invariants.payerSeparated = true;

  return {
    ok: true,
    invariants,
    settlement: {
      txHash: normalizedHash,
      ledger: txLedger,
      latestLedger,
      ledgerAge,
      assetContract: expectedAssetContract,
      amount: netToMerchant.toString(),
      amountUsdc: formatStroopsToUsdc(netToMerchant),
      payer: primary.from,
      payerType: primary.payerType,
      payTo: expectedPayTo,
      feeSponsor: envInfo.feeSponsor,
      txSource: envInfo.txSource,
      isFeeBump: envInfo.isFeeBump,
      sponsorDiffersFromPayer: envInfo.feeSponsor !== primary.from,
      toMuxedId: primary.toMuxedId,
      cap67Wrapped: primary.cap67Wrapped,
      smartAccountAuth: envInfo.authEntries.filter((a) => a.isSmartAccount),
      allAuthEntries: envInfo.authEntries,
      stellarExpertUrl: `${STELLAR_EXPERT_TX_BASE}${normalizedHash}`,
    },
  };
}

/**
 * Diagnóstico Forense CAP-46 / OpenZeppelin Smart Accounts (read-only real en Soroban RPC).
 * No inventa políticas: lee existencia, executable/wasmHash y balance USDC real del contrato C... en Testnet.
 */
export async function diagnoseSmartAccount(
  rpcServer,
  contractId,
  { simulationSourcePublicKey = null, expectedAssetContract = USDC_SAC_TESTNET } = {}
) {
  if (!StrKey.isValidContract(contractId)) {
    return {
      ok: false,
      code: 'NOT_A_CONTRACT_ADDRESS',
      detail: `La dirección ${contractId} no es un contrato Soroban válido (debe iniciar con C...).`,
    };
  }

  let existsOnTestnet = false;
  let wasmHash = null;
  let instanceType = 'unknown';

  try {
    const instanceKey = new Contract(contractId).getFootprint();
    const entries = await rpcServer.getLedgerEntries(instanceKey);
    const found = entries?.entries?.[0];
    if (found) {
      existsOnTestnet = true;
      const valJson = toXdrJson(found.val, xdr.LedgerEntryData);
      const exec = valJson?.contract_data?.val?.contract_instance?.executable;
      if (typeof exec === 'string') {
        instanceType = exec; // ej. "stellar_asset"
      } else if (exec && typeof exec === 'object') {
        instanceType = Object.keys(exec)[0] || 'wasm';
        wasmHash = exec.wasm ?? null;
      }
    }
  } catch (err) {
    return {
      ok: false,
      code: 'RPC_CONTRACT_LOOKUP_FAILED',
      detail: err?.message ?? 'Error al leer ContractInstance en Soroban RPC',
    };
  }

  let usdcBalanceStroops = null;
  let usdcBalanceUsdc = null;
  if (simulationSourcePublicKey && StrKey.isValidEd25519PublicKey(simulationSourcePublicKey)) {
    try {
      const sac = new Contract(expectedAssetContract);
      const sourceAcc = await rpcServer.getAccount(simulationSourcePublicKey);
      const balTx = new TransactionBuilder(sourceAcc, {
        fee: '100',
        networkPassphrase: Networks.TESTNET,
      })
        .addOperation(sac.call('balance', new Address(contractId).toScVal()))
        .setTimeout(30)
        .build();
      const sim = await rpcServer.simulateTransaction(balTx);
      if (sim?.result?.retval) {
        const val = scValToNative(sim.result.retval);
        usdcBalanceStroops = String(val);
        usdcBalanceUsdc = formatStroopsToUsdc(val);
      }
    } catch {
      // Simulación de balance es best-effort si la cuenta fuente no existe o no soporta balance
    }
  }

  return {
    ok: true,
    mode: 'live_rpc_preflight_diagnostic',
    contractId,
    existsOnTestnet,
    instanceType,
    wasmHash,
    usdcBalanceStroops,
    usdcBalanceUsdc,
    stellarExpertUrl: `${STELLAR_EXPERT_CONTRACT_BASE}${contractId}`,
    cap46AndOzAnalysis: {
      cannotBeEnvelopeSource: true,
      requiresSorobanCredentialsAddress: true,
      cep402ExtractorCompatible: true,
      ozSpendingLimitErrorCode: '#3221 (SpendingLimitExceeded)',
      authFlowSummary:
        'Relayer/Facilitator G... firma como sourceAccount/feeSponsor mientras C... autoriza transfer via SorobanAuthorizationEntry (__check_auth + ContextRules + SpendingLimitPolicy).',
    },
  };
}
