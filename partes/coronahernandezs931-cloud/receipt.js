import crypto from 'node:crypto';
import { Keypair, StrKey } from '@stellar/stellar-sdk';
import { verifyOnChainSettlement, USDC_SAC_TESTNET } from './stellar-extractor.js';

// Prefijo DER SPKI fijo RFC 8410 para llaves públicas Ed25519 (12 bytes + 32 bytes raw key)
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/**
 * Serialización JSON canónica determinista (claves ordenadas recursivamente).
 * Idéntica en Node.js y navegador para garantizar verificación Ed25519 Zero-Trust.
 */
export function canonicalize(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('Non-finite number in canonical JSON');
    return JSON.stringify(value);
  }
  if (typeof value === 'bigint') {
    throw new Error('BigInt not allowed directly in canonical JSON; serialize as string');
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => (v === undefined ? 'null' : canonicalize(v))).join(',')}]`;
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value)
      .filter((k) => value[k] !== undefined)
      .sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(',')}}`;
  }
  throw new Error(`Unsupported type in canonical JSON: ${typeof value}`);
}

export function sha256Hex(buf) {
  const input = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  return crypto.createHash('sha256').update(input).digest('hex');
}

/**
 * Convierte una llave pública Stellar (G...) a formato SPKI Base64 compatible
 * directamente con Web Crypto `crypto.subtle.importKey('spki', ..., 'Ed25519', ...)`.
 */
export function stellarPublicKeyToSpkiBase64(stellarPublicKey) {
  const rawPub = StrKey.decodeEd25519PublicKey(stellarPublicKey);
  return Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(rawPub)]).toString('base64');
}

export function buildAndSignReceipt({
  settlement,
  reqMeta,
  resMeta,
  merchantSecret,
  network = 'stellar:testnet',
}) {
  const kp = Keypair.fromSecret(merchantSecret);
  const merchantPubKey = kp.publicKey();
  const payload = {
    amount: String(settlement.amount),
    amountUsdc: String(settlement.amountUsdc),
    assetContract: settlement.assetContract,
    cep: 'CEP-402',
    feeSponsor: settlement.feeSponsor,
    folio: `CEP402-${settlement.ledger}-${settlement.txHash.slice(0, 8).toUpperCase()}`,
    isFeeBump: Boolean(settlement.isFeeBump),
    issuedAt: new Date().toISOString(),
    ledger: Number(settlement.ledger),
    merchantPubKey,
    merchantSpkiBase64: stellarPublicKeyToSpkiBase64(merchantPubKey),
    network,
    payTo: settlement.payTo,
    payer: settlement.payer,
    payerType: settlement.payerType,
    request: {
      method: reqMeta.method,
      path: reqMeta.path,
      querySha256: reqMeta.querySha256,
    },
    response: {
      bodySha256: resMeta.bodySha256,
      contentType: resMeta.contentType,
      status: Number(resMeta.status),
    },
    stellarExpertUrl: settlement.stellarExpertUrl,
    txHash: settlement.txHash,
    version: '2.0',
  };

  const canonicalJson = canonicalize(payload);
  const signature = Buffer.from(kp.sign(Buffer.from(canonicalJson, 'utf8'))).toString('base64');
  return { alg: 'Ed25519', payload, signature };
}

export function verifyReceiptOffline(envelope, rawResponseBytes = null, pinnedMerchantPubKey = null) {
  if (!envelope?.payload || typeof envelope.signature !== 'string') {
    return { ok: false, code: 'MALFORMED_RECEIPT', detail: 'Estructura de recibo CEP-402 inválida.' };
  }

  const { payload, signature } = envelope;
  if (pinnedMerchantPubKey && payload.merchantPubKey !== pinnedMerchantPubKey) {
    return {
      ok: false,
      code: 'UNTRUSTED_MERCHANT_KEY',
      detail: `Llave del comercio ${payload.merchantPubKey} no coincide con la anclada ${pinnedMerchantPubKey}.`,
    };
  }
  if (!StrKey.isValidEd25519PublicKey(payload.merchantPubKey)) {
    return { ok: false, code: 'INVALID_MERCHANT_PUBKEY', detail: 'Llave pública Stellar inválida.' };
  }

  if (rawResponseBytes != null) {
    const actualHash = sha256Hex(rawResponseBytes);
    if (actualHash !== payload.response?.bodySha256) {
      return {
        ok: false,
        code: 'BODY_HASH_MISMATCH',
        detail: 'El contenido entregado fue alterado después de la emisión del recibo (tampering detectado).',
        expected: payload.response?.bodySha256,
        actual: actualHash,
      };
    }
  }

  const sigBuf = Buffer.from(signature, 'base64');
  if (sigBuf.length !== 64) {
    return { ok: false, code: 'INVALID_SIGNATURE_LENGTH', detail: 'Firma Ed25519 debe medir 64 bytes.' };
  }

  const canonicalJson = canonicalize(payload);
  const valid = Keypair.fromPublicKey(payload.merchantPubKey).verify(
    Buffer.from(canonicalJson, 'utf8'),
    sigBuf
  );
  if (!valid) {
    return {
      ok: false,
      code: 'INVALID_ED25519_SIGNATURE',
      detail: 'La firma Ed25519 del recibo CEP-402 no corresponde al payload canónico.',
    };
  }

  return { ok: true, canonicalJson, folio: payload.folio };
}

export async function verifyReceiptZeroTrust(rpcServer, envelope, rawResponseBytes = null, opts = {}) {
  const off = verifyReceiptOffline(envelope, rawResponseBytes, opts.pinnedMerchantPubKey ?? null);
  if (!off.ok) return { ok: false, stage: 'offline', ...off };

  const p = envelope.payload;
  const on = await verifyOnChainSettlement(rpcServer, {
    txHash: p.txHash,
    expectedPayTo: p.payTo,
    expectedAmount: p.amount,
    expectedAssetContract: opts.expectedAssetContract ?? USDC_SAC_TESTNET,
    expectedPayer: p.payer,
    maxLedgerAge: opts.maxLedgerAge ?? null, // Auditoría histórica de recibos antiguos permitida
  });

  if (!on.ok) return { ok: false, stage: 'onchain', ...on };

  const s = on.settlement;
  if (s.ledger !== p.ledger || s.feeSponsor !== p.feeSponsor || BigInt(s.amount) !== BigInt(p.amount)) {
    return {
      ok: false,
      stage: 'onchain_binding',
      code: 'RECEIPT_LEDGER_MISMATCH',
      detail: 'Los metadatos del recibo no coinciden con los hechos inmutables en Soroban RPC.',
      onChain: s,
      receipt: p,
    };
  }

  return { ok: true, stage: 'verified_zero_trust', onChain: s, receipt: p };
}
