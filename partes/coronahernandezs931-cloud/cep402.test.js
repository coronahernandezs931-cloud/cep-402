import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Keypair, StrKey } from '@stellar/stellar-sdk';

import {
  USDC_SAC_TESTNET,
  createFailoverRpcClient,
  verifyOnChainSettlement,
  diagnoseSmartAccount,
  AtomicReplayStore,
  canonicalize,
  sha256Hex,
  buildCadenaOriginal,
  buildAndSignReceipt,
  verifyReceiptOffline,
  verifyReceiptZeroTrust,
  receiptToBanxicoXml,
  receiptsToAccountingCsv,
  RavenKnowledgeProvider,
  startCep402Server,
} from './index.js';

// Llaves deterministas en memoria — cero dependencia de .env para garantizar `# fail 0` en cualquier Codespace
const MERCHANT_KP = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 11));
const PAYER_KP = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 22));
const SPONSOR_KP = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 33));
const OTHER_KP = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 44));
const SMART_ACCOUNT_C = StrKey.encodeContract(Buffer.alloc(32, 99));
const FAKE_USDC_SAC = StrKey.encodeContract(Buffer.alloc(32, 77));

const VALID_TX_HASH = 'a1'.repeat(32);
const CAP67_TX_HASH = 'b2'.repeat(32);
const V3_TX_HASH = 'c3'.repeat(32);
const SMART_TX_HASH = 'd4'.repeat(32);
const FAKE_SAC_HASH = 'e5'.repeat(32);
const UNDERPAY_HASH = 'f6'.repeat(32);
const WRONG_TO_HASH = '12'.repeat(32);
const EXPIRED_HASH = '34'.repeat(32);

function makeEnvelopeJson({
  feeSponsor = SPONSOR_KP.publicKey(),
  payer = PAYER_KP.publicKey(),
  payTo = MERCHANT_KP.publicKey(),
  amount = '100000',
  contractId = USDC_SAC_TESTNET,
  feeBump = false,
  nonce = '4949694090879309593',
  expirationLedger = 6000100,
} = {}) {
  const innerTx = {
    source_account: feeSponsor,
    fee: 16693,
    seq_num: '1000',
    operations: [
      {
        source_account: null,
        body: {
          invoke_host_function: {
            host_function: {
              invoke_contract: {
                contract_address: contractId,
                function_name: 'transfer',
                args: [{ address: payer }, { address: payTo }, { i128: amount }],
              },
            },
            auth: [
              {
                credentials: {
                  address: {
                    address: payer,
                    nonce,
                    signature_expiration_ledger: expirationLedger,
                    signature: StrKey.isValidContract(payer)
                      ? { map: [{ key: { symbol: 'signer' }, val: { bytes: 'deadbeef' } }] }
                      : { vec: [{ map: [] }] },
                  },
                },
                root_invocation: {
                  function: {
                    contract_fn: {
                      contract_address: contractId,
                      function_name: 'transfer',
                      args: [{ address: payer }, { address: payTo }, { i128: amount }],
                    },
                  },
                  sub_invocations: [],
                },
              },
            ],
          },
        },
      },
    ],
  };

  if (feeBump) {
    return {
      tx_fee_bump: {
        tx: {
          fee_source: feeSponsor,
          inner_tx: { tx: { tx: { ...innerTx, source_account: OTHER_KP.publicKey() } } },
        },
      },
    };
  }
  return { tx: { tx: innerTx } };
}

function makeContractEventJson({
  contractId = USDC_SAC_TESTNET,
  from = PAYER_KP.publicKey(),
  to = MERCHANT_KP.publicKey(),
  amount = '100000',
  cap67Map = false,
  toMuxedId = '40299',
  type = 'contract',
} = {}) {
  const data = cap67Map
    ? {
        map: [
          { key: { symbol: 'amount' }, val: { i128: amount } },
          { key: { symbol: 'to_muxed_id' }, val: { u64: toMuxedId } },
        ],
      }
    : { i128: amount };

  return {
    ext: 'v0',
    contract_id: contractId,
    type,
    body: {
      v0: {
        topics: [{ symbol: 'transfer' }, { address: from }, { address: to }],
        data,
      },
    },
  };
}

function createStubRpcServer(txMap = new Map()) {
  return {
    async getTransaction(hash) {
      return txMap.get(hash) ?? { status: 'NOT_FOUND' };
    },
    async getLedgerEntries() {
      return {
        entries: [
          {
            val: {
              contract_data: {
                val: { contract_instance: { executable: { wasm: 'ab'.repeat(32) } } },
              },
            },
          },
        ],
      };
    },
  };
}

describe('CEP-402 v3 — 7 Invariantes Soroban RPC, Multi-RPC Failover, CAP-67 y Smart Accounts C...', () => {
  const txMap = new Map();

  txMap.set(VALID_TX_HASH, {
    status: 'SUCCESS',
    ledger: 6000000,
    latestLedger: 6000005,
    envelopeXdr: makeEnvelopeJson({ feeBump: true }),
    events: { contractEventsXdr: [[makeContractEventJson()]] },
  });

  txMap.set(CAP67_TX_HASH, {
    status: 'SUCCESS',
    ledger: 6000010,
    latestLedger: 6000012,
    envelopeXdr: makeEnvelopeJson(),
    resultMetaXdr: { v4: { operations: [{ events: [makeContractEventJson({ cap67Map: true })] }] } },
  });

  txMap.set(V3_TX_HASH, {
    status: 'SUCCESS',
    ledger: 6000015,
    latestLedger: 6000018,
    envelopeXdr: makeEnvelopeJson(),
    resultMetaXdr: { v3: { soroban_meta: { events: [makeContractEventJson()] } } },
  });

  txMap.set(SMART_TX_HASH, {
    status: 'SUCCESS',
    ledger: 6000020,
    latestLedger: 6000022,
    envelopeXdr: makeEnvelopeJson({ payer: SMART_ACCOUNT_C }),
    events: { contractEventsXdr: [[makeContractEventJson({ from: SMART_ACCOUNT_C })]] },
  });

  txMap.set(FAKE_SAC_HASH, {
    status: 'SUCCESS',
    ledger: 6000025,
    latestLedger: 6000026,
    envelopeXdr: makeEnvelopeJson({ contractId: FAKE_USDC_SAC }),
    events: { contractEventsXdr: [[makeContractEventJson({ contractId: FAKE_USDC_SAC })]] },
  });

  txMap.set(UNDERPAY_HASH, {
    status: 'SUCCESS',
    ledger: 6000030,
    latestLedger: 6000031,
    envelopeXdr: makeEnvelopeJson({ amount: '1' }),
    events: { contractEventsXdr: [[makeContractEventJson({ amount: '1' })]] },
  });

  txMap.set(WRONG_TO_HASH, {
    status: 'SUCCESS',
    ledger: 6000035,
    latestLedger: 6000036,
    envelopeXdr: makeEnvelopeJson({ payTo: OTHER_KP.publicKey() }),
    events: { contractEventsXdr: [[makeContractEventJson({ to: OTHER_KP.publicKey() })]] },
  });

  txMap.set(EXPIRED_HASH, {
    status: 'SUCCESS',
    ledger: 5999000,
    latestLedger: 6000000,
    envelopeXdr: makeEnvelopeJson(),
    events: { contractEventsXdr: [[makeContractEventJson()]] },
  });

  const rpcStub = createStubRpcServer(txMap);

  it('1. Valida liquidación legítima con FeeBump separando Fee Sponsor vs Real Payer', async () => {
    const r = await verifyOnChainSettlement(rpcStub, {
      txHash: VALID_TX_HASH,
      expectedPayTo: MERCHANT_KP.publicKey(),
      expectedAmount: '100000',
      pollDelaysMs: [0],
    });
    assert.equal(r.ok, true);
    assert.equal(r.settlement.payer, PAYER_KP.publicKey());
    assert.equal(r.settlement.feeSponsor, SPONSOR_KP.publicKey());
    assert.equal(r.settlement.isFeeBump, true);
    assert.equal(r.settlement.sponsorDiffersFromPayer, true);
    assert.equal(r.settlement.amountUsdc, '0.01');
  });

  it('2. Soporta Protocol 23 TransactionMeta V4 + CAP-67 Map { amount, to_muxed_id }', async () => {
    const r = await verifyOnChainSettlement(rpcStub, {
      txHash: CAP67_TX_HASH,
      expectedPayTo: MERCHANT_KP.publicKey(),
      expectedAmount: '100000',
      pollDelaysMs: [0],
    });
    assert.equal(r.ok, true);
    assert.equal(r.settlement.cap67Wrapped, true);
    assert.equal(r.settlement.toMuxedId, '40299');
  });

  it('3. Soporta fallback TransactionMeta V3 legacy', async () => {
    const r = await verifyOnChainSettlement(rpcStub, {
      txHash: V3_TX_HASH,
      expectedPayTo: MERCHANT_KP.publicKey(),
      expectedAmount: '100000',
      pollDelaysMs: [0],
    });
    assert.equal(r.ok, true);
    assert.equal(r.settlement.amount, '100000');
  });

  it('4. Rechaza contrato token falso (Fake-USDC SAC spoofing)', async () => {
    const r = await verifyOnChainSettlement(rpcStub, {
      txHash: FAKE_SAC_HASH,
      expectedPayTo: MERCHANT_KP.publicKey(),
      expectedAmount: '100000',
      pollDelaysMs: [0],
    });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'WRONG_ASSET_OR_NO_TRANSFER');
    assert.deepEqual(r.observedContracts, [FAKE_USDC_SAC]);
  });

  it('5. Rechaza subpago en BigInt stroops (1 stroop < 100000 stroops)', async () => {
    const r = await verifyOnChainSettlement(rpcStub, {
      txHash: UNDERPAY_HASH,
      expectedPayTo: MERCHANT_KP.publicKey(),
      expectedAmount: '100000',
      pollDelaysMs: [0],
    });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'UNDERPAID');
  });

  it('6. Rechaza destinatario incorrecto', async () => {
    const r = await verifyOnChainSettlement(rpcStub, {
      txHash: WRONG_TO_HASH,
      expectedPayTo: MERCHANT_KP.publicKey(),
      expectedAmount: '100000',
      pollDelaysMs: [0],
    });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'WRONG_RECIPIENT');
  });

  it('7. Rechaza transacción histórica expirada (> 60 ledgers)', async () => {
    const r = await verifyOnChainSettlement(rpcStub, {
      txHash: EXPIRED_HASH,
      expectedPayTo: MERCHANT_KP.publicKey(),
      expectedAmount: '100000',
      maxLedgerAge: 60,
      pollDelaysMs: [0],
    });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'LEDGER_EXPIRED');
  });

  it('8. Detecta OpenZeppelin Smart Account (C...), extrae SorobanAuthorizationEntry y diagnostica wasmHash', async () => {
    const r = await verifyOnChainSettlement(rpcStub, {
      txHash: SMART_TX_HASH,
      expectedPayTo: MERCHANT_KP.publicKey(),
      expectedAmount: '100000',
      pollDelaysMs: [0],
    });
    assert.equal(r.ok, true);
    assert.equal(r.settlement.payer, SMART_ACCOUNT_C);
    assert.equal(r.settlement.payerType, 'smart_account');
    assert.equal(r.settlement.feeSponsor, SPONSOR_KP.publicKey());
    assert.equal(r.settlement.smartAccountAuth.length, 1);
    assert.equal(r.settlement.smartAccountAuth[0].invokedFn, 'transfer');

    const diag = await diagnoseSmartAccount(rpcStub, SMART_ACCOUNT_C);
    assert.equal(diag.ok, true);
    assert.equal(diag.existsOnTestnet, true);
    assert.equal(diag.wasmHash, 'ab'.repeat(32));
  });

  it('9. Pool Multi-RPC rota automáticamente a RPC secundario cuando el primario falla', async () => {
    // Levantamos un mini JSON-RPC local en puerto efímero como RPC #2 de respaldo
    const http = await import('node:http');
    const mockRpc2 = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { status: 'NOT_FOUND', latestLedger: 6000123 } }));
    });
    await new Promise((r) => mockRpc2.listen(0, '127.0.0.1', r));
    const port2 = mockRpc2.address().port;

    try {
      const pool = createFailoverRpcClient([
        'http://127.0.0.1:1', // Primario caído (ECONNREFUSED inmediato)
        `http://127.0.0.1:${port2}`,
      ]);
      const tx = await pool.getTransaction(VALID_TX_HASH);
      assert.equal(tx.status, 'NOT_FOUND');
      assert.equal(pool.getStats().failoverCount, 1);
      assert.equal(pool.getStats().lastEndpointUsed, `http://127.0.0.1:${port2}`);
    } finally {
      mockRpc2.closeAllConnections?.();
      await new Promise((r) => mockRpc2.close(r));
    }
  });
});

describe('AtomicReplayStore — Anti-Replay 5x Paralelo + Persistencia NDJSON', () => {
  it('10. Ante ráfaga 5x paralela, exactamente 1 adquiere el lock y 4 reciben REPLAY_IN_FLIGHT', async () => {
    const store = new AtomicReplayStore({ inMemory: true });
    const results = await Promise.all(
      Array.from({ length: 5 }, () => Promise.resolve(store.tryAcquireSync(VALID_TX_HASH)))
    );
    const acquired = results.filter((r) => r.acquired);
    const blocked = results.filter((r) => !r.acquired && r.reason === 'REPLAY_IN_FLIGHT');
    assert.equal(acquired.length, 1);
    assert.equal(blocked.length, 4);
    store.close();
  });

  it('11. Sobrevive reinicio de proceso vía NDJSON fsync y releasePending nunca borra COMMITTED', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cep402-test-'));
    const file = path.join(tmpDir, 'replay.ndjson');
    try {
      const store1 = new AtomicReplayStore({ filePath: file });
      assert.equal(store1.tryAcquireSync(VALID_TX_HASH).acquired, true);
      store1.commitSync(VALID_TX_HASH, { ledger: 6000000 });
      store1.releasePending(VALID_TX_HASH);
      assert.equal(store1.has(VALID_TX_HASH), true);
      store1.close();

      const store2 = new AtomicReplayStore({ filePath: file });
      const second = store2.tryAcquireSync(VALID_TX_HASH);
      assert.equal(second.acquired, false);
      assert.equal(second.reason, 'REPLAY_COMMITTED');
      store2.close();
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});

describe('Recibo Canónico CEP-402 — Cadena Original Banxico, Ed25519, XML, CSV y Web Crypto', () => {
  const sampleSettlement = {
    txHash: VALID_TX_HASH,
    ledger: 6000000,
    assetContract: USDC_SAC_TESTNET,
    amount: '100000',
    amountUsdc: '0.01',
    payer: PAYER_KP.publicKey(),
    payerType: 'classic',
    payTo: MERCHANT_KP.publicKey(),
    feeSponsor: SPONSOR_KP.publicKey(),
    isFeeBump: false,
    stellarExpertUrl: `https://stellar.expert/explorer/testnet/tx/${VALID_TX_HASH}`,
  };

  it('12. Firma recibo Ed25519, verifica Zero-Trust y detecta alteración de 1 byte (TAMPERED)', async () => {
    const rawBody = Buffer.from(JSON.stringify({ dato: 'liquidez-ok', precio: 19.85 }), 'utf8');
    const txMap = new Map([
      [
        VALID_TX_HASH,
        {
          status: 'SUCCESS',
          ledger: 6000000,
          latestLedger: 6000005,
          envelopeXdr: makeEnvelopeJson(),
          events: { contractEventsXdr: [[makeContractEventJson()]] },
        },
      ],
    ]);
    const rpcStub = createStubRpcServer(txMap);

    const receipt = buildAndSignReceipt({
      settlement: sampleSettlement,
      reqMeta: { method: 'GET', path: '/api/cep402/dato', querySha256: sha256Hex('') },
      resMeta: { status: 200, contentType: 'application/json', bodySha256: sha256Hex(rawBody) },
      merchantSecret: MERCHANT_KP.secret(),
    });

    const zt = await verifyReceiptZeroTrust(rpcStub, receipt, rawBody, {
      pinnedMerchantPubKey: MERCHANT_KP.publicKey(),
    });
    assert.equal(zt.ok, true);
    assert.equal(zt.stage, 'verified_zero_trust');

    const tampered = Buffer.from(rawBody.toString('utf8').replace('19.85', '19.86'), 'utf8');
    const bad = verifyReceiptOffline(receipt, tampered, MERCHANT_KP.publicKey());
    assert.equal(bad.ok, false);
    assert.equal(bad.code, 'BODY_HASH_MISMATCH');
  });

  it('13. Genera Cadena Original ||...|| estilo Banxico y detecta manipulación CADENA_ORIGINAL_MISMATCH', () => {
    const rawBody = Buffer.from('{"ok":true}', 'utf8');
    const receipt = buildAndSignReceipt({
      settlement: sampleSettlement,
      reqMeta: { method: 'GET', path: '/api/cep402/dato', querySha256: sha256Hex('') },
      resMeta: { status: 200, contentType: 'application/json', bodySha256: sha256Hex(rawBody) },
      merchantSecret: MERCHANT_KP.secret(),
    });
    assert.ok(receipt.cadenaOriginal.startsWith('||2.0|CEP-402|'));
    assert.ok(receipt.cadenaOriginal.endsWith('||'));
    assert.equal(receipt.cadenaOriginal, buildCadenaOriginal(receipt.payload));

    const mutated = { ...receipt, cadenaOriginal: receipt.cadenaOriginal.replace('CEP-402', 'FAKE') };
    const check = verifyReceiptOffline(mutated, rawBody, MERCHANT_KP.publicKey());
    assert.equal(check.ok, false);
    assert.equal(check.code, 'CADENA_ORIGINAL_MISMATCH');
  });

  it('14. Exporta XML ComprobanteCEP402 y Póliza Contable CSV válidos para ERP', () => {
    const rawBody = Buffer.from('{"ok":true}', 'utf8');
    const receipt = buildAndSignReceipt({
      settlement: sampleSettlement,
      reqMeta: { method: 'GET', path: '/api/cep402/dato', querySha256: sha256Hex('') },
      resMeta: { status: 200, contentType: 'application/json', bodySha256: sha256Hex(rawBody) },
      merchantSecret: MERCHANT_KP.secret(),
    });
    const xml = receiptToBanxicoXml(receipt);
    assert.match(xml, /<ComprobanteCEP402 /);
    assert.match(xml, /<CadenaOriginal>\|\|2\.0\|CEP-402\|/);
    assert.match(xml, /SelloDigital="/);

    const csv = receiptsToAccountingCsv([receipt]);
    const lines = csv.trim().split('\n');
    assert.equal(lines.length, 2);
    assert.match(lines[0], /^folio,issuedAt,txHash,/);
    assert.match(lines[1], new RegExp(VALID_TX_HASH));
  });

  it('15. La llave SPKI del recibo verifica nativamente con Web Crypto subtle.verify("Ed25519")', async () => {
    const rawBody = Buffer.from('{"ok":true}', 'utf8');
    const receipt = buildAndSignReceipt({
      settlement: sampleSettlement,
      reqMeta: { method: 'GET', path: '/api/cep402/dato', querySha256: sha256Hex('') },
      resMeta: { status: 200, contentType: 'application/json', bodySha256: sha256Hex(rawBody) },
      merchantSecret: MERCHANT_KP.secret(),
    });

    const spkiBytes = Buffer.from(receipt.payload.merchantSpkiBase64, 'base64');
    const pubKey = await crypto.webcrypto.subtle.importKey('spki', spkiBytes, { name: 'Ed25519' }, false, [
      'verify',
    ]);
    const ok = await crypto.webcrypto.subtle.verify(
      { name: 'Ed25519' },
      pubKey,
      Buffer.from(receipt.signature, 'base64'),
      Buffer.from(canonicalize(receipt.payload), 'utf8')
    );
    assert.equal(ok, true);
  });
});

describe('Integración Express 5.3.0 Split-Screen, Well-Known, Auditor Público y Exportaciones', () => {
  let srv;
  let validSigHeader;

  before(async () => {
    const txMap = new Map([
      [
        VALID_TX_HASH,
        {
          status: 'SUCCESS',
          ledger: 6000000,
          latestLedger: 6000002,
          envelopeXdr: makeEnvelopeJson(),
          events: { contractEventsXdr: [[makeContractEventJson()]] },
        },
      ],
    ]);

    srv = await startCep402Server({
      port: 0,
      inMemoryReplay: true,
      merchantSecret: MERCHANT_KP.secret(),
      merchantPublic: MERCHANT_KP.publicKey(),
      rpcServer: createStubRpcServer(txMap),
      pollDelaysMs: [0],
      ravenProvider: new RavenKnowledgeProvider({ mode: 'snapshot' }),
    });

    const probe = await fetch(`${srv.url}/api/cep402/dato`);
    const parsed = JSON.parse(Buffer.from(probe.headers.get('payment-required'), 'base64').toString('utf8'));
    validSigHeader = Buffer.from(
      JSON.stringify({ x402Version: 2, accepted: parsed.accepts[0], payload: { transaction: 'stub' } }),
      'utf8'
    ).toString('base64');
  });

  after(async () => {
    await srv.close();
  });

  it('16. Publica /.well-known/cep402.json con merchantPublicKey, SPKI y SAC USDC canónico', async () => {
    const res = await fetch(`${srv.url}/.well-known/cep402.json`);
    assert.equal(res.status, 200);
    const wk = await res.json();
    assert.equal(wk.spec, 'CEP-402');
    assert.equal(wk.merchantPublicKey, MERCHANT_KP.publicKey());
    assert.equal(wk.canonicalUsdcSac, USDC_SAC_TESTNET);
    assert.ok(wk.merchantSpkiBase64.length > 40);
  });

  it('17. Ruta protegida sin pago devuelve HTTP 402 con header PAYMENT-REQUIRED', async () => {
    const res = await fetch(`${srv.url}/api/cep402/dato`);
    assert.equal(res.status, 402);
    assert.ok(res.headers.get('payment-required'));
  });

  it('18. Facilitador comprometido (FAKE_SETTLE): Vanilla saqueado 200 OK vs CEP-402 bloqueado 403', async () => {
    srv.facilitator.setMode('FAKE_SETTLE');
    const [vanilla, cep] = await Promise.all([
      fetch(`${srv.url}/api/vanilla/dato`, { headers: { 'PAYMENT-SIGNATURE': validSigHeader } }),
      fetch(`${srv.url}/api/cep402/dato`, { headers: { 'PAYMENT-SIGNATURE': validSigHeader } }),
    ]);
    assert.equal(vanilla.status, 200);
    assert.equal(cep.status, 403);
    const cepErr = await cep.json();
    assert.equal(cepErr.blockedBy, 'CEP-402');
    assert.equal(cepErr.error, 'TX_NOT_FOUND_ON_CHAIN');
  });

  it('19. Pago válido emite 200 + recibo XML/CSV descargable y ráfaga 5x replay bloquea 5/5 con 409', async () => {
    srv.facilitator.setMode('REPLAY_OLD_TX', { lastRealTxHash: VALID_TX_HASH });

    const first = await fetch(`${srv.url}/api/cep402/dato`, {
      headers: { 'PAYMENT-SIGNATURE': validSigHeader },
    });
    assert.equal(first.status, 200);
    const raw = Buffer.from(await first.arrayBuffer());
    const receiptB64 = first.headers.get('x-cep402-receipt');
    assert.ok(receiptB64);
    const receipt = JSON.parse(Buffer.from(receiptB64, 'base64url').toString('utf8'));
    assert.equal(verifyReceiptOffline(receipt, raw, MERCHANT_KP.publicKey()).ok, true);

    // Exportación XML y Póliza CSV disponibles tras liquidar
    const [xmlRes, csvRes] = await Promise.all([
      fetch(`${srv.url}/api/last-receipt.xml`),
      fetch(`${srv.url}/api/export/accounting.csv`),
    ]);
    assert.equal(xmlRes.status, 200);
    assert.match(await xmlRes.text(), /<ComprobanteCEP402 /);
    assert.equal(csvRes.status, 200);
    assert.match(await csvRes.text(), new RegExp(VALID_TX_HASH));

    // 5x replay paralelo del mismo hash -> Vanilla entrega 5/5, CEP-402 bloquea 5/5 con 409
    const [vanillaBurst, cepBurst] = await Promise.all([
      Promise.all(
        Array.from({ length: 5 }, () =>
          fetch(`${srv.url}/api/vanilla/dato`, { headers: { 'PAYMENT-SIGNATURE': validSigHeader } }).then(
            (r) => r.status
          )
        )
      ),
      Promise.all(
        Array.from({ length: 5 }, () =>
          fetch(`${srv.url}/api/cep402/dato`, { headers: { 'PAYMENT-SIGNATURE': validSigHeader } }).then(
            (r) => r.status
          )
        )
      ),
    ]);
    assert.deepEqual(vanillaBurst, [200, 200, 200, 200, 200]);
    assert.deepEqual(cepBurst, [409, 409, 409, 409, 409]);
  });

  it('20. Endpoint /api/audit-tx audita cualquier txHash público y rechaza hashes inexistentes', async () => {
    const okRes = await fetch(`${srv.url}/api/audit-tx`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ txHash: VALID_TX_HASH }),
    });
    const okJson = await okRes.json();
    assert.equal(okJson.ok, true);
    assert.equal(okJson.settlement.amountUsdc, '0.01');
    assert.ok(okJson.receipt?.payload?.folio?.startsWith('CEP402-'));

    const badRes = await fetch(`${srv.url}/api/audit-tx`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ txHash: '99'.repeat(32) }),
    });
    const badJson = await badRes.json();
    assert.equal(badJson.ok, false);
    assert.equal(badJson.code, 'TX_NOT_FOUND_ON_CHAIN');
    assert.ok(badJson.ravenDiagnostic);
  });
});

describe('RavenKnowledgeProvider — MCP Streamable HTTP (Handshake + SSE + Fallback)', () => {
  it('21. Degrada limpiamente a VERIFIED_SNAPSHOT ante 401 y soporta initialize + SSE text/event-stream', async () => {
    const failing = new RavenKnowledgeProvider({
      accessToken: 'fake-expired-token',
      fetchImpl: async () => ({ ok: false, status: 401, text: async () => 'Unauthorized' }),
    });
    const d1 = await failing.diagnose('SMART_ACCOUNT_POLICY_3221');
    assert.equal(d1.source, 'VERIFIED_SNAPSHOT');

    const calls = [];
    const liveSse = new RavenKnowledgeProvider({
      accessToken: 'valid-token',
      fetchImpl: async (_url, init) => {
        const body = JSON.parse(init.body);
        calls.push({ method: body.method, sessionHeader: init.headers['Mcp-Session-Id'] || null });
        if (body.method === 'initialize') {
          return {
            ok: true,
            status: 200,
            headers: new Map([['mcp-session-id', 'sess-raven-402']]),
            text: async () => JSON.stringify({ jsonrpc: '2.0', id: 0, result: { protocolVersion: '2025-03-26' } }),
          };
        }
        return {
          ok: true,
          status: 200,
          headers: new Map(),
          text: async () =>
            'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"content":[{"text":"Stellar Scout + OZ Smart Accounts #3221 verified via SSE"}]}}\n\n',
        };
      },
    });

    const d2 = await liveSse.diagnose('SMART_ACCOUNT_POLICY_3221');
    assert.equal(d2.source, 'LIVE_RAVEN_MCP');
    assert.equal(calls.length, 2);
    assert.equal(calls[0].method, 'initialize');
    assert.equal(calls[1].method, 'tools/call');
    assert.equal(calls[1].sessionHeader, 'sess-raven-402');
    assert.match(d2.liveExcerpt, /verified via SSE/);
  });
});
