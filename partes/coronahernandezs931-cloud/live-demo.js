import { Keypair, rpc } from '@stellar/stellar-sdk';
import { x402Client, wrapFetchWithPayment } from '@x402/fetch';
import { createEd25519Signer } from '@x402/stellar';
import { ExactStellarScheme } from '@x402/stellar/exact/client';
import { startCep402Server } from './server.js';
import {
  USDC_SAC_TESTNET,
  diagnoseSmartAccount,
  formatStroopsToUsdc,
} from './stellar-extractor.js';
import { verifyReceiptZeroTrust } from './receipt.js';
import { RavenKnowledgeProvider } from './auditor-raven.js';

const NETWORK = 'stellar:testnet';
const RPC_URL = process.env.SOROBAN_RPC_URL || 'https://soroban-testnet.stellar.org';
const HORIZON_URL = 'https://horizon-testnet.stellar.org';

async function checkHorizonAccount(label, pubKey) {
  const res = await fetch(`${HORIZON_URL}/accounts/${pubKey}`);
  if (!res.ok) return { label, pubKey, ok: false, detail: `HTTP ${res.status}` };
  const data = await res.json();
  const xlm = data.balances.find((b) => b.asset_type === 'native')?.balance ?? '0';
  const usdc = data.balances.find((b) => b.asset_code === 'USDC')?.balance ?? null;
  return { label, pubKey, ok: true, xlm, usdc, hasUsdcTrustline: usdc !== null };
}

async function runPreflight() {
  console.log('\n🔎 CEP-402 PREFLIGHT CHECK (Stellar Testnet)\n');
  const merchantPub = process.env.MI_PUBLICA;
  const payerSec = process.env.PAYER_SECRETA || process.env.AMIGO_SECRETA;
  const facSec = process.env.FACILITATOR_SECRETA || process.env.AGENTE_SECRETA;

  if (!merchantPub || !process.env.MI_SECRETA || !payerSec || !facSec) {
    console.error('❌ Faltan llaves en .env (MI_PUBLICA, MI_SECRETA, PAYER_SECRETA, FACILITATOR_SECRETA).');
    process.exit(1);
  }

  const payerPub = Keypair.fromSecret(payerSec).publicKey();
  const facPub = Keypair.fromSecret(facSec).publicKey();

  const checks = await Promise.all([
    checkHorizonAccount('MERCHANT (PAY_TO)', merchantPub),
    checkHorizonAccount('PAYER (Cliente x402)', payerPub),
    checkHorizonAccount('FACILITATOR (Fee Sponsor)', facPub),
  ]);

  for (const c of checks) {
    console.log(
      `  ${c.ok ? '✅' : '❌'} ${c.label}: ${c.pubKey} | XLM=${c.xlm} | USDC=${c.usdc ?? 'SIN TRUSTLINE'}`
    );
  }

  const rpcServer = new rpc.Server(RPC_URL);
  const t0 = Date.now();
  const latest = await rpcServer.getLatestLedger();
  console.log(`  ✅ Soroban RPC (${RPC_URL}): ledger=${latest.sequence} (${Date.now() - t0}ms)`);
  console.log(`  ✅ SAC USDC Canónico: ${USDC_SAC_TESTNET}`);

  const raven = new RavenKnowledgeProvider();
  const diag = await raven.diagnose('SMART_ACCOUNT_POLICY_3221');
  console.log(`  ✅ Raven Auditor: ${diag.badge}\n`);

  const ready =
    checks[0].ok &&
    checks[0].hasUsdcTrustline &&
    checks[1].ok &&
    Number(checks[1].usdc || 0) >= 0.01 &&
    checks[2].ok &&
    Number(checks[2].xlm || 0) >= 5;

  if (!ready) {
    console.error('❌ Preflight falló: revisa trustlines USDC o saldos XLM/USDC.');
    process.exit(1);
  }
  console.log('🚀 PREFLIGHT 100% VERDE — LISTO PARA DEMO EN VIVO!\n');
}

async function runLiveDemo() {
  await runPreflight();

  const srv = await startCep402Server({ port: 0, inMemoryReplay: true });
  try {
    console.log(`🛡️  Servidor efímero CEP-402 levantado en ${srv.url}\n`);

    // 1. Duelo Split-Screen con Facilitador Comprometido (FAKE_SETTLE)
    console.log('=== ACTO 1: DUELO SPLIT-SCREEN (FACILITADOR COMPROMETIDO / FAKE_SETTLE) ===');
    const duelRes = await fetch(`${srv.url}/api/demo/corrupt-duel`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'FAKE_SETTLE' }),
    });
    const duel = await duelRes.json();
    console.log(`  ❌ x402 Vanilla: HTTP ${duel.vanilla.status} (hacked=${duel.vanilla.hacked}, USDC recibidos=$${duel.vanilla.usdcReceivedOnChain})`);
    console.log(`  ✅ CEP-402 Guard: HTTP ${duel.cep402.status} (blocked=${duel.cep402.blocked}, error=${duel.cep402.body.error})\n`);

    // 2. Pago REAL en Stellar Testnet vía @x402/fetch + verificación Zero-Trust
    console.log('=== ACTO 2: PAGO REAL EN STELLAR TESTNET ($0.01 USDC) ===');
    const payerSec = process.env.PAYER_SECRETA || process.env.AMIGO_SECRETA;
    const signer = createEd25519Signer(payerSec, NETWORK);
    const client = x402Client.fromConfig({
      schemes: [{ network: 'stellar:*', client: new ExactStellarScheme(signer, { url: RPC_URL }) }],
      spendControls: { maxAmountPerPayment: '$0.05' },
    });
    const fetchWithPay = wrapFetchWithPayment(fetch, client);

    const paidRes = await fetchWithPay(`${srv.url}/api/cep402/dato`);
    const rawBytes = Buffer.from(await paidRes.arrayBuffer());
    const receiptB64 = paidRes.headers.get('x-cep402-receipt');
    if (paidRes.status !== 200 || !receiptB64) {
      throw new Error(`Pago live falló (HTTP ${paidRes.status}): ${rawBytes.toString('utf8')}`);
    }
    const receipt = JSON.parse(Buffer.from(receiptB64, 'base64url').toString('utf8'));
    const p = receipt.payload;

    console.log(`  ✅ HTTP ${paidRes.status} | Folio: ${p.folio}`);
    console.log(`  • txHash:       ${p.txHash}`);
    console.log(`  • Ledger:       ${p.ledger}`);
    console.log(`  • Real Payer:   ${p.payer} (${p.payerType})`);
    console.log(`  • Fee Sponsor:  ${p.feeSponsor} (distinto=${p.feeSponsor !== p.payer})`);
    console.log(`  • Monto neto:   ${formatStroopsToUsdc(p.amount)} USDC (${p.amount} stroops)`);
    console.log(`  • StellarExpert: ${p.stellarExpertUrl}`);

    // Re-verificación Zero-Trust independiente contra Soroban RPC
    const zt = await verifyReceiptZeroTrust(srv.rpcServer, receipt, rawBytes, {
      pinnedMerchantPubKey: srv.merchantPublicKey,
    });
    console.log(`  ✅ Verificación Zero-Trust Independiente: ok=${zt.ok} (stage=${zt.stage})\n`);

    // 3. Metralleta de 3 Ataques (Replay 5x paralelo, Tampering 1 byte, Forense Smart Account C... + Raven)
    console.log('=== ACTO 3: METRALLETA DE 3 ATAQUES (<4s) ===');
    const gauntletRes = await fetch(`${srv.url}/api/demo/attack-gauntlet`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ txHash: p.txHash }),
    });
    const g = await gauntletRes.json();
    console.log(
      `  1) Replay 5x paralelo: Vanilla saqueado ${g.attack1_parallelReplay5x.vanillaLootedCount}/5 veces | CEP-402 bloqueó ${g.attack1_parallelReplay5x.cep402BlockedCount}/5 (${g.attack1_parallelReplay5x.sampleCep402Error})`
    );
    console.log(
      `  2) Alterar 1 byte del body: ok=${g.attack2_tampering1Byte.ok} (${g.attack2_tampering1Byte.code})`
    );
    console.log(
      `  3) Smart Account C... CAP-46 Forensics: contract=${g.attack3_corruptFacilitatorAndSmartAccount.smartAccountForensics.contractId} exists=${g.attack3_corruptFacilitatorAndSmartAccount.smartAccountForensics.existsOnTestnet}`
    );
    console.log(
      `     Raven MCP Auditor: [${g.attack3_corruptFacilitatorAndSmartAccount.ravenDiagnostic.badge}] ${g.attack3_corruptFacilitatorAndSmartAccount.ravenDiagnostic.title}\n`
    );

    const sa = await diagnoseSmartAccount(srv.rpcServer, USDC_SAC_TESTNET, {
      simulationSourcePublicKey: srv.merchantPublicKey,
    });
    console.log(`  • Diagnóstico live RPC contrato C...: exists=${sa.existsOnTestnet}, type=${sa.instanceType}`);
  } finally {
    await srv.close();
  }
}

if (process.argv.includes('--preflight')) {
  await runPreflight();
} else {
  await runLiveDemo();
}
