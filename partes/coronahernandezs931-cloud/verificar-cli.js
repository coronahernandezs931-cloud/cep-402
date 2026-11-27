import fs from 'node:fs';
import {
  USDC_SAC_TESTNET,
  createFailoverRpcClient,
  verifyOnChainSettlement,
} from './stellar-extractor.js';
import { verifyReceiptZeroTrust } from './receipt.js';

const arg = process.argv[2];
if (!arg) {
  console.log('Uso:');
  console.log('  npm run verificar -- <txHash de 64 caracteres>');
  console.log('  npm run verificar -- <ruta/a/recibo.cep402.json>');
  process.exit(1);
}

const rpcClient = createFailoverRpcClient(process.env.SOROBAN_RPC_URLS || process.env.SOROBAN_RPC_URL);

if (/^[0-9a-fA-F]{64}$/.test(arg.trim())) {
  const expectedPayTo = process.env.DESTINO || process.env.MI_PUBLICA || null;
  const expectedAmount = String(Math.round(Number(process.env.MONTO || '0.01') * 1e7));
  console.log(`\n🔎 Auditando txHash en Soroban RPC: ${arg.trim()}`);
  console.log(
    `   Esperado: >= ${expectedAmount} stroops USDC${expectedPayTo ? ` a ${expectedPayTo}` : ' (auditoría abierta sin destinatario fijo)'}\n`
  );

  const res = await verifyOnChainSettlement(rpcClient, {
    txHash: arg.trim(),
    expectedPayTo,
    expectedAmount,
    expectedAssetContract: USDC_SAC_TESTNET,
    maxLedgerAge: null, // Permite auditar transacciones históricas desde CLI
  });

  if (!res.ok) {
    console.error(`❌ RECHAZADO [${res.code}]: ${res.detail}`);
    process.exit(1);
  }

  const s = res.settlement;
  console.log(`✅ LIQUIDACIÓN VERIFICADA ON-CHAIN`);
  console.log(`   • Ledger:        #${s.ledger}`);
  console.log(`   • Monto Neto:    ${s.amountUsdc} USDC (${s.amount} stroops)`);
  console.log(`   • Real Payer:    ${s.payer} (${s.payerType})`);
  console.log(`   • Fee Sponsor:   ${s.feeSponsor} (distinto=${s.sponsorDiffersFromPayer})`);
  console.log(`   • RPC Usado:     ${s.rpcEndpointUsed} (${s.rpcLatencyMs}ms)`);
  console.log(`   • StellarExpert: ${s.stellarExpertUrl}\n`);
} else {
  if (!fs.existsSync(arg)) {
    console.error(`❌ No existe el archivo: ${arg}`);
    process.exit(1);
  }
  const envelope = JSON.parse(fs.readFileSync(arg, 'utf8'));
  console.log(`\n🧾 Verificando Comprobante CEP-402 Zero-Trust: ${envelope?.payload?.folio || arg}\n`);

  const res = await verifyReceiptZeroTrust(rpcClient, envelope, null, {
    pinnedMerchantPubKey: process.env.MI_PUBLICA || null,
    expectedAssetContract: USDC_SAC_TESTNET,
  });

  if (!res.ok) {
    console.error(`❌ COMPROBANTE INVÁLIDO [${res.stage} / ${res.code}]: ${res.detail}`);
    process.exit(1);
  }

  console.log(`✅ COMPROBANTE CEP-402 AUTÉNTICO (Ed25519 + Cadena Original + Soroban RPC)`);
  console.log(`   • Folio:          ${res.receipt.folio}`);
  console.log(`   • Clave Rastreo:  ${res.receipt.txHash}`);
  console.log(`   • Monto:          ${res.receipt.amountUsdc} USDC (Ledger #${res.receipt.ledger})`);
  console.log(`   • Ordenante:      ${res.receipt.payer} (${res.receipt.payerType})`);
  console.log(`   • Patrocinador:   ${res.receipt.feeSponsor}`);
  console.log(`   • Beneficiario:   ${res.receipt.payTo}`);
  console.log(`   • StellarExpert:  ${res.receipt.stellarExpertUrl}\n`);
}
