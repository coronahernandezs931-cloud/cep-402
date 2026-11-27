# Parte de coronahernandezs931-cloud · CEP-402 v3

Middleware Zero-Trust de verificación de pagos x402 sobre Stellar Testnet + Comprobante Electrónico de Pago criptográfico (**CEP-402**, inspirado en el CEP de Banxico con **Cadena Original `||...||`**, **Sello Ed25519**, exportación **JSON / XML / Póliza CSV** y `/.well-known/cep402.json`) + Forense CAP-46 de Smart Accounts (`C...` / OpenZeppelin) + Auditor de Camino Rojo con **Raven MCP**.

## Arquitectura implementada

- `stellar-extractor.js`: 7 invariantes sobre Soroban RPC (`@stellar/stellar-sdk@17.4.0`), **Pool Multi-RPC con failover automático** (`createFailoverRpcClient`), soporte `TransactionMeta` V4/V3 y CAP-67 (`i128` + `Map { amount, to_muxed_id }`), validación de SAC USDC canónico, frescura de ledger (`<= 60` ledgers), separación `Fee Sponsor (G...)` vs `Real Payer (G... o C...)` desde `envelopeXdr`, extracción de `SorobanAuthorizationEntry` y diagnóstico live + simulación de `transfer(from=C...)` en contratos `C...`.
- `replay-store.js`: `AtomicReplayStore` con lock síncrono previo al primer `await` (inmune a ráfagas 5× paralelas → `409 Conflict`) y persistencia NDJSON con `fsyncSync`.
- `receipt.js`: Recibo canónico `CEP-402` con **Cadena Original estilo Banxico (`||...||`)**, firma **Ed25519**, llave pública **SPKI Base64** para verificación Zero-Trust 4/4 en navegador (`crypto.subtle` + inspección binaria XDR contra RPC público), exportación **XML (`ComprobanteCEP402`)** y **Póliza Contable CSV**.
- `express-gate.js`: Outer-wrapper `createCep402Gate()` montado **antes** de `paymentMiddleware` usando `AsyncLocalStorage` (fail-closed antes de liberar bytes `2xx`).
- `facilitator.js`: Facilitador Dual local (`@x402/stellar/exact/facilitator`) con modo `HONEST` real en Testnet y simulador explícito de Facilitador Comprometido / MITM (`FAKE_SETTLE`, `REPLAY_OLD_TX`, `UNDERPAY_TX`, `FAKE_SAC_TX`).
- `auditor-raven.js` + `.mcp.json`: Cliente Streamable HTTP MCP `2025-03-26` (`initialize` → `Mcp-Session-Id` → `tools/call` con soporte JSON y SSE) hacia `https://raven.stellar.org/mcp` exclusivo para el Camino Rojo, con degradación honesta a Snapshot Verificado para CI/Codespaces.
- `server.js` + `public/index.html`: Servidor Express 5 single-origin con UI Split-Screen minimalista (modo Claro/Oscuro), **Validador Público** de cualquier `txHash`/`.cep402.json`/`C...`, **Cronómetro integrado 3:00** para Demo Day, **Modal de Arquitectura & Roadmap SCF**, exportación XML/CSV/PDF y documento `/.well-known/cep402.json`.
- `verificar-cli.js` + `live-demo.js`: Verificador CLI independiente y demo end-to-end en Stellar Testnet.
- `cep402.test.js`: 21 pruebas automatizadas (`node:test`) 100% deterministas y offline (`# fail 0` sin requerir `.env`).

## Cómo correr mi parte

```bash
# 1. Correr las 21 pruebas deterministas (funciona incluso sin .env -> # fail 0)
npm test

# 2. Levantar la UI Split-Screen + Validador Público en http://127.0.0.1:3000
npm start

# 3. Auditar cualquier txHash o archivo .cep402.json desde la terminal
npm run verificar -- 25adcb23697676e05e7efaaf5e7a562a25f06f3c0aaa782d0a9ff0795ab4be8c

# 4. Verificar saldos, trustlines USDC y Soroban RPC en Testnet (requiere .env)
npm run preflight

# 5. Ejecutar demo CLI completo en Stellar Testnet (Duelo + Pago Real + Metralleta de 3 Ataques)
npm run demo
```

## Hash de prueba

- Pago real de `0.01 USDC` verificado Zero-Trust (Folio `CEP402-5909535-25ADCB23`, Ledger `5909535`, `Fee Sponsor` distinto al `Real Payer`):
  - `25adcb23697676e05e7efaaf5e7a562a25f06f3c0aaa782d0a9ff0795ab4be8c`
  - Verlo: https://stellar.expert/explorer/testnet/tx/25adcb23697676e05e7efaaf5e7a562a25f06f3c0aaa782d0a9ff0795ab4be8c
- Pago adicional confirmado en Testnet (Ledger `5909443`):
  - `e4d0cdf63792e0c66ee86450790e3817a2ea9ea06fe30c8a85378caa30c99c3b`
  - Verlo: https://stellar.expert/explorer/testnet/tx/e4d0cdf63792e0c66ee86450790e3817a2ea9ea06fe30c8a85378caa30c99c3b
- Contrato `C...` (SAC USDC canónico) verificado en vivo vía `Contract.getFootprint()` + Soroban RPC:
  - `CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA`
  - Verlo: https://stellar.expert/explorer/testnet/contract/CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA
