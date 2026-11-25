# Parte de coronahernandezs931-cloud · CEP-402 v2

Middleware Zero-Trust de verificación de pagos x402 sobre Stellar Testnet + Comprobante Electrónico de Pago criptográfico (**CEP-402**, inspirado en el CEP de Banxico) + Forense CAP-46 de Smart Accounts (`C...` / OpenZeppelin) + Auditor de Camino Rojo con **Raven MCP**.

## Arquitectura implementada

- `stellar-extractor.js`: 7 invariantes directamente sobre Soroban RPC (`@stellar/stellar-sdk@17.4.0`), soporte dual `TransactionMeta` V4/V3 y CAP-67 (`i128` + `Map { amount, to_muxed_id }`), validación de SAC USDC canónico contra tokens falsos, frescura de ledger (`<= 60` ledgers), separación `Fee Sponsor (G...)` vs `Real Payer (G... o C...)` desde `envelopeXdr`, extracción de `SorobanAuthorizationEntry` y diagnóstico live read-only de contratos `C...`.
- `replay-store.js`: `AtomicReplayStore` con lock síncrono previo al primer `await` (inmune a ráfagas 5× paralelas → `409 Conflict`) y persistencia NDJSON con `fsyncSync`.
- `receipt.js`: Recibo canónico `CEP-402` firmado con Ed25519 (clave privada del comercio) atando `txHash + ledger + payer + payerType + feeSponsor + amount + reqHash + SHA256(rawResponseBody)` con clave pública en formato SPKI Base64 para verificación Zero-Trust en el navegador (`crypto.subtle`) y directo contra Soroban RPC.
- `express-gate.js`: Outer-wrapper `createCep402Gate()` montado **antes** de `paymentMiddleware` usando `AsyncLocalStorage` (fail-closed antes de liberar bytes `2xx`).
- `facilitator.js`: Facilitador Dual local (`@x402/stellar/exact/facilitator`) con modo `HONEST` real en Testnet y simulador explícito de Facilitador Comprometido / MITM (`FAKE_SETTLE`, `REPLAY_OLD_TX`, `UNDERPAY_TX`, `FAKE_SAC_TX`).
- `auditor-raven.js` + `mcp.json`: Cliente Streamable HTTP a `https://raven.stellar.org/mcp` exclusivo para el Camino Rojo, con degradación explícita a Snapshot Verificado (`RAVEN MCP: LIVE` vs `RAVEN VERIFIED SNAPSHOT`) para pruebas offline deterministas.
- `server.js` + `public/index.html`: Servidor Express 5 single-origin con UI Split-Screen (`x402 Vanilla` vs `CEP-402 Guard`), tarjeta descargable CEP-402 y metralleta de 3 ataques.
- `live-demo.js`: Preflight y ejecución real end-to-end en Stellar Testnet.
