# CEP-402

Middleware Zero-Trust y Comprobante Electrónico de Pago criptográfico (estilo CEP de Banxico) para verificar pagos x402 USDC directo en Soroban RPC.

**Track:** Verificación de pagos · Código 402 · BAF México × Programa de Embajadores de Stellar · Stellar testnet (dinero de prueba)

## Qué resuelve

En México nadie entrega mercancía por una captura de pantalla de SPEI: todos exigen el **CEP de Banxico**. Hoy en el protocolo `x402`, las APIs confían ciegamente en el recibo devuelto por un facilitador. **CEP-402** agrega una capa de verificación independiente en 1 línea (`app.use(createCep402Gate(...))`) que audita **7 invariantes directamente contra Soroban RPC** (con **Pool Multi-RPC y failover automático**) antes de liberar el recurso:

1. **Lock Anti-Replay atómico (409 Conflict):** bloquea síncronamente ráfagas paralelas (5× `Promise.all`) y persiste hashes en NDJSON (`fsyncSync`).
2. **Confirmación on-chain (`SUCCESS`):** polling acotado en `rpc.Server.getTransaction(txHash)`.
3. **Frescura de ledger (`<= 60` ledgers):** evita reciclar pagos históricos.
4. **Protocol 23 / CAP-67:** soporta `events.contractEventsXdr`, `TransactionMeta` V4/V3 y `transfer` en formato `i128` o `Map { amount, to_muxed_id }`.
5. **SAC USDC canónico:** rechaza tokens impostores aunque declaren símbolo `USDC`.
6. **Monto neto exacto y destinatario en `BigInt` stroops** (7 decimales en Stellar).
7. **Separación `Fee Sponsor (G...)` vs `Real Payer (G... o C...)`:** extrae `SorobanAuthorizationEntry` para soportar cuentas clásicas y **OpenZeppelin Smart Accounts (`C...`)**.

Además emite un **Comprobante CEP-402** con **Cadena Original delimitada (`||...||`)** y **Sello Digital Ed25519**, publica el documento de descubrimiento **`/.well-known/cep402.json`** (llave SPKI para verificación client-side 4/4 con `crypto.subtle` + inspección binaria XDR contra el RPC público de Stellar Testnet), exporta en **JSON, XML (`ComprobanteCEP402`) y Póliza Contable CSV**, e integra **Raven MCP** (`https://raven.stellar.org/mcp` vía Streamable HTTP) en el Auditor Forense del Camino Rojo sin meter latencia ni IA en el firewall.

## Herramientas oficiales utilizadas

- **x402 (`@x402/core@2.30.0`, `@x402/express@2.30.0`, `@x402/fetch@2.30.0`, `@x402/stellar@2.30.0`)** + Facilitador Dual local (`@x402/stellar/exact/facilitator`) con simulador explícito de Facilitador Comprometido / MITM para duelo Split-Screen.
- **Soroban RPC (`@stellar/stellar-sdk@17.4.0`)** con Pool Multi-RPC (`createFailoverRpcClient`) para verificación trustless y simulación de contratos `C...`.
- **Raven MCP (`https://raven.stellar.org/mcp`)** vía `.mcp.json` y `partes/coronahernandezs931-cloud/auditor-raven.js` (handshake MCP `2025-03-26` + soporte JSON/SSE).
- **OpenZeppelin Smart Accounts (Reto opcional):** detección polimórfica `payerType: "smart_account"`, extracción de `SorobanAuthorizationEntry`, lectura de `Contract.getFootprint()` y simulación live de `transfer(from=C...)` para diagnóstico CAP-46 / `#3221`.

## Cómo correrlo

Cada integrante explica cómo se corre su parte en `partes/<usuario>/README.md`.

```bash
npm install
npm test                            # 21 pruebas deterministas offline (funciona incluso sin .env -> # fail 0)
npm start                           # UI Split-Screen + Validador Público en http://127.0.0.1:3000
npm run preflight                   # Verifica saldos, trustlines USDC y Soroban RPC (requiere .env)
npm run demo                        # Corrida completa end-to-end en Stellar Testnet (requiere .env)
npm run verificar -- <txHash|json>  # Verificador CLI independiente contra Soroban RPC
```

## Hashes de prueba

Cada parte lista sus pagos de testnet, con su link a Stellar Expert, en su README.

- Pago real `0.01 USDC` verificado Zero-Trust (Folio `CEP402-5909535-25ADCB23`, Ledger `5909535`):
  - `25adcb23697676e05e7efaaf5e7a562a25f06f3c0aaa782d0a9ff0795ab4be8c`
  - Verlo: https://stellar.expert/explorer/testnet/tx/25adcb23697676e05e7efaaf5e7a562a25f06f3c0aaa782d0a9ff0795ab4be8c
- Pago adicional confirmado en Testnet (Ledger `5909443`):
  - `e4d0cdf63792e0c66ee86450790e3817a2ea9ea06fe30c8a85378caa30c99c3b`
  - Verlo: https://stellar.expert/explorer/testnet/tx/e4d0cdf63792e0c66ee86450790e3817a2ea9ea06fe30c8a85378caa30c99c3b

## Equipo y partes

- [coronahernandezs931-cloud](https://github.com/coronahernandezs931-cloud): [su parte](partes/coronahernandezs931-cloud/README.md)
