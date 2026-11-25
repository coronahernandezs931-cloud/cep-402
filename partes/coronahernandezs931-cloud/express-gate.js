import { AsyncLocalStorage } from 'node:async_hooks';
import { buildAndSignReceipt, canonicalize, sha256Hex } from './receipt.js';
import { verifyOnChainSettlement, USDC_SAC_TESTNET } from './stellar-extractor.js';

export const cep402ALS = new AsyncLocalStorage();

/**
 * Engancha la verificación on-chain de las 7 invariantes + AtomicReplayStore
 * en el hook `onAfterSettle` del x402ResourceServer.
 */
export function attachCep402AfterSettleHook(
  resourceServer,
  {
    rpcServer,
    replayStore,
    expectedAssetContract = USDC_SAC_TESTNET,
    maxLedgerAge = 60,
    pollDelaysMs,
    onAuditEvent = null,
  }
) {
  resourceServer.onAfterSettle(async ({ requirements, result }) => {
    const reqCtx = cep402ALS.getStore();
    if (!reqCtx) return;

    const txHash = result?.transaction;
    // Invariante 1 (ANTES de tocar RPC): Lock atómico síncrono contra replay y race condition 5x
    const lock = replayStore.tryAcquireSync(txHash);
    if (!lock.acquired) {
      const fail = {
        ok: false,
        transient: false,
        code: lock.reason,
        detail:
          lock.reason === 'REPLAY_COMMITTED'
            ? `El txHash ${txHash} ya fue consumido previamente (${lock.firstCommittedAt || 'commit previo'}).`
            : lock.reason === 'REPLAY_IN_FLIGHT'
              ? `Ráfaga paralela bloqueada: el txHash ${txHash} ya está siendo verificado en vuelo.`
              : `Hash de transacción inválido reportado por el facilitador: ${txHash}`,
        txHash,
        invariants: {
          antiReplayLock: false,
        },
      };
      reqCtx.cep402 = fail;
      onAuditEvent?.({ type: 'BLOCKED', ...fail });
      return;
    }

    const check = await verifyOnChainSettlement(rpcServer, {
      txHash: lock.key,
      expectedPayTo: requirements.payTo,
      expectedAmount: requirements.amount,
      expectedAssetContract,
      maxLedgerAge,
      ...(pollDelaysMs ? { pollDelaysMs } : {}),
    });

    if (!check.ok) {
      // Liberamos PENDING porque nunca se sirvió 200 OK ni se comprometió el recurso
      replayStore.releasePending(lock.key);
      const fail = {
        ...check,
        txHash: lock.key,
        invariants: { antiReplayLock: true, ...(check.invariants || {}) },
      };
      reqCtx.cep402 = fail;
      onAuditEvent?.({ type: 'BLOCKED', ...fail });
      return;
    }

    try {
      replayStore.commitSync(lock.key, {
        ledger: check.settlement.ledger,
        amount: check.settlement.amount,
        payer: check.settlement.payer,
        payTo: check.settlement.payTo,
      });
      const verified = {
        ...check,
        invariants: { antiReplayLock: true, ...check.invariants },
      };
      reqCtx.cep402 = verified;
      onAuditEvent?.({ type: 'VERIFIED', ...verified });
    } catch (diskErr) {
      // No liberamos si falló fsync tras escribir: fallamos cerrado 503
      const fail = {
        ok: false,
        transient: true,
        code: 'REPLAY_PERSIST_FAILED',
        detail: diskErr?.message ?? 'Error al persistir en AtomicReplayStore',
        txHash: lock.key,
      };
      reqCtx.cep402 = fail;
      onAuditEvent?.({ type: 'BLOCKED', ...fail });
    }
  });
}

/**
 * Middleware Zero-Trust de 1 línea: `app.use(cep402Gate(...))`
 * DEBE montarse ANTES de `paymentMiddleware` para actuar como outer-wrapper fail-closed
 * cuando `@x402/express` termina `settle()` y reproduce el body de respuesta.
 */
export function createCep402Gate({
  merchantSecret,
  network = 'stellar:testnet',
  isProtected = () => true,
  onReceiptIssued = null,
}) {
  return function cep402Gate(req, res, next) {
    res.setHeader(
      'Access-Control-Expose-Headers',
      'X-CEP402-Receipt, X-CEP402-Tx-Hash, X-CEP402-Folio, PAYMENT-RESPONSE, PAYMENT-REQUIRED'
    );

    if (!isProtected(req) || req.headers.accept?.includes('text/event-stream')) {
      return next();
    }

    const ctx = { cep402: null };
    const chunks = [];
    let pendingStatus = null;
    let pendingMessage = null;
    let finalized = false;

    const origWriteHead = res.writeHead.bind(res);
    const origWrite = res.write.bind(res);
    const origEnd = res.end.bind(res);
    const origFlushHeaders = res.flushHeaders.bind(res);

    res.writeHead = (statusCode, statusMessage, headers) => {
      pendingStatus = statusCode;
      if (typeof statusMessage === 'string') {
        pendingMessage = statusMessage;
        if (headers) {
          for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
        }
      } else if (statusMessage && typeof statusMessage === 'object') {
        for (const [k, v] of Object.entries(statusMessage)) res.setHeader(k, v);
      }
      res.statusCode = statusCode;
      return res;
    };

    res.write = (chunk, encoding) => {
      if (chunk != null) {
        chunks.push(
          Buffer.isBuffer(chunk)
            ? chunk
            : Buffer.from(chunk, typeof encoding === 'string' ? encoding : 'utf8')
        );
      }
      return true;
    };

    res.flushHeaders = () => {
      // Retenido hasta validar las 7 invariantes on-chain
    };

    res.end = (chunk, encoding, cb) => {
      if (finalized) return res;
      finalized = true;

      if (typeof chunk === 'function') {
        cb = chunk;
        chunk = undefined;
        encoding = undefined;
      } else if (typeof encoding === 'function') {
        cb = encoding;
        encoding = undefined;
      }
      if (chunk != null) {
        chunks.push(
          Buffer.isBuffer(chunk)
            ? chunk
            : Buffer.from(chunk, typeof encoding === 'string' ? encoding : 'utf8')
        );
      }

      const rawBody = Buffer.concat(chunks);
      const status = pendingStatus ?? res.statusCode ?? 200;

      const restore = () => {
        res.writeHead = origWriteHead;
        res.write = origWrite;
        res.end = origEnd;
        res.flushHeaders = origFlushHeaders;
      };

      // Dejar pasar challenge 402 inicial, 4xx y 5xx sin alterar
      if (status < 200 || status >= 300) {
        restore();
        if (pendingMessage) origWriteHead(status, pendingMessage);
        return origEnd(rawBody, cb);
      }

      // FAIL-CLOSED GATE para cualquier 2xx en ruta protegida
      if (!ctx.cep402?.ok) {
        const fail = ctx.cep402 ?? {
          code: 'UNVERIFIED_SETTLEMENT',
          detail: 'No se recibió verificación on-chain de CEP-402.',
          transient: false,
        };
        const rejectStatus = fail.code?.startsWith('REPLAY_')
          ? 409
          : fail.transient
            ? 503
            : 403;
        res.removeHeader('PAYMENT-RESPONSE');
        res.removeHeader('X-PAYMENT-RESPONSE');
        res.removeHeader('ETag');
        const errBuf = Buffer.from(
          JSON.stringify({
            blockedBy: 'CEP-402',
            error: fail.code,
            detail: fail.detail,
            txHash: fail.txHash ?? null,
            invariants: fail.invariants ?? null,
          }),
          'utf8'
        );
        res.statusCode = rejectStatus;
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        res.setHeader('Cache-Control', 'no-store');
        res.setHeader('Content-Length', String(errBuf.length));
        restore();
        return origEnd(errBuf, cb);
      }

      // 7 invariantes confirmadas on-chain: sellar SHA256(rawBody) + firma Ed25519
      const qIndex = req.originalUrl.indexOf('?');
      const rawQuery = qIndex >= 0 ? req.originalUrl.slice(qIndex + 1) : '';
      const envelope = buildAndSignReceipt({
        settlement: ctx.cep402.settlement,
        reqMeta: {
          method: req.method,
          path: req.path,
          querySha256: sha256Hex(Buffer.from(rawQuery, 'utf8')),
        },
        resMeta: {
          status,
          contentType: String(res.getHeader('Content-Type') ?? 'application/json; charset=utf-8'),
          bodySha256: sha256Hex(rawBody),
        },
        merchantSecret,
        network,
      });

      const receiptB64 = Buffer.from(canonicalize(envelope), 'utf8').toString('base64url');
      res.setHeader('X-CEP402-Receipt', receiptB64);
      res.setHeader('X-CEP402-Tx-Hash', ctx.cep402.settlement.txHash);
      res.setHeader('X-CEP402-Folio', envelope.payload.folio);
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Content-Length', String(rawBody.length));
      onReceiptIssued?.(envelope, rawBody);

      restore();
      return origEnd(rawBody, cb);
    };

    cep402ALS.run(ctx, () => next());
  };
}
