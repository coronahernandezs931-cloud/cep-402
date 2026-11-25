import express from 'express';
import { x402Facilitator } from '@x402/core/facilitator';
import { ExactStellarScheme } from '@x402/stellar/exact/facilitator';
import { createEd25519Signer } from '@x402/stellar';

export const FACILITATOR_MODES = ['HONEST', 'FAKE_SETTLE', 'REPLAY_OLD_TX', 'UNDERPAY_TX', 'FAKE_SAC_TX'];

/**
 * Facilitador Dual x402 en proceso (implementa la interfaz FacilitatorClient de @x402/core).
 * - En modo HONEST: liquida pagos REALES USDC en Stellar Testnet usando @x402/stellar/exact/facilitator
 *   (con Fee Sponsoring real del FACILITATOR_SECRETA).
 * - En modos CORRUPT: simula explícitamente un Facilitador Comprometido / MITM
 *   para demostrar en vivo cómo x402 Vanilla entrega el recurso sin pago mientras CEP-402 lo bloquea.
 */
export class DualFacilitatorClient {
  constructor({
    facilitatorSecret = null,
    rpcUrl = 'https://soroban-testnet.stellar.org',
    network = 'stellar:testnet',
    underlyingFacilitator = null,
  } = {}) {
    this.network = network;
    this.rpcUrl = rpcUrl;
    this.mode = 'HONEST';
    this.seeds = {
      lastRealTxHash: null,
      underpayTxHash: null,
      fakeSacTxHash: null,
    };

    if (underlyingFacilitator) {
      this._facilitator = underlyingFacilitator;
    } else if (facilitatorSecret) {
      const signer = createEd25519Signer(facilitatorSecret, network);
      this._facilitator = new x402Facilitator().register(
        network,
        new ExactStellarScheme([signer], { rpcConfig: { url: rpcUrl } })
      );
    } else {
      // Fallback para tests offline sin llaves reales
      this._facilitator = null;
    }
  }

  setMode(mode, seeds = {}) {
    if (!FACILITATOR_MODES.includes(mode)) {
      throw new Error(`Modo inválido: ${mode}. Permitidos: ${FACILITATOR_MODES.join(', ')}`);
    }
    this.mode = mode;
    if (seeds.lastRealTxHash) this.seeds.lastRealTxHash = seeds.lastRealTxHash;
    if (seeds.underpayTxHash) this.seeds.underpayTxHash = seeds.underpayTxHash;
    if (seeds.fakeSacTxHash) this.seeds.fakeSacTxHash = seeds.fakeSacTxHash;
    return this.getState();
  }

  getState() {
    return {
      mode: this.mode,
      isCompromised: this.mode !== 'HONEST',
      seeds: { ...this.seeds },
    };
  }

  async getSupported() {
    if (this._facilitator) {
      return this._facilitator.getSupported();
    }
    return {
      kinds: [
        {
          x402Version: 2,
          scheme: 'exact',
          network: this.network,
          extra: { areFeesSponsored: true },
        },
      ],
      extensions: [],
      signers: {},
    };
  }

  async verify(paymentPayload, paymentRequirements) {
    if (this.mode !== 'HONEST') {
      // Facilitador comprometido aprueba sin simular on-chain
      return {
        isValid: true,
        payer: 'GCORRUPTFACILITATORBYPASSAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      };
    }
    if (!this._facilitator) {
      throw new Error('Facilitador real no configurado (falta FACILITATOR_SECRETA)');
    }
    return this._facilitator.verify(paymentPayload, paymentRequirements);
  }

  async settle(paymentPayload, paymentRequirements) {
    if (this.mode === 'FAKE_SETTLE') {
      return {
        success: true,
        transaction: 'deadbeef'.repeat(8), // Hash inexistente en Stellar Testnet
        network: this.network,
        payer: 'GCORRUPTFACILITATORBYPASSAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      };
    }
    if (this.mode === 'REPLAY_OLD_TX') {
      const txHash = this.seeds.lastRealTxHash || '11'.repeat(32);
      return {
        success: true,
        transaction: txHash,
        network: this.network,
      };
    }
    if (this.mode === 'UNDERPAY_TX') {
      const txHash = this.seeds.underpayTxHash || '22'.repeat(32);
      return {
        success: true,
        transaction: txHash,
        network: this.network,
      };
    }
    if (this.mode === 'FAKE_SAC_TX') {
      const txHash = this.seeds.fakeSacTxHash || '33'.repeat(32);
      return {
        success: true,
        transaction: txHash,
        network: this.network,
      };
    }

    if (!this._facilitator) {
      throw new Error('Facilitador real no configurado (falta FACILITATOR_SECRETA)');
    }
    const result = await this._facilitator.settle(paymentPayload, paymentRequirements);
    if (result?.success && result.transaction) {
      this.seeds.lastRealTxHash = result.transaction;
    }
    return result;
  }
}

/**
 * Expone endpoints HTTP estándar x402 (`/supported`, `/verify`, `/settle`) sobre el mismo Express.
 */
export function createFacilitatorRouter(dualClient) {
  const router = express.Router();
  router.get('/supported', async (_req, res) => {
    res.json(await dualClient.getSupported());
  });
  router.post('/verify', async (req, res) => {
    const { paymentPayload, paymentRequirements } = req.body ?? {};
    res.json(await dualClient.verify(paymentPayload, paymentRequirements));
  });
  router.post('/settle', async (req, res) => {
    const { paymentPayload, paymentRequirements } = req.body ?? {};
    res.json(await dualClient.settle(paymentPayload, paymentRequirements));
  });
  return router;
}
