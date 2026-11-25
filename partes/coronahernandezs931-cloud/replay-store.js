import fs from 'node:fs';
import path from 'node:path';

/**
 * Store Anti-Replay estrictamente atómico en Node.js.
 * - tryAcquireSync() no tiene awaits: ante una ráfaga 5x Promise.all,
 *   EXACTAMENTE 1 request adquiere el lock y 4 son rechazados con 409 Conflict en <1ms.
 * - Persiste en NDJSON con fs.writeSync + fs.fsyncSync para sobrevivir reinicios.
 */
export class AtomicReplayStore {
  constructor({ filePath = null, inMemory = false } = {}) {
    this.inMemory = Boolean(inMemory || !filePath);
    this.filePath = this.inMemory ? null : filePath;
    this.entries = new Map(); // txHash -> { state: 'PENDING' | 'COMMITTED', meta }
    this.fd = null;

    if (!this.inMemory && this.filePath) {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      this._loadSync();
      this.fd = fs.openSync(this.filePath, 'a');
    }
  }

  _loadSync() {
    if (!this.filePath || !fs.existsSync(this.filePath)) return;
    const raw = fs.readFileSync(this.filePath, 'utf8');
    for (const line of raw.split('\n')) {
      if (!line.trim()) continue;
      try {
        const rec = JSON.parse(line);
        if (typeof rec.txHash === 'string' && /^[0-9a-f]{64}$/.test(rec.txHash)) {
          this.entries.set(rec.txHash, { state: 'COMMITTED', meta: rec });
        }
      } catch {
        // Ignora última línea truncada si hubo corte brusco de energía
      }
    }
  }

  tryAcquireSync(txHash) {
    const key = String(txHash ?? '').trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(key)) {
      return { acquired: false, reason: 'INVALID_TX_HASH', key };
    }
    const existing = this.entries.get(key);
    if (existing?.state === 'COMMITTED') {
      return {
        acquired: false,
        reason: 'REPLAY_COMMITTED',
        key,
        firstCommittedAt: existing.meta?.committedAt ?? null,
      };
    }
    if (existing?.state === 'PENDING') {
      return { acquired: false, reason: 'REPLAY_IN_FLIGHT', key };
    }
    this.entries.set(key, { state: 'PENDING', meta: { acquiredAt: new Date().toISOString() } });
    return { acquired: true, key };
  }

  commitSync(txHash, meta = {}) {
    const key = String(txHash ?? '').trim().toLowerCase();
    const cur = this.entries.get(key);
    if (cur?.state !== 'PENDING') {
      throw new Error(`Invalid state transition to COMMITTED for ${key}`);
    }
    const record = { txHash: key, committedAt: new Date().toISOString(), ...meta };
    if (!this.inMemory && this.fd !== null) {
      const line = `${JSON.stringify(record)}\n`;
      fs.writeSync(this.fd, line, null, 'utf8');
      fs.fsyncSync(this.fd);
    }
    this.entries.set(key, { state: 'COMMITTED', meta: record });
    return record;
  }

  /**
   * SOLO libera entradas PENDING que fallaron antes de comprometerse.
   * JAMÁS borra una entrada COMMITTED.
   */
  releasePending(txHash) {
    const key = String(txHash ?? '').trim().toLowerCase();
    if (this.entries.get(key)?.state === 'PENDING') {
      this.entries.delete(key);
    }
  }

  has(txHash) {
    const key = String(txHash ?? '').trim().toLowerCase();
    return this.entries.get(key)?.state === 'COMMITTED';
  }

  get(txHash) {
    const key = String(txHash ?? '').trim().toLowerCase();
    return this.entries.get(key) ?? null;
  }

  stats() {
    let committed = 0;
    let pending = 0;
    for (const v of this.entries.values()) {
      if (v.state === 'COMMITTED') committed += 1;
      else if (v.state === 'PENDING') pending += 1;
    }
    return { committed, pending, total: this.entries.size };
  }

  close() {
    if (this.fd !== null) {
      fs.closeSync(this.fd);
      this.fd = null;
    }
  }
}
