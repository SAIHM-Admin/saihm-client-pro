// Canonical server-issued monotonic sequence rule. The high-water mark is ENFORCED by the
// SAIHM server-side runtime; this module is the single source of truth for the rule so that
// the server and the client test-suite agree. Because `seq` is inside the
// ML-DSA-signed record, a client cannot advance it without the signing key, and SAIHM rejects
// any write whose `seq` is not strictly greater than the current high-water mark — preventing
// rollback to stale content and re-instatement of a forgotten cell.

/** Accept iff `incoming` strictly exceeds the current high-water mark (or it is the first write). */
export function acceptSeq(
  current: bigint | undefined,
  incoming: bigint,
): boolean {
  if (incoming < 0n) return false;
  if (current === undefined) return true;
  return incoming > current;
}

/** Reference per-cell high-water-mark store, keyed `${agentIdHashHex}:${cellId}`. */
export class SeqHighWaterMark {
  private readonly hw = new Map<string, bigint>();

  private key(agentIdHashHex: string, cellId: string): string {
    return `${agentIdHashHex}:${cellId}`;
  }

  /** Admit + advance if accepted; return false (no state change) if stale/replayed. */
  admit(agentIdHashHex: string, cellId: string, seq: bigint): boolean {
    const k = this.key(agentIdHashHex, cellId);
    if (!acceptSeq(this.hw.get(k), seq)) return false;
    this.hw.set(k, seq);
    return true;
  }

  current(agentIdHashHex: string, cellId: string): bigint | undefined {
    return this.hw.get(this.key(agentIdHashHex, cellId));
  }
}
