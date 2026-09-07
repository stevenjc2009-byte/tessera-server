"""Per-source-address and global token buckets.

Keyed on IP only, never on (IP, port) — an attacker changes source port for
free, so including it would make the limiter trivially bypassable. The address
comes from the PROXY protocol v2 header (proxyproto.py), which is why that
header is a hard requirement rather than a nicety: without it every console
shares the playit relay's address and this becomes one bucket for the world.

Time is passed in rather than read internally so the buckets can be tested
deterministically, exactly as Blocksmith's gateway/ratelimit.c does.

The slot table is bounded and evicts least-recently-used. Bounding it matters:
an unbounded dict keyed on attacker-controlled addresses is itself a memory
exhaustion primitive. Evicting LRU rather than at random matters too — an
address that is actively flooding is by definition recently used, so it keeps
its empty bucket instead of being forgotten and handed a fresh burst.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass

from .config import TesseraConfig


@dataclass
class _Bucket:
    tokens: float
    last: float


class TokenBucketLimiter:
    """One bucket per address, plus a ceiling across all of them."""

    def __init__(
        self,
        *,
        slots: int,
        burst: int,
        refill_secs: float,
        global_burst: int,
        global_refill_secs: float,
    ) -> None:
        self._slots = max(1, int(slots))
        self._burst = float(burst)
        self._refill_secs = float(refill_secs)
        self._global_burst = float(global_burst)
        self._global_refill_secs = float(global_refill_secs)
        self._buckets: OrderedDict[str, _Bucket] = OrderedDict()
        self._global = _Bucket(tokens=float(global_burst), last=0.0)
        self._global_started = False

    @classmethod
    def from_config(cls, cfg: TesseraConfig) -> TokenBucketLimiter:
        return cls(
            slots=cfg.ip_slots,
            burst=cfg.ip_burst,
            refill_secs=cfg.ip_refill_secs,
            global_burst=cfg.global_burst,
            global_refill_secs=cfg.global_refill_secs,
        )

    def tracked(self) -> int:
        return len(self._buckets)

    @staticmethod
    def _refill(bucket: _Bucket, now: float, burst: float, refill_secs: float) -> None:
        if refill_secs <= 0.0:
            bucket.tokens = burst
        else:
            elapsed = max(0.0, now - bucket.last)
            bucket.tokens = min(burst, bucket.tokens + elapsed / refill_secs)
        bucket.last = now

    def allow(self, ip: str, now: float) -> bool:
        """True if a request from `ip` may proceed, consuming one token from
        the address bucket AND the global bucket. False consumes nothing."""
        if not self._global_started:
            self._global.last = now
            self._global_started = True

        bucket = self._buckets.get(ip)
        if bucket is None:
            if len(self._buckets) >= self._slots:
                self._buckets.popitem(last=False)  # least recently used
            bucket = _Bucket(tokens=self._burst, last=now)
            self._buckets[ip] = bucket
        self._buckets.move_to_end(ip)

        self._refill(bucket, now, self._burst, self._refill_secs)
        if bucket.tokens < 1.0:
            return False

        # Only now is the global bucket touched. Charging it before the
        # per-address check would let one flooding address drain the ceiling
        # for everybody with requests that were going to be refused anyway.
        self._refill(self._global, now, self._global_burst, self._global_refill_secs)
        if self._global.tokens < 1.0:
            return False

        bucket.tokens -= 1.0
        self._global.tokens -= 1.0
        return True
