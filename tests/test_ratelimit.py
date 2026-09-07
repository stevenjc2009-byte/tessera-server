from __future__ import annotations

from tessera.config import TesseraConfig
from tessera.ratelimit import TokenBucketLimiter

IP_A = "203.0.113.9"
IP_B = "198.51.100.4"


def limiter(**kwargs) -> TokenBucketLimiter:
    args = dict(slots=8, burst=3, refill_secs=1.0, global_burst=100, global_refill_secs=0.01)
    args.update(kwargs)
    return TokenBucketLimiter(**args)


def test_a_cold_address_may_burst_then_is_refused() -> None:
    rl = limiter()
    assert [rl.allow(IP_A, 0.0) for _ in range(3)] == [True, True, True]
    assert rl.allow(IP_A, 0.0) is False


def test_a_refused_request_consumes_nothing_from_the_global_bucket() -> None:
    rl = limiter(global_burst=10, global_refill_secs=1000.0)
    for _ in range(3):
        rl.allow(IP_A, 0.0)
    for _ in range(20):
        rl.allow(IP_A, 0.0)          # all refused by the per-IP bucket
    # IP_B must still have the whole global allowance minus IP_A's 3.
    assert [rl.allow(IP_B, 0.0) for _ in range(3)] == [True, True, True]


def test_tokens_come_back_over_time() -> None:
    rl = limiter()
    for _ in range(3):
        rl.allow(IP_A, 0.0)
    assert rl.allow(IP_A, 0.5) is False
    assert rl.allow(IP_A, 1.0) is True
    assert rl.allow(IP_A, 1.0) is False
    assert rl.allow(IP_A, 3.0) is True


def test_a_bucket_never_refills_past_its_burst() -> None:
    rl = limiter()
    rl.allow(IP_A, 0.0)
    assert [rl.allow(IP_A, 10_000.0) for _ in range(3)] == [True, True, True]
    assert rl.allow(IP_A, 10_000.0) is False


def test_addresses_are_independent() -> None:
    rl = limiter()
    for _ in range(3):
        assert rl.allow(IP_A, 0.0) is True
    assert rl.allow(IP_A, 0.0) is False
    assert rl.allow(IP_B, 0.0) is True


def test_the_global_ceiling_stops_a_distributed_flood() -> None:
    rl = limiter(slots=512, burst=100, global_burst=5, global_refill_secs=1000.0)
    allowed = sum(rl.allow(f"203.0.113.{i}", 0.0) for i in range(50))
    assert allowed == 5


def test_the_slot_table_does_not_grow_without_bound() -> None:
    rl = limiter(slots=8, global_burst=10_000, global_refill_secs=0.0001)
    for i in range(200):
        rl.allow(f"10.0.0.{i}", float(i))
    assert rl.tracked() <= 8


def test_evicting_a_slot_does_not_hand_out_free_tokens_to_a_live_flooder() -> None:
    # The evicted slot must be the least recently used, so an address that is
    # hammering keeps its (empty) bucket rather than being forgotten and reset.
    rl = limiter(slots=2, burst=1, refill_secs=1000.0, global_burst=10_000,
                 global_refill_secs=0.0001)
    assert rl.allow(IP_A, 0.0) is True
    assert rl.allow(IP_A, 0.1) is False
    rl.allow("10.0.0.1", 0.2)
    assert rl.allow(IP_A, 0.3) is False, "a flooding address was evicted and reset"


def test_from_config_uses_the_configured_numbers(config: TesseraConfig) -> None:
    rl = TokenBucketLimiter.from_config(config)
    allowed = sum(rl.allow(IP_A, 0.0) for _ in range(config.ip_burst + 5))
    assert allowed == config.ip_burst
