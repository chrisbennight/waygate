-- Phase 5 PR5-1b: mark cache-hit usage rows.
--
-- A gateway cache hit (design §9) is a free, zero-token replay of a previously
-- served completion. It is still ledgered (so call volume/latency analytics see
-- it), but without this flag a hit is indistinguishable in the durable usage
-- ledger from a real zero-token provider call. `gateway_cache_hit` lets
-- operators separate cache hits from upstream calls when attributing cost and
-- volume. Defaults false: every pre-existing row, and every real provider call,
-- reads as a non-hit.
ALTER TABLE llm_usage ADD COLUMN gateway_cache_hit BOOLEAN NOT NULL DEFAULT false;
