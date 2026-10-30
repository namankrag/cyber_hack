# SCALABILITY

How AgentShield scales horizontally, what each knob changes, and the numbers
measured for this change. Synthetic data only; single-machine measurements.

## Architecture

```
                    +------------------+
                    |  edge load       |
                    |  balancer        |
                    +--------+---------+
                             |
              +--------------+--------------+
              |                             |
   +----------v----------+      +-----------v---------+
   | gateway-a (uvicorn) |      | gateway-b (uvicorn) |
   | stateless verdicts  |      | stateless verdicts  |
   +----+----+----+------+      +-----+----+----+-----+
        |    |    |                       |    |    |
   audit|    |approvals              audit|    |approvals
        |    |    |                       |    |    |
   +----v----v----v-----------------------v----v----v----+
   | shared backends (opt-in, images only in compose):    |
   |  postgres  agentshield_audit / agentshield_approvals |
   |  redis     agentshield:audit / agentshield:approvals |
   +------------------------------------------------------+
   | default (no drivers): JSONL file + audit-backed      |
   | approvals, local to each replica                     |
   +------------------------------------------------------+
```

The decision engine is stateless (audit below), so throughput scales with
replicas: `docker compose up --build` runs gateway-a (:8000) + gateway-b
(:8001) with redis + postgres available. The gateways default to
JSONL/in-memory (no drivers needed); point them at the shared backends with
the env flags when you install the optional drivers.

## Measured numbers

Box: single Windows machine (shared, sibling workloads running — treat as
indicative, not a lab benchmark). Server: `uvicorn agentshield.gateway.app`
1 worker, heuristic detector, `AGENTSHIELD_RATE_LIMIT_PER_MIN=0`.
Tool: `scripts/loadtest.py` (asyncio stdlib, keep-alive, warmed up).
Attribution: the server wrote to a marker audit file; line count matched
requests exactly (3540 lines for 3540 requests), so every request below hit
the measured server.

| workload | req/s | p50 | p99 | errors |
|---|---|---|---|---|
| in-process `shield.check` (2000 iters) | 4028 | 0.25 ms | — | 0 |
| served POST /v1/check allow-only (2000 req, 50 conc) | 624.5 | 79.2 ms | 107.6 ms | 0 |
| served POST /v1/check allow/hold/deny mix (1500 req, 25 conc) | 618.0 | 39.7 ms | 55.7 ms | 0 |

Reading: the engine itself is ~0.25 ms/check; the served cost (~40–80 ms
p50) is the HTTP + threadpool + audit-append stack on one worker, not the
verdict. Repeat runs on the same box varied ±2x with background load; the
gap between in-process and served is the headroom replicas + workers buy.

## Statelessness audit (decision engine)

Method: read the whole check path (`engine_factory.AgentShield.check` ->
`PolicyEngine.evaluate` + detectors + manifest/provenance tripwires),
grepped `agentshield/` for module-level mutable state on that path
(globals written per request, caches, locks), and verified empirically in
`tests/test_scalability.py` (50 repeat checks: identical verdicts, identical
reasons, `vars(engine)`/detector state unchanged; 24 concurrent checks agree).

Findings:

* `PolicyEngine.evaluate` is pure: it reads `self.policy/detectors/manifest`
  (loaded once at startup, never mutated) and builds only local
  `reasons`/`detections` lists. Same inputs -> same verdict, every time.
* `HeuristicDetector.scan` reads module-level compiled regexes (read-only,
  thread-safe) and writes only locals. No per-request instance mutation.
* Per-request mutable state exists only OFF the verdict path, each for a
  stated reason:
  1. Audit appends — that is the sink (`AuditSink`); verdicts do not depend
     on it. JSONL is per-replica local; use the postgres sink for one trail.
  2. Provenance replay-nonce cache — single-use tokens MUST record use
     (replay resistance, item 3). `InMemoryReplayCache` (locked, bounded,
     pruned); swap a Redis backend via `set_replay_cache` for multi-process.
  3. HTTP rate-limit buckets — per-replica edge backpressure, not verdict
     state (`AGENTSHIELD_RATE_LIMIT_PER_MIN`, default 600, 0 disables).
  4. `ToolCall` ids/timestamps — per-call identity (uuid/time), not shared.

Conclusion: replicas share nothing to agree on a verdict. Shared state is
needed only for durability/coordination (audit, approvals) — that is what
the sink/store backends are for.

## Knobs and what each changes

| knob | effect |
|---|---|
| replicas (`gateway-a/b/...` in compose) | linear verdict throughput; engine holds no shared state |
| `uvicorn --workers N` | more serving threads per replica (served p50 falls while the audit lock is uncontended) |
| `AGENTSHIELD_DETECTORS=heuristic` vs `+llm` | heuristic is microseconds; the LLM detector adds seconds per check (not measured here) |
| `AGENTSHIELD_RATE_LIMIT_PER_MIN` | per-IP backpressure per replica; `0` disables (use for engine benchmarks; 429s are reported, not errors, by loadtest) |
| `AGENTSHIELD_AUDIT_BACKEND=jsonl/postgres/redis` | where decisions persist; postgres centralizes the trail across replicas |
| `AGENTSHIELD_APPROVAL_BACKEND=audit/memory/postgres/redis` | where decisions persist; default `audit` keeps current behavior |
| `AGENTSHIELD_POSTGRES_DSN` / `AGENTSHIELD_REDIS_URL` | required by the postgres/redis backends; missing/unreachable FAILS CLOSED at startup, never downgrades |
| `AGENTSHIELD_REDIS_MAX_ENTRIES` (default 100000) | caps the redis lists (audit + approvals) via LTRIM |
| `AGENTSHIELD_UPSTREAM_TIMEOUT_S` (default 30) | one upstream MCP round-trip budget (proxy path) |

## Caveats (honest limits)

* Holds are written by `shield.check` to each replica's audit trail; an
  external approval store shares *decisions*, not holds. Cross-replica
  `/v1/approvals/pending` needs sticky routing (or one approval reader)
  until holds are mirrored. The compose default (`audit`) keeps the
  current per-replica behavior.
* Unconfigured or unreachable postgres/redis backends raise at startup and
  every operation raises instead of writing — by design (fail closed).
* Optional drivers (`psycopg`/`redis-py`) are deliberately NOT in
  requirements.txt; install them in your image layer to enable those
  backends.

## Reproduce

```sh
# terminal 1 (project root):
AGENTSHIELD_RATE_LIMIT_PER_MIN=0 .venv/Scripts/python -m uvicorn \
    agentshield.gateway.app:app --port 8000
# terminal 2:
.venv/Scripts/python scripts/loadtest.py --requests 2000 --concurrency 50
.venv/Scripts/python scripts/loadtest.py --requests 1500 --concurrency 25 --mix
# scale-out:
docker compose up --build
```
