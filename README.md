# Swarmie

**Swarmie is a passive HTTP signal sluice.** It reads completed request/response pairs from a
capture database (any supported HTTP-capture proxy) **read-only**, correlates cheap deterministic signals,
and emits redacted `swarmie.signal.v1` hypotheses — each carrying interrogation questions — into
a bounded mailbox for an LLM to judge. Swarmie **surfaces and asks; it never decides whether a
vulnerability exists.** That is the LLM's job.

> Swarm explores, LLM judges: cheap correlation handles volume, dedup, and prioritization; the
> scarce frontier judge handles strategy and verdicts.

## What is the product (read these first)

| area | where | role |
|------|-------|------|
| Passive engine | `rqswarm_eval/passive.py` | the tailer: read-only cursor, ~44 signal families, investigation graph, per-signal interrogation |
| Supporting | `rqswarm_eval/{sources,triage,response}.py`, `rqswarm_eval/profile_adapter.py` | request profiling, card/hypothesis building, response normalization, observable-feature routing (imported by the engine) |
| Learned lane | `rqswarm_eval/learned_lane.py` + `sidecar/` | optional out-of-process classifier for meaning-defined families (agent-injection); tier-1 heuristic + tier-3 Core ML |
| Contract & design | `AGENTS.md` / `CLAUDE.md` (handoff), `ARCHITECTURE.md`, `.devfw/decisions/` | mission, boundaries, the swarm-explores/LLM-judges architecture, ADRs |
| Tests | `tests/test_passive.py`, `test_learned_lane.py`, `test_sidecar.py` | the executable specification |

The non-negotiable boundaries (read-only DB, no HTTP from the passive path, no raw secrets in
the mailbox, hypothesis-never-finding, stdlib-only core) are listed in `AGENTS.md`.

## Removed: the legacy falsification / GA harness

An earlier phase carried a synthetic-fixture falsification harness — generators, evolutionary
proposers, scheduler, judge, executor, oracle fixtures, and `check`/`anti` probes. It was a
documented dead-end: the synthetic-fixture GA is unsolvable by blind search, so it yields no
gradient (`ARCHITECTURE.md` finding #4). It has been **removed** from the product. The full
harness is preserved at git tag `archive/experiment-harness` (and branch
`worktree-passive-triage`) if ever needed. Its surviving *discipline* — the append-only
hash-chained ledger (`ledger.py`, used by `triage.py`) and the stdlib-only + deterministic
constraints — lives on in the passive engine. The real fitness signal is the scarce LLM judge:
**learn from labels, not blind search.**

## Status

Verified: the passive core works and is measured (zero DB writes, no raw secrets in the mailbox,
throughput target met, real leads found). **Not yet end-to-end** by its own definition of done —
the production LLM + capture-driver adapter and the outcome/learning loop are the open work. Until
those are demonstrated, describe Swarmie as a working *signal engine* with an unproven
*integration + learning* story, not a finished system.

## Quick start

```bash
pytest -q                                   # full suite

# bounded historical assessment over a capture DB
python3 -m rqswarm_eval.passive \
  --source /path/to/traffic.db \
  --mailbox /tmp/swarmie-signals.jsonl \
  --checkpoint /tmp/swarmie-checkpoint.json \
  --start 0 --once --max-rows 10000 --batch 10000 --hydrate-limit 256
```

### Capture-DB discovery (bulk triage)

A *capture DB* is any SQLite file carrying the `http_traffic` ⋈ `http_messages` schema. A single
run takes one DB via `--source` (above). To triage many DBs at once, point discovery at your
capture stores with `$SWARMIE_CAPTURE_GLOBS` (colon-separated globs) or repeated `--glob`:

```bash
# via env var (colon-separated glob patterns)
export SWARMIE_CAPTURE_GLOBS="$HOME/captures/*.db:$HOME/proxy/**/traffic.db"
python3 -m rqswarm_eval.triage_all --out runs/triage

# or pass globs explicitly (repeatable)
python3 -m rqswarm_eval.triage_all --glob '~/captures/*.db' --glob '~/proxy/**/traffic.db'
```

Nothing is sent: `triage_all` is a dry run that reads each DB read-only and writes a cross-corpus
`SUMMARY.json` plus a ranked shortlist. Only DBs with a non-empty `http_traffic` table are used;
if no globs are configured it prints a hint and exits.

The learned-lane sidecar (optional) is documented in `sidecar/README.md`.
