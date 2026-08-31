"""rqswarm_eval: Swarmie, a passive HTTP signal engine.

Reads completed request/response pairs from a capture database (any supported HTTP-capture proxy) read-only, correlates cheap deterministic signals, and emits redacted
`swarmie.signal.v1` hypotheses — each carrying interrogation questions — into a
bounded mailbox for an LLM to judge. Swarmie surfaces and asks; it never decides
whether a vulnerability exists. Stdlib-only core; no network from the passive
path; no raw secrets in the mailbox. See README.md and CLAUDE.md.
"""

__all__ = ["__version__"]
__version__ = "0.2.0"
