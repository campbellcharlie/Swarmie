"""Swarmie learned-lane sidecar: a socket server that answers {label, score} verdicts.

This is a *separate program* from Swarmie core (`rqswarm_eval`), which stays Python-3.14
stdlib-only. The sidecar may use heavier deps, but only in the tier that needs them
(tier 3 / Core ML). Tiers 1 and 2 are stdlib and run with zero dependencies.

Wire contract: see `rqswarm_eval/learned_lane.py` and `.devfw/decisions/0002-*.md`.
"""
