# perception spine — FROZEN CONTRACT (ADR-0003)

Every builder reads this file first and conforms EXACTLY. Python 3.14. Core files
(`rqswarm_eval/perception/*`) are **stdlib-only, no network, deterministic, pure**. The
sidecar file (`sidecar/scorers/interest.py`) may use math/stdlib only for now. Do NOT edit
any existing file; create ONLY the file you are assigned. Mirror the style of the named
reference file.

## File 1 — `rqswarm_eval/perception/obs_features.py` (core, stdlib, pure)
Reference for style: `sidecar/features.py`.

```
FEATURE_NAMES: list[str]                      # canonical order, FROZEN as listed below
def observation_features(envelope: dict) -> dict[str, float]   # every name -> float, pure
def feature_list(envelope: dict) -> list[float]                # [features[n] for n in FEATURE_NAMES]
```
`envelope` is a `swarmie.signal.v1` dict (schema in this contract's appendix). Missing keys →
treat as absent/zero, never raise. All values finite floats. FEATURE_NAMES (exactly these, in
order):
```
# reason-family counts (map each reason string to a family via REASON_FAMILY; count per family)
rf_idor rf_injection rf_leak rf_error rf_auth rf_cors rf_cache rf_exfil rf_redirect
rf_jwt rf_disclosure rf_novel_status rf_novel_shape rf_other
# request structure
req_header_count req_query_count req_body_key_count req_auth_present req_has_body
req_ct_json req_ct_form req_ct_xml req_ct_multipart req_ct_other
# response structure
resp_2xx resp_3xx resp_4xx resp_5xx
resp_ct_json resp_ct_html resp_ct_js resp_ct_xml resp_ct_text resp_ct_other
resp_length_log resp_json_key_count resp_has_fingerprint
# baseline / rarity
base_obs_log base_status_seen base_ctype_seen
# signal-level
sig_attention_norm sig_reason_count sig_hypothesis_count sig_lens_count sig_learned_hit
```
Normalization rules: counts clipped at a sane cap then left as float (document the cap inline);
`*_log` = `math.log1p(x)`; onehots ∈ {0.0,1.0}; `sig_attention_norm` = attention.score/100
clipped 0..1; `base_status_seen`/`base_ctype_seen` = 1.0 if this response status/content_type
appears in `observation.baseline.statuses`/`.content_types`, else 0.0. Provide a module-level
`REASON_FAMILY: dict[str,str]` mapping known reason substrings to the rf_* family (e.g.
"idor"->idor, "resp:leak"/"leak"/"excessive"->leak, "error"/"stack"->error, "new_status"->
novel_status, route:* -> its class); anything unmatched increments `rf_other`.

## File 2 — `rqswarm_eval/perception/interest_lane.py` (core, stdlib)
Reference for style + fail-open + framing: `rqswarm_eval/learned_lane.py` (COPY its
`_LEN`, `_recv_exact`, `_MAX_RESPONSE`, socket/timeout/error handling pattern verbatim).

```
class InterestLane:
    def __init__(self, socket_path: str, *, active: bool = False, timeout: float = 0.5): ...
    def score_batch(self, batch: list[list[float]], feature_names: list[str]) -> list[float] | None: ...
def make_interest_lane(socket_path: str | None, *, active: bool = False) -> InterestLane | None
```
Wire (uint32-BE length prefix + UTF-8 JSON, ONE request/response per connection):
```
request  = {"v":1,"kind":"interest","feature_names":[...],"batch":[[f,...],...]}
response = {"v":1,"scores":[f,...],"model":"<str>"}
```
`score_batch`: empty batch -> `[]` (no socket call). On ANY error (connect/timeout/framing/
parse), or if `len(scores) != len(batch)`, or a non-list `scores` -> return `None`
(fail-open). Never raise into the caller. `make_interest_lane(None)` -> `None`.

## File 3 — `sidecar/scorers/interest.py` (sidecar side; math+stdlib only)
Reference for style: `sidecar/scorers/heuristic.py`. Register nothing; the server wires it.

```
class InterestScorer:
    model_id = "interest-heuristic-v1"
    def __init__(self): ...                         # holds running per-feature baseline
    def score_batch(self, batch: list[list[float]], feature_names: list[str]) -> list[float]: ...
```
Unsupervised. For each vector return interest ∈ [0,1] combining:
  * anomaly = mean over features of clipped squared z-score vs the running baseline
    (Welford mean/variance); high = unusual;
  * novelty = fraction of features exceeding running mean+1σ;
  * prior = weighted sum of a few always-interesting feature NAMES (look them up by
    `feature_names.index(...)`, tolerate absence): sig_attention_norm, sig_learned_hit,
    rf_idor, rf_leak, rf_error, rf_exfil, rf_auth.
Combine via logistic into [0,1]. Update the running baseline with the batch **after** scoring
it (so a score depends only on vectors seen before this batch; the first-ever batch scores on
`prior` alone). Deterministic; no RNG; no third-party imports. Handle ragged/short vectors and
an empty batch (`-> []`) without raising.

## File 4 — `rqswarm_eval/perception/fuse.py` (core, stdlib, pure)
```
def fuse_interest(attention_0_100: float, interest_0_1: float | None,
                  *, w_attention: float = 0.6, w_interest: float = 0.4) -> float
    # -> priority in [0,1]. interest None -> attention/100 clipped (dormant fallback).
def select_top_k(scored: list[tuple], *, k_frac: float = 0.05, k_min: int = 3,
                 k_max: int = 50) -> set
    # scored = [(id, priority), ...]; return the set of ids in the top ceil(k_frac*N)
    # bounded to [k_min, k_max] and to N; ties broken by higher priority then by id.
```

## File 5 — `tests/test_perception.py` (pytest, stdlib)
Reference for style: `tests/test_gate.py`, `tests/test_sidecar.py`. Cover:
  * obs_features: determinism (same envelope -> identical vector twice); every FEATURE_NAME
    present; `len(feature_list)==len(FEATURE_NAMES)`; a hand-built envelope with an idor+leak
    reason sets rf_idor/rf_leak >=1 and sig_attention_norm from attention.score.
  * InterestScorer.score_batch: all scores in [0,1]; a vector with high prior features
    (attention_norm=1, rf_leak=3) scores higher than an all-zero vector; empty batch -> [].
  * InterestLane: `make_interest_lane(None) is None`; `score_batch` against a bound stub
    AF_UNIX server (spin one up in the test, echoing scores) returns the scores; a closed/
    missing socket -> None (fail-open); a length-mismatched reply -> None.
  * fuse: `fuse_interest(80, None)==0.8`; interest raises priority; `select_top_k` returns
    k_min when N small, respects k_frac on large N, and is deterministic.
Import only from `rqswarm_eval.perception.*` and `sidecar.scorers.interest`.

## Appendix — `swarmie.signal.v1` envelope shape (fields obs_features may read)
```
{"schema":"swarmie.signal.v1","request_id":int,
 "endpoint":{"host":str,"method":str,"path_shape":str,"ip_address":str},
 "observation":{"reasons":[str,...],
   "request":{"header_names":[str],"auth_present":bool,"content_type":str,
              "query_names":[str],"body_keys":[str],"body_sha256":str},
   "response":{"status":int,"content_type":str,"length":int,"headers":{...},
               "json_keys":[str],"body_sha256":str,"fingerprint":str},
   "baseline":{"endpoint_observations":int,"statuses":{int:count},"content_types":{str:count}}},
 "hypotheses":[{...}],"counterevidence":[...],"attention":{"score":float 0..100},
 "questions":[...],"interrogation":{"lenses":[{"persona":str,"ask":[str]}],...},
 "learned":[{"score":float,...}]  # optional; presence => sig_learned_hit=1}
```
