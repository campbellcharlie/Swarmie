#!/usr/bin/env python3
"""Reconstruct a year (or any window) of a site's JS-bundle change history.

Content-hashed immutable bundles have no per-URL history — each hash is one frozen
version. But two facts make history recoverable:

  1. The Wayback Machine densely archives the HTML *pages* (not the hashed bundles),
     and each snapshot's HTML lists the bundle URLs that were live on that date.
  2. CDNs retain old immutable artifacts indefinitely (old deploys' cached pages must
     keep working), so an old hash usually still 200s from the live host — served,
     just unreferenced.

So: mine bundle URLs out of archived HTML across time, group them by logical module
(name + webpack module-id, stripping the content hash), fetch each distinct version
LIVE from the CDN, and diff consecutive versions. The result is real code history.

STANDALONE recon utility. It makes OUTBOUND requests (Wayback + live CDN) and therefore
lives OUTSIDE the passive engine (Swarmie boundary #3: the passive pipeline never sends
HTTP). It imports nothing from rqswarm_eval. Stdlib-only.

Usage:
  python3 tools/js_history.py --page https://example.com/app/view \
      --from 20240901 --to 20251231 --host cdn.example.net --out /tmp/jshist
"""
from __future__ import annotations
import argparse, difflib, hashlib, json, os, re, sys, urllib.request, urllib.parse

UA = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"}
CDX = "https://web.archive.org/cdx/search/cdx"
# <name>-<modid>.<contenthash>.js  ->  logical id keeps name+modid, drops the content hash.
_CONTENTHASH = re.compile(r"\.[0-9a-f]{16,}\.js(\?|$)")
_SRC = re.compile(r'src=["\']([^"\']+\.js[^"\']*)["\']')
_WB_PREFIX = re.compile(r"^.*?/web/\d+[a-z_]*/")


def _get(url: str, timeout: int = 40) -> bytes | None:
    try:
        return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout).read()
    except Exception:
        return None


def snapshots(page: str, frm: str, to: str, per: str = "6") -> list[str]:
    """Timestamps of archived HTML snapshots of `page`, ~one per month (collapse=timestamp:6)."""
    q = urllib.parse.urlencode({
        "url": page, "output": "json", "from": frm, "to": to,
        "filter": "statuscode:200", "collapse": f"timestamp:{per}",
    })
    # two filters need two params; urlencode keeps only the last, so append the mimetype filter raw
    raw = _get(f"{CDX}?{q}&filter=mimetype:text/html", timeout=30)
    if not raw:
        return []
    try:
        rows = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return [r[1] for r in rows[1:]]


def bundles_in_snapshot(ts: str, page: str, host: str | None) -> set[str]:
    """Absolute .js URLs referenced by the archived HTML at `ts` (optionally host-filtered)."""
    raw = _get(f"https://web.archive.org/web/{ts}id_/{page}", timeout=40)
    if not raw:
        return set()
    html = raw.decode("utf-8", "replace")
    out = set()
    for m in _SRC.findall(html):
        u = _WB_PREFIX.sub("", m)
        if u.startswith("//"):
            u = "https:" + u
        if not u.startswith("http"):
            continue
        if host and host not in u:
            continue
        out.add(u)
    return out


def logical_id(url: str) -> str:
    """Stable module identity across deploys: filename minus the content hash."""
    name = url.split("/")[-1].split("?")[0]
    return _CONTENTHASH.sub(".js", name)


def token_lines(data: bytes) -> list[str]:
    """Break minified JS on statement boundaries so difflib sees structural changes, not one line."""
    return data.decode("utf-8", "replace").replace(",", ",\n").replace(";", ";\n").replace("{", "{\n").splitlines()


def endpoint_timeline(by_ts: dict[str, set[str]], ensure, out: str) -> None:
    """Structured surface drift: dissect every bundle at each snapshot date with Swarmie's dissect_js,
    then report which endpoints / GraphQL ops first appear or drop out over time. dissect_js is HTTP-free
    and already redacts secret-shaped tokens (ADR-0006), so its output is safe to print. Imported lazily
    so this recon tool still runs when rqswarm_eval isn't on the path (the diff features don't need it)."""
    try:
        from rqswarm_eval.perception.jsdissect import dissect_js
    except Exception as e:  # noqa: BLE001 — optional dependency for this mode only
        print(f"[!] --timeline needs rqswarm_eval on PYTHONPATH ({e})", file=sys.stderr)
        return
    surface: dict[str, set[str]] = {}
    for ts in sorted(by_ts):
        if not by_ts[ts]:
            continue  # snapshot caught a different stack / no matching bundles — skip, don't read as "all removed"
        eps: set[str] = set()
        for url in by_ts[ts]:
            path = ensure(url)
            if not path:
                continue
            d = dissect_js(open(path, encoding="utf-8", errors="replace").read(), url)
            eps |= {f"EP  {e}" for e in d.get("endpoints", [])}
            eps |= {f"GQL {o}" for o in d.get("graphql", [])}
        surface[ts] = eps
    rows, prev = [], set()
    print("\n=== endpoint-surface timeline (dissect_js) ===")
    for i, ts in enumerate(sorted(surface)):
        cur = surface[ts]
        added, removed = sorted(cur - prev), (sorted(prev - cur) if i else [])
        rows.append({"ts": ts, "surface_size": len(cur), "added": added, "removed": removed})
        print(f"  {ts}  surface={len(cur):>3}  " + ("baseline" if not i else f"+{len(added)} / -{len(removed)}"))
        for a in added[:12]:
            print(f"      + {a}")
        for r in removed[:12]:
            print(f"      - {r}")
        prev = cur
    with open(os.path.join(out, "timeline.json"), "w") as f:
        json.dump(rows, f, indent=2)
    print(f"[*] timeline.json written to {out}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--page", required=True, help="stable HTML page URL whose bundle refs to mine")
    ap.add_argument("--from", dest="frm", default="20240101")
    ap.add_argument("--to", default="20251231")
    ap.add_argument("--host", default=None, help="only track bundles whose URL contains this host/substring")
    ap.add_argument("--out", default="/tmp/jshist", help="dir for fetched versions + diffs + report.json")
    ap.add_argument("--max-diff-bytes", type=int, default=800_000, help="skip diffing versions larger than this")
    ap.add_argument("--timeline", action="store_true",
                    help="also emit a dissect_js endpoint/GraphQL-op surface timeline (needs rqswarm_eval on PYTHONPATH)")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    cache = os.path.join(args.out, "versions"); os.makedirs(cache, exist_ok=True)

    tss = snapshots(args.page, args.frm, args.to)
    print(f"[*] {len(tss)} monthly snapshots of {args.page}", file=sys.stderr)
    if not tss:
        print("[!] no archived snapshots — is the page in Wayback?", file=sys.stderr)
        return 1

    # logical_id -> ordered [(first_seen_ts, url)] de-duplicated by url; ts -> set(urls) for the timeline
    history: dict[str, list[tuple[str, str]]] = {}
    by_ts: dict[str, set[str]] = {}
    for ts in tss:
        urls = sorted(bundles_in_snapshot(ts, args.page, args.host))
        by_ts[ts] = set(urls)
        for u in urls:
            seq = history.setdefault(logical_id(u), [])
            if not any(url == u for _, url in seq):
                seq.append((ts, u))
        print(f"    {ts}: bundles={len(urls)}  cumulative logical chunks={len(history)}", file=sys.stderr)

    _cache: dict[str, str | None] = {}
    def ensure(url: str) -> str | None:
        """Fetch a bundle version once into the content-addressed cache; return its path or None (dead hash)."""
        if url in _cache:
            return _cache[url]
        path = os.path.join(cache, hashlib.sha256(url.encode()).hexdigest()[:16] + ".js")
        if not os.path.exists(path):
            data = _get(url, timeout=25)
            if data is None:
                _cache[url] = None; return None
            with open(path, "wb") as f:
                f.write(data)
        _cache[url] = path
        return path

    changed = {k: v for k, v in history.items() if len(v) > 1}
    print(f"[*] {len(history)} logical chunks; {len(changed)} changed >=1x in window", file=sys.stderr)

    report = []
    for lid, seq in sorted(changed.items()):
        versions = []
        for ts, url in seq:
            path = ensure(url)
            if path is None:
                versions.append({"ts": ts, "url": url, "live": False}); continue
            versions.append({"ts": ts, "url": url, "live": True,
                             "bytes": os.path.getsize(path), "path": path})
        # diff consecutive live versions
        diffs = []
        live = [v for v in versions if v.get("live")]
        for a, b in zip(live, live[1:]):
            da, db = open(a["path"], "rb").read(), open(b["path"], "rb").read()
            if da == db:
                diffs.append({"from": a["ts"], "to": b["ts"], "identical": True}); continue
            entry = {"from": a["ts"], "to": b["ts"], "identical": False,
                     "delta_bytes": b["bytes"] - a["bytes"]}
            if max(len(da), len(db)) <= args.max_diff_bytes:
                ud = list(difflib.unified_diff(token_lines(da), token_lines(db),
                                               a["url"].split("/")[-1], b["url"].split("/")[-1], lineterm=""))
                entry["added"] = sum(1 for l in ud if l.startswith("+") and not l.startswith("+++"))
                entry["removed"] = sum(1 for l in ud if l.startswith("-") and not l.startswith("---"))
                dp = os.path.join(args.out, f"{lid}__{a['ts']}_{b['ts']}.diff")
                with open(dp, "w") as f:
                    f.write("\n".join(ud))
                entry["diff"] = dp
            diffs.append(entry)
        report.append({"chunk": lid, "versions": versions, "diffs": diffs,
                       "n_live": len(live), "n_missing": len(versions) - len(live)})

    with open(os.path.join(args.out, "report.json"), "w") as f:
        json.dump(report, f, indent=2)

    # console summary
    print(f"\n{'chunk':42} versions  live  changes  bytes(first->last)")
    for r in sorted(report, key=lambda r: -r["n_live"]):
        real = [d for d in r["diffs"] if not d.get("identical")]
        lv = [v for v in r["versions"] if v.get("live")]
        span = f"{lv[0]['bytes']}->{lv[-1]['bytes']}" if lv else "-"
        print(f"  {r['chunk']:40} {len(r['versions']):>7}  {r['n_live']:>4}  {len(real):>7}  {span}")
    print(f"\n[*] report + per-chunk .diff files in {args.out}")

    if args.timeline:
        endpoint_timeline(by_ts, ensure, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
