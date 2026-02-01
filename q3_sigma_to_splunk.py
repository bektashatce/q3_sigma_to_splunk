from __future__ import annotations

import os
import re
import json
import glob
import time
import argparse
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

import requests
import yaml


def ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def die(msg: str) -> None:
    raise SystemExit(f"[{ts()}] ERROR: {msg}")


def spl_quote(v: str) -> str:
    v = v.replace("\\", "\\\\").replace('"', '\\"')
    return f"\"{v}\""


def load_yaml(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def sanitize_filename(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_\-]+", "_", s)[:120] or "rule"


def wrap_contains(value: str) -> str:
    if "*" in value:
        return value
    return f"*{value}*"


def load_rule_files(rule_file: str, rules_dir: str) -> List[str]:
    paths: List[str] = []

    if rule_file and os.path.exists(rule_file):
        paths.append(rule_file)

    if rules_dir and os.path.isdir(rules_dir):
        paths.extend(sorted(glob.glob(os.path.join(rules_dir, "*.yml"))))
        paths.extend(sorted(glob.glob(os.path.join(rules_dir, "*.yaml"))))

    out: List[str] = []
    seen = set()
    for p in paths:
        ap = os.path.abspath(p)
        if ap not in seen:
            seen.add(ap)
            out.append(p)
    return out


def normalize_logsource(rule: Dict[str, Any]) -> Dict[str, str]:
    logsource = rule.get("logsource", {}) or {}
    product = (logsource.get("product") or "").lower()
    service = (logsource.get("service") or "").lower()
    category = (logsource.get("category") or "").lower()

    out = {"index": "main", "sourcetype": ""}

    if product == "windows" and service in ("powershell", "powershell/operational"):
        out["sourcetype"] = "XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"
        return out

    if product == "windows" and service == "sysmon":
        out["sourcetype"] = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
        return out

    if product == "windows" and (service == "security" or category == "authentication"):
        out["sourcetype"] = "XmlWinEventLog:Security"
        return out

    return out


RegexFilter = Tuple[str, str]


def build_field_expr(field: str, value: Any) -> Tuple[str, List[RegexFilter]]:
    regex_filters: List[RegexFilter] = []

    if isinstance(value, list):
        parts: List[str] = []
        for v in value:
            expr, rf = build_field_expr(field, v)
            if expr:
                parts.append(expr)
            regex_filters.extend(rf)
        if not parts:
            return "", regex_filters
        return "(" + " OR ".join(parts) + ")", regex_filters

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f"{field}={value}", regex_filters

    s = str(value)

    if field == "_raw":
        return f"_raw={spl_quote(wrap_contains(s))}", regex_filters

    if field.lower() in ("eventid", "eventcode") and s.isdigit():
        xml_pat = f"*<EventID>{s}</EventID>*"
        return f"(EventCode={s} OR EventID={s} OR _raw={spl_quote(xml_pat)})", regex_filters

    return f"{field}={spl_quote(s)}", regex_filters


def convert_selection(selection: Dict[str, Any]) -> Tuple[str, List[RegexFilter]]:
    clauses: List[str] = []
    regex_filters: List[RegexFilter] = []

    for raw_key, raw_val in selection.items():
        if "|" in raw_key:
            field, mod = raw_key.split("|", 1)
            field = field.strip()
            mod = mod.strip().lower()

            if field == "ScriptBlockText" and mod == "contains":
                vals = raw_val if isinstance(raw_val, list) else [raw_val]
                parts = []
                for v in vals:
                    v = str(v)
                    parts.append(
                        f"(ps_script={spl_quote(wrap_contains(v))} OR _raw={spl_quote(wrap_contains(v))})"
                    )
                clauses.append("(" + " OR ".join(parts) + ")")
                continue

            if mod == "contains":
                vals = raw_val if isinstance(raw_val, list) else [raw_val]
                parts = [f'{field}={spl_quote(wrap_contains(str(v)))}' for v in vals]
                clauses.append("(" + " OR ".join(parts) + ")")
                continue

            if mod == "startswith":
                clauses.append(f'{field}={spl_quote(str(raw_val) + "*")}')
                continue

            if mod == "endswith":
                clauses.append(f'{field}={spl_quote("*" + str(raw_val))}')
                continue

            if mod == "regex":
                regex_filters.append((field, str(raw_val)))
                clauses.append(f'{field}={spl_quote("*")}')
                continue

            expr, rf = build_field_expr(field, raw_val)
            if expr:
                clauses.append(expr)
            regex_filters.extend(rf)
            continue

        expr, rf = build_field_expr(raw_key, raw_val)
        if expr:
            clauses.append(expr)
        regex_filters.extend(rf)

    if not clauses:
        return "", regex_filters

    return "(" + " AND ".join(clauses) + ")", regex_filters


def sigma_condition_to_spl(condition: str, selections_spl: Dict[str, str]) -> str:
    tokens = re.findall(r"\w+|\(|\)|and|or|not", condition, flags=re.IGNORECASE)
    out: List[str] = []

    for t in tokens:
        tl = t.lower()
        if tl in ("and", "or", "not"):
            out.append(tl.upper())
        elif t in ("(", ")"):
            out.append(t)
        else:
            if t not in selections_spl:
                die(f"Condition references unknown selection: {t}")
            out.append(selections_spl[t])

    return " ".join(out)


def sigma_to_search_expr(rule: Dict[str, Any]) -> Tuple[str, List[RegexFilter]]:
    detection = rule.get("detection") or {}
    condition = detection.get("condition")
    if not condition:
        die("Sigma rule missing detection.condition")

    selections_spl: Dict[str, str] = {}
    regex_filters: List[RegexFilter] = []

    for key, val in detection.items():
        if key == "condition":
            continue

        if not isinstance(val, dict):
            selections_spl[key] = f'_raw={spl_quote(wrap_contains(str(val)))}'
            continue

        sel_spl, rf = convert_selection(val)
        if not sel_spl:
            die(f"Empty selection produced for: {key}")
        selections_spl[key] = sel_spl
        regex_filters.extend(rf)

    base_expr = sigma_condition_to_spl(condition, selections_spl)
    return base_expr, regex_filters


def build_full_spl(rule: Dict[str, Any]) -> str:
    ls = normalize_logsource(rule)
    prefix = f'index={ls["index"]}'
    if ls.get("sourcetype"):
        prefix += f' sourcetype={spl_quote(ls["sourcetype"])}'

    base_expr, regex_filters = sigma_to_search_expr(rule)

    spl_parts: List[str] = [prefix]
    st = (ls.get("sourcetype") or "").lower()

    if "powershell/operational" in st:
        spl_parts.append(
            r"""| rex field=_raw max_match=1 "<Data Name=[\"']ScriptBlockText[\"']>(?<ps_script>[\s\S]*?)</Data>" """.strip()
        )

    if "sysmon/operational" in st:
        spl_parts.append(r"""| rex field=_raw "<Data Name=[\"']Image[\"']>(?<Image>[^<]+)</Data>" """.strip())
        spl_parts.append(r"""| rex field=_raw "<Data Name=[\"']CommandLine[\"']>(?<CommandLine>[^<]+)</Data>" """.strip())
        spl_parts.append(r"""| rex field=_raw "<Data Name=[\"']ParentImage[\"']>(?<ParentImage>[^<]+)</Data>" """.strip())
        spl_parts.append(r"""| rex field=_raw "<Data Name=[\"']ParentCommandLine[\"']>(?<ParentCommandLine>[^<]+)</Data>" """.strip())
        spl_parts.append(r"""| rex field=_raw "<Data Name=[\"']User[\"']>(?<User>[^<]+)</Data>" """.strip())
        spl_parts.append(r"""| rex field=_raw "<Data Name=[\"']TargetFilename[\"']>(?<TargetFilename>[^<]+)</Data>" """.strip())

    spl_parts.append(f"| search {base_expr}")

    for field, pattern in regex_filters:
        spl_parts.append(f"| regex {field}={spl_quote(pattern)}")

    if "powershell/operational" in st:
        spl_parts.append("| table _time host ps_script _raw")
        spl_parts.append("| sort - _time")
    elif "sysmon/operational" in st:
        spl_parts.append("| table _time host User Image CommandLine ParentImage ParentCommandLine TargetFilename _raw")
        spl_parts.append("| sort - _time")
    else:
        spl_parts.append("| table _time host _raw")
        spl_parts.append("| sort - _time")

    return " ".join(spl_parts)


class SplunkClient:
    def __init__(self, base_url: str, username: str, password: str, verify_ssl: bool):
        self.base_url = base_url.rstrip("/")
        self.auth = (username, password)
        self.verify_ssl = verify_ssl
        self.s = requests.Session()

        if not verify_ssl:
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass

    def server_info(self) -> Dict[str, Any]:
        r = self.s.get(
            f"{self.base_url}/services/server/info",
            params={"output_mode": "json"},
            auth=self.auth,
            verify=self.verify_ssl,
            timeout=30,
        )
        if r.status_code >= 300:
            die(f"Cannot reach Splunk server info ({r.status_code}): {r.text[:300]}")
        return r.json()

    def export_oneshot(self, spl: str, earliest: str, latest: str) -> List[Dict[str, Any]]:
        r = self.s.post(
            f"{self.base_url}/services/search/jobs/export",
            data={
                "search": f"search {spl}",
                "earliest_time": earliest,
                "latest_time": latest,
                "output_mode": "json",
            },
            auth=self.auth,
            verify=self.verify_ssl,
            timeout=240,
        )
        if r.status_code >= 300:
            die(f"Search export failed ({r.status_code}): {r.text[:400]}")

        results: List[Dict[str, Any]] = []
        for line in r.text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if "result" in obj:
                    results.append(obj["result"])
            except Exception:
                continue
        return results


def print_top_table(results: List[Dict[str, Any]], top_n: int = 3) -> None:
    top = results[:top_n]
    if not top:
        return

    preferred = [
        "_time",
        "host",
        "User",
        "Image",
        "CommandLine",
        "ParentImage",
        "ParentCommandLine",
        "TargetFilename",
        "ps_script",
    ]
    cols = [c for c in preferred if any(c in r for r in top)]
    if not cols:
        cols = list(top[0].keys())[:8]

    widths = {c: max(len(c), max(len(str(r.get(c, ""))) for r in top)) for c in cols}
    header = "  ".join(c.ljust(widths[c]) for c in cols)
    print(header)
    print("-" * len(header))
    for r in top:
        row = "  ".join(str(r.get(c, "")).ljust(widths[c]) for c in cols)
        print(row)


def export_json_results(results: List[Dict[str, Any]], outdir: str, rule_id: str, run_tag: str) -> str:
    os.makedirs(outdir, exist_ok=True)
    safe_id = sanitize_filename(rule_id)
    path = os.path.join(outdir, f"{safe_id}_{run_tag}_matches.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    return path


def run_once(
    client: SplunkClient,
    rule_paths: List[str],
    outdir: str,
    earliest: str,
    latest: str,
    top_n: int,
) -> int:
    total_matches = 0
    run_tag = datetime.now().strftime("%Y%m%d_%H%M%S")

    for rp in rule_paths:
        rule = load_yaml(rp)
        title = rule.get("title", os.path.basename(rp))
        rid = str(rule.get("id", os.path.basename(rp)))

        print("\n" + "=" * 78)
        print(f"[{ts()}] Rule: {title} (id: {rid}) [{rp}]")

        spl = build_full_spl(rule)
        print(f"[{ts()}] Generated SPL:\n{spl}")
        print(f"[{ts()}] Running search window: earliest={earliest} latest={latest}")

        results = client.export_oneshot(spl, earliest, latest)

        if results:
            total_matches += len(results)
            print(f"[{ts()}] {len(results)} match(es) found. Showing top {top_n}:")
            print_top_table(results, top_n=top_n)
            out_path = export_json_results(results, outdir, rid, run_tag)
            print(f"[{ts()}] Exported results to: {out_path}")
        else:
            print(f"[{ts()}] No matches found for this rule. (completion message)")

    print("\n" + "=" * 78)
    print(f"[{ts()}] Completed run_tag={run_tag}. Total matches across all rules: {total_matches}")
    return total_matches


def main() -> None:
    ap = argparse.ArgumentParser(description="Q3 Sigma to Splunk automation (oneshot and scheduled rolling window)")
    ap.add_argument("--rule-file", default="", help="Single sigma rule file (optional)")
    ap.add_argument("--rules-dir", default="rules", help="Folder containing sigma rules")
    ap.add_argument("--outdir", default="out", help="Output folder for JSON match exports")

    ap.add_argument("--mode", choices=["oneshot", "scheduled"], default="oneshot")
    ap.add_argument("--interval-seconds", type=int, default=300)
    ap.add_argument("--max-runs", type=int, default=0)
    ap.add_argument("--lookback-days", type=int, default=10, help="Rolling window in days for scheduled mode")
    ap.add_argument("--top-n", type=int, default=3)
    args = ap.parse_args()

    base_url = os.getenv("SPLUNK_BASE_URL", "https://127.0.0.1:8089").rstrip("/")
    username = os.getenv("SPLUNK_USERNAME", "")
    password = os.getenv("SPLUNK_PASSWORD", "")
    verify_ssl = os.getenv("SPLUNK_VERIFY_SSL", "true").lower() == "true"

    default_earliest = os.getenv("SPLUNK_EARLIEST", "-24h")
    default_latest = os.getenv("SPLUNK_LATEST", "now")

    if not username or not password:
        die("Set SPLUNK_USERNAME and SPLUNK_PASSWORD environment variables.")

    rule_paths = load_rule_files(args.rule_file, args.rules_dir)
    if not rule_paths:
        die(f"No rule files found. Check --rule-file or --rules-dir ({args.rules_dir}).")

    print(f"[{ts()}] Connected config: base_url={base_url} verify_ssl={verify_ssl}")
    print(f"[{ts()}] Mode={args.mode} rules_count={len(rule_paths)} outdir={args.outdir}")

    client = SplunkClient(base_url, username, password, verify_ssl)
    info = client.server_info()
    server_name = info.get("entry", [{}])[0].get("name", "unknown")
    print(f"[{ts()}] Connected to Splunk OK: {server_name}")

    if args.mode == "oneshot":
        print(f"[{ts()}] Oneshot window: earliest={default_earliest} latest={default_latest}")
        run_once(client, rule_paths, args.outdir, default_earliest, default_latest, args.top_n)
        return

    lookback_days = max(1, int(args.lookback_days))
    earliest_rel = f"-{lookback_days}d"
    latest_rel = "now"

    max_runs_label = str(args.max_runs) if args.max_runs else "forever"
    print(f"[{ts()}] Scheduled interval={args.interval_seconds}s max_runs={max_runs_label}")
    print(f"[{ts()}] Rolling window: earliest={earliest_rel} latest={latest_rel}")

    run_count = 0
    try:
        while True:
            run_count += 1
            print("\n" + "=" * 78)
            print(f"[{ts()}] Scheduled cycle {run_count} started (utc={utc_iso()})")

            run_once(client, rule_paths, args.outdir, earliest_rel, latest_rel, args.top_n)

            if args.max_runs and run_count >= args.max_runs:
                print(f"[{ts()}] Reached max_runs={args.max_runs}. Exiting scheduled mode.")
                break

            print(f"[{ts()}] Sleeping {args.interval_seconds}s before next scheduled cycle...")
            time.sleep(max(1, args.interval_seconds))

    except KeyboardInterrupt:
        print(f"\n[{ts()}] Interrupted by user. Exiting.")


if __name__ == "__main__":
    main()
