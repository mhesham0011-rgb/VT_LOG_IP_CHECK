# Write a ready-to-run Python script.
#!/usr/bin/env python3
"""
vt_log_ip_check.py

Collect IP addresses from log files and check them against VirusTotal (v3 API).

Usage:
  python vt_log_ip_check.py --input /path/to/log/or/dir --output results.csv

Requirements:
  - Python 3.8+
  - pip install requests python-dateutil
  - Set your VirusTotal API key in environment variable: VT_API_KEY=...
    (Create one at https://www.virustotal.com/ )

Notes:
  - Free VT API has strict rate limits. Use --rate to space requests.
  - Results are cached locally (cache_ip.json) to avoid re-querying the same IP.
"""

import argparse
import concurrent.futures
import csv
import ipaddress
import json
import os
import re
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Set, Tuple

import requests
from dateutil import tz

VT_API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

# Regex for IPv4. Avoids leading zeros issue but keeps it pragmatic.
IPV4_REGEX = re.compile(
    r'(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)'
)

# Default cache file name
CACHE_FILE = "cache_ip.json"


@dataclass
class VTResult:
    ip: str
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    reputation: Optional[int] = None
    last_analysis_date: Optional[str] = None  # ISO 8601
    link: Optional[str] = None
    verdict: str = "unknown"  # malicious / suspicious / clean / unknown
    error: Optional[str] = None


def load_cache(cache_path: str) -> Dict[str, dict]:
    if os.path.exists(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_cache(cache_path: str, data: Dict[str, dict]) -> None:
    try:
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[WARN] Failed to write cache: {e}", file=sys.stderr)


def is_private_or_reserved(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_reserved or ip.is_link_local
    except Exception:
        return True


def find_ips_in_text(text: str) -> Set[str]:
    ips = set(IPV4_REGEX.findall(text))
    return ips


def iter_files(path: str) -> Iterable[str]:
    if os.path.isfile(path):
        yield path
    else:
        for root, _, files in os.walk(path):
            for name in files:
                full = os.path.join(root, name)
                # Skip binary-ish files by simple heuristic
                try:
                    if os.path.getsize(full) > 50 * 1024 * 1024:  # 50MB guard
                        continue
                except Exception:
                    pass
                yield full


def collect_ips_from_path(path: str, verbose: bool = True) -> Set[str]:
    all_ips: Set[str] = set()
    for fp in iter_files(path):
        try:
            with open(fp, "r", errors="ignore", encoding="utf-8") as f:
                content = f.read()
            ips = find_ips_in_text(content)
            if verbose and ips:
                print(f"[INFO] {fp}: found {len(ips)} IPs")
            all_ips.update(ips)
        except Exception as e:
            print(f"[WARN] Could not read {fp}: {e}", file=sys.stderr)
    return all_ips


def vt_fetch_ip(ip: str, api_key: str, session: requests.Session) -> VTResult:
    headers = {"x-apikey": api_key}
    url = VT_API_URL.format(ip=ip)
    try:
        r = session.get(url, headers=headers, timeout=30)
        if r.status_code == 404:
            return VTResult(ip=ip, verdict="unknown", error="Not found in VT")
        if r.status_code == 401 or r.status_code == 403:
            return VTResult(ip=ip, verdict="unknown", error=f"Auth error {r.status_code}: check API key/plan")
        if r.status_code == 429:
            return VTResult(ip=ip, verdict="unknown", error="Rate limited (HTTP 429)")
        r.raise_for_status()
        data = r.json()
        attr = data.get("data", {}).get("attributes", {})

        stats = attr.get("last_analysis_stats", {}) or {}
        rep = attr.get("reputation")
        # Last analysis date to ISO
        lad = attr.get("last_analysis_date")
        lad_iso = None
        if lad:
            lad_iso = datetime.fromtimestamp(lad, tz=timezone.utc).isoformat()

        link = f"https://www.virustotal.com/gui/ip-address/{ip}"

        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))

        # Simple verdict policy:
        # - malicious >= 1 => malicious
        # - else suspicious >= 1 or reputation < 0 => suspicious
        # - else harmless > 0 and malicious == 0 and suspicious == 0 => clean
        # - else unknown
        verdict = "unknown"
        if malicious >= 1:
            verdict = "malicious"
        elif suspicious >= 1 or (isinstance(rep, int) and rep < 0):
            verdict = "suspicious"
        elif harmless > 0 and malicious == 0 and suspicious == 0:
            verdict = "clean"

        return VTResult(
            ip=ip,
            malicious=malicious,
            suspicious=suspicious,
            harmless=harmless,
            undetected=undetected,
            reputation=rep if isinstance(rep, int) else None,
            last_analysis_date=lad_iso,
            link=link,
            verdict=verdict,
        )
    except requests.exceptions.RequestException as e:
        return VTResult(ip=ip, verdict="unknown", error=f"Request error: {e}")


def write_csv(results: List[VTResult], output_path: str) -> None:
    fieldnames = [
        "ip",
        "verdict",
        "malicious",
        "suspicious",
        "harmless",
        "undetected",
        "reputation",
        "last_analysis_date",
        "link",
        "error",
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(asdict(r))


def write_json(results: List[VTResult], output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in results], f, indent=2, ensure_ascii=False)


def main():
    parser = argparse.ArgumentParser(description="Collect IPs from logs and check them with VirusTotal (v3).")
    parser.add_argument("--input", "-i", required=True, help="Path to a log file or a directory containing logs.")
    parser.add_argument("--output", "-o", default="vt_results.csv", help="Output file path (.csv or .json).")
    parser.add_argument("--cache", default=CACHE_FILE, help="Path to cache file (JSON).")
    parser.add_argument("--skip-private", action="store_true", help="Skip private/reserved IPs (RFC1918, loopback, etc.)")
    parser.add_argument("--rate", type=float, default=16.0, help="Seconds to sleep between API calls (free tier ~4/min).")
    parser.add_argument("--max", type=int, default=0, help="Optional limit on number of IPs to check (0 = no limit).")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging.")
    args = parser.parse_args()

    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        print("ERROR: Please set VT_API_KEY environment variable with your VirusTotal API key.", file=sys.stderr)
        sys.exit(2)

    # Collect IPs
    all_ips = collect_ips_from_path(args.input, verbose=args.verbose)
    if args.skip_private:
        all_ips = {ip for ip in all_ips if not is_private_or_reserved(ip)}

    # De-duplicate
    ips_sorted = sorted(all_ips, key=lambda x: tuple(int(p) for p in x.split(".")))

    if args.max and args.max > 0:
        ips_sorted = ips_sorted[:args.max]

    if not ips_sorted:
        print("[INFO] No IPs found. Nothing to do.")
        return

    # Load cache
    cache = load_cache(args.cache)

    session = requests.Session()
    results: List[VTResult] = []

    for idx, ip in enumerate(ips_sorted, start=1):
        if ip in cache:
            if args.verbose:
                print(f"[CACHE] {ip}")
            cached = cache[ip]
            results.append(VTResult(**cached))
            continue

        if args.verbose:
            print(f"[{idx}/{len(ips_sorted)}] Querying VT for {ip} ...")

        res = vt_fetch_ip(ip, api_key, session)
        results.append(res)
        # Save to cache immediately
        cache[ip] = asdict(res)
        save_cache(args.cache, cache)

        if idx < len(ips_sorted):
            time.sleep(max(args.rate, 0.0))

    # Write output
    out = args.output
    _, ext = os.path.splitext(out)
    if ext.lower() == ".json":
        write_json(results, out)
    else:
        write_csv(results, out)

    # Print a small summary
    counts = {"malicious": 0, "suspicious": 0, "clean": 0, "unknown": 0}
    for r in results:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1

    print("[SUMMARY] Verdict counts:")
    for k in ["malicious", "suspicious", "clean", "unknown"]:
        print(f"  {k}: {counts.get(k, 0)}")

    print(f"[DONE] Wrote results to: {out}")
    print(f"[DONE] Cache stored at: {args.cache}")


if __name__ == "__main__":
    main()
