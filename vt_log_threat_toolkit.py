#!/usr/bin/env python3
"""
vt_log_threat_toolkit.py

General Log Threat-Analysis Toolkit
- Extract IOCs: IPs, Domains, Hashes (MD5/SHA1/SHA256), URLs
- Query VirusTotal v3 (unified Provider abstraction)
- Local JSON cache (provider:kind:value)
- GUI: scope toggles, Requests/min rate, auto-tune, unified results table, CSV/JSON export

Requirements:
  pip install requests python-dateutil
Env:
  VT_API_KEY=your_key_here   # or paste in GUI and tick "Save key to local config"
"""

import argparse
import base64
import csv
import ipaddress
import json
import os
import queue
import re
import sys
import threading
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Set, Any, Tuple

import requests
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import pathlib
from concurrent.futures import ThreadPoolExecutor, as_completed

# -----------------------------
# Config
# -----------------------------

CONFIG_PATH = os.path.expanduser("~/.vt_gui_config.json")
DEFAULT_CACHE_FILE = "cache_ioc.json"

def load_config() -> dict:
    try:
        p = pathlib.Path(CONFIG_PATH)
        if p.exists():
            return json.loads(p.read_text(encoding="utf8"))
    except Exception:
        pass
    return {}

def save_config(cfg: dict) -> None:
    try:
        pathlib.Path(CONFIG_PATH).write_text(json.dumps(cfg, indent=2), encoding="utf8")
    except Exception:
        pass

# -----------------------------
# VT endpoints & regex
# -----------------------------

VT_API_URLS = {
    "ip":     "https://www.virustotal.com/api/v3/ip_addresses/{value}",
    "domain": "https://www.virustotal.com/api/v3/domains/{value}",
    "hash":   "https://www.virustotal.com/api/v3/files/{value}",
    "url":    "https://www.virustotal.com/api/v3/urls/{value}",  # expects base64url(id) of raw URL
}

# IPv4 (pragmatic)
IPV4_REGEX = re.compile(r'(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)')

# Precompiled detectors (speed)
DOMAIN_RX  = re.compile(r"\b(?!(?:\d{1,3}\.){3}\d{1,3}\b)(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
URL_RX     = re.compile(r"https?://[^\s\"'>)]+", re.I)
MD5_RX     = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RX    = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RX  = re.compile(r"\b[a-fA-F0-9]{64}\b")

# VT key sanity check (VT keys are typically ~64 alphanum chars)
API_KEY_RX = re.compile(r"^[A-Za-z0-9]{32,128}$")

def _sanitize_validate_api_key(raw: str) -> str:
    """Return a single-line, whitespace-free key or raise ValueError."""
    if not raw:
        return ""
    s = raw.strip()
    # If multi-line, keep only the first non-empty line
    if "\n" in s or "\r" in s:
        for ln in s.splitlines():
            ln = ln.strip()
            if ln:
                s = ln
                break
        else:
            s = ""
    # Remove internal whitespace just in case
    s = re.sub(r"\s+", "", s)
    # Sanity check
    if not API_KEY_RX.fullmatch(s):
        raise ValueError("The VirusTotal API key appears invalid. Ensure it's a single line of letters/numbers (32–128 chars).")
    return s

# -----------------------------
# Data model
# -----------------------------

@dataclass
class IOCResult:
    kind: str                  # "ip" | "domain" | "hash" | "url"
    value: str
    verdict: str = "unknown"   # malicious/suspicious/clean/unknown
    source: str = "VirusTotal"
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    reputation: Optional[int] = None
    last_analysis_date: Optional[str] = None  # ISO 8601
    link: Optional[str] = None
    error: Optional[str] = None
    enrich: Optional[Dict[str, Any]] = None

# -----------------------------
# Cache I/O (atomic writes)
# -----------------------------

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
        tmp = cache_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, cache_path)   # atomic on same FS
    except Exception as e:
        print(f"[WARN] Failed to write cache: {e}", file=sys.stderr)

# -----------------------------
# IOC helpers
# -----------------------------

def is_private_or_reserved(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_reserved or ip.is_link_local
        )
    except Exception:
        return True

def iter_files(path: str) -> Iterable[str]:
    if os.path.isfile(path):
        yield path
    else:
        for root, _, files in os.walk(path):
            for name in files:
                full = os.path.join(root, name)
                try:
                    if os.path.getsize(full) > 50 * 1024 * 1024:  # skip >50MB
                        continue
                except Exception:
                    pass
                yield full

def collect_iocs_from_path(path: str, verbose_cb=None) -> Dict[str, Set[str]]:
    """Stream files line-by-line; return sets per kind."""
    kinds: Dict[str, Set[str]] = {"ip": set(), "domain": set(), "url": set(), "hash": set()}
    for fp in iter_files(path):
        try:
            ips=set(); doms=set(); urls=set(); hashes=set()
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    ips.update(IPV4_REGEX.findall(line))
                    doms.update(DOMAIN_RX.findall(line))
                    urls.update(URL_RX.findall(line))
                    m = MD5_RX.search(line);    hashes.add(m.group(0)) if m else None
                    m = SHA1_RX.search(line);   hashes.add(m.group(0)) if m else None
                    m = SHA256_RX.search(line); hashes.add(m.group(0)) if m else None
            if verbose_cb:
                total = len(ips)+len(doms)+len(urls)+len(hashes)
                if total:
                    verbose_cb(f"[INFO] {fp}: {total} IOCs (IP:{len(ips)} Dom:{len(doms)} URL:{len(urls)} Hash:{len(hashes)})")
            kinds["ip"].update(ips); kinds["domain"].update(doms)
            kinds["url"].update(urls); kinds["hash"].update(hashes)
        except Exception as e:
            if verbose_cb:
                verbose_cb(f"[WARN] Could not read {fp}: {e}")
    return kinds

# -----------------------------
# Provider
# -----------------------------

class Provider:
    name = "Base"
    def lookup(self, kind: str, value: str) -> IOCResult:
        raise NotImplementedError

class VirusTotalProvider(Provider):
    name = "VirusTotal"

    def __init__(self, api_key: str, session: requests.Session):
        self.api_key = api_key
        self.session = session
        self.headers = {"x-apikey": api_key.strip()}  # defensive strip

    @staticmethod
    def _compute_verdict(malicious: int, suspicious: int, harmless: int, reputation: Optional[int]) -> str:
        if malicious >= 1:
            return "malicious"
        if suspicious >= 1 or (isinstance(reputation, int) and reputation < 0):
            return "suspicious"
        if harmless > 0 and not malicious and not suspicious:
            return "clean"
        return "unknown"

    def _parse_common(self, kind: str, value: str, data: dict) -> IOCResult:
        attr = (data or {}).get("data", {}).get("attributes", {}) or {}
        stats = attr.get("last_analysis_stats", {}) or {}
        rep = attr.get("reputation")
        lad = attr.get("last_analysis_date")
        lad_iso = datetime.fromtimestamp(lad, tz=timezone.utc).isoformat() if lad else None

        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))

        verdict = self._compute_verdict(malicious, suspicious, harmless, rep if isinstance(rep, int) else None)

        link = {
            "ip":     f"https://www.virustotal.com/gui/ip-address/{value}",
            "domain": f"https://www.virustotal.com/gui/domain/{value}",
            "hash":   f"https://www.virustotal.com/gui/file/{value}",
            "url":    f"https://www.virustotal.com/gui/url/{(data or {}).get('data', {}).get('id', '')}",
        }.get(kind, None)

        return IOCResult(
            kind=kind, value=value, verdict=verdict, source=self.name,
            malicious=malicious, suspicious=suspicious, harmless=harmless, undetected=undetected,
            reputation=rep if isinstance(rep, int) else None,
            last_analysis_date=lad_iso, link=link
        )

    @staticmethod
    def _vt_url_id_from_raw(url: str) -> str:
        b = url.encode("utf-8")
        b64 = base64.urlsafe_b64encode(b).decode("ascii")
        return b64.strip("=")

    def lookup(self, kind: str, value: str) -> IOCResult:
        try:
            if kind == "url":
                url_id = self._vt_url_id_from_raw(value)
                url = VT_API_URLS[kind].format(value=url_id)
            else:
                url = VT_API_URLS[kind].format(value=value)
        except KeyError:
            return IOCResult(kind=kind, value=value, verdict="unknown", source=self.name, error="Unsupported kind")

        try:
            r = self.session.get(url, headers=self.headers, timeout=30)
            if r.status_code == 404:
                return IOCResult(kind=kind, value=value, verdict="unknown", source=self.name, error="Not found in VT")
            if r.status_code in (401, 403):
                return IOCResult(kind=kind, value=value, verdict="unknown", source=self.name, error=f"Auth error {r.status_code}")
            if r.status_code == 429:
                return IOCResult(kind=kind, value=value, verdict="unknown", source=self.name, error="Rate limited (HTTP 429)")
            r.raise_for_status()
            data = r.json()
            return self._parse_common(kind, value, data)
        except requests.exceptions.RequestException as e:
            return IOCResult(kind=kind, value=value, verdict="unknown", source=self.name, error=f"Request error: {e}")

# -----------------------------
# Writers
# -----------------------------

def write_csv(results: List[IOCResult], output_path: str) -> None:
    fieldnames = [
        "kind","value","verdict","malicious","suspicious","harmless","undetected",
        "reputation","last_analysis_date","link","source","error",
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            d = asdict(r)
            d.pop("enrich", None)
            writer.writerow(d)

def write_json(results: List[IOCResult], output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in results], f, indent=2, ensure_ascii=False)

# -----------------------------
# Rate limiting
# -----------------------------

class RateLimiter:
    """Token-bucket-ish limiter with optional adaptive backoff."""
    def __init__(self, interval_sec: float = 16.0, auto_tune: bool = False,
                 min_interval: float = 0.1, max_interval: float = 60.0):
        self.interval = max(0.0, float(interval_sec))
        self.min_interval = float(min_interval)
        self.max_interval = float(max_interval)
        self.auto_tune = bool(auto_tune)
        self._lock = threading.Lock()
        self._next_ok = time.monotonic()
        self._success_counter = 0

    def wait(self):
        if self.interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            wait_for = self._next_ok - now
            if wait_for > 0:
                time.sleep(wait_for)
            self._next_ok = max(now, self._next_ok) + self.interval

    def observe_rate_limit(self):
        if not self.auto_tune:
            return
        with self._lock:
            self.interval = min(self.max_interval, self.interval * 1.25 if self.interval > 0 else 1.0)
            self._success_counter = 0

    def observe_success(self):
        if not self.auto_tune:
            return
        with self._lock:
            self._success_counter += 1
            if self._success_counter >= 50:
                self.interval = max(self.min_interval, self.interval * 0.9)
                self._success_counter = 0

# -----------------------------
# GUI
# -----------------------------

class VTGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Threat Analysis Toolkit (VirusTotal)")
        self.geometry("1120x720")
        self.minsize(980, 620)

        self._worker_thread: Optional[threading.Thread] = None
        self._stop_flag = threading.Event()
        self._log_queue = queue.Queue()

        self.results: List[IOCResult] = []
        self.cfg = load_config()
        # Pre-fill from config or env (UI may override)
        self.api_key = (self.cfg.get("vt_api_key") or os.getenv("VT_API_KEY", ""))

        self._build_ui()
        self._after_poll_logs()

    def _build_ui(self):
        frm = ttk.Frame(self, padding=10); frm.pack(fill="x")
        ttk.Label(frm, text="Input (log file or directory):").grid(row=0, column=0, sticky="w")
        self.var_input = tk.StringVar()
        ttk.Entry(frm, textvariable=self.var_input).grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Button(frm, text="Browse…", command=self._browse_input).grid(row=0, column=2, sticky="w")

        ttk.Label(frm, text="Output file:").grid(row=1, column=0, sticky="w")
        self.var_output = tk.StringVar(value="ioc_results.csv")
        ttk.Entry(frm, textvariable=self.var_output).grid(row=1, column=1, sticky="ew", padx=6)
        ttk.Button(frm, text="Save As…", command=self._browse_output).grid(row=1, column=2, sticky="w")

        ttk.Label(frm, text="Cache file:").grid(row=2, column=0, sticky="w")
        self.var_cache = tk.StringVar(value=DEFAULT_CACHE_FILE)
        ttk.Entry(frm, textvariable=self.var_cache).grid(row=2, column=1, sticky="ew", padx=6)
        ttk.Button(frm, text="Choose…", command=self._browse_cache).grid(row=2, column=2, sticky="w")

        ttk.Label(frm, text="VirusTotal API Key:").grid(row=3, column=0, sticky="w")
        self.var_apikey = tk.StringVar(value=self.api_key)
        ttk.Entry(frm, textvariable=self.var_apikey, show="*", width=36).grid(row=3, column=1, sticky="w", padx=6)
        self.var_save_key = tk.BooleanVar(value=bool(self.api_key))
        ttk.Checkbutton(frm, text="Save key to local config", variable=self.var_save_key).grid(row=3, column=2, sticky="w")

        opt = ttk.Frame(frm); opt.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(8,0))
        self.var_inc_ip = tk.BooleanVar(value=True);    ttk.Checkbutton(opt, text="IPs",     variable=self.var_inc_ip).pack(side="left")
        self.var_inc_dom = tk.BooleanVar(value=True);   ttk.Checkbutton(opt, text="Domains", variable=self.var_inc_dom).pack(side="left")
        self.var_inc_hash= tk.BooleanVar(value=True);   ttk.Checkbutton(opt, text="Hashes",  variable=self.var_inc_hash).pack(side="left")
        self.var_inc_url = tk.BooleanVar(value=True);   ttk.Checkbutton(opt, text="URLs",    variable=self.var_inc_url).pack(side="left")

        self.var_skip_private = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, text="Skip private/reserved IPs", variable=self.var_skip_private).pack(side="left", padx=(12,0))

        self.var_verbose = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, text="Verbose", variable=self.var_verbose).pack(side="left", padx=(12,0))

        ttk.Label(opt, text="Requests/min:").pack(side="left", padx=(16,4))
        self.var_rpm = tk.DoubleVar(value=60.0/16.0)  # ~3.75 rpm
        ttk.Spinbox(opt, from_=0.0, to=600.0, increment=0.5, textvariable=self.var_rpm, width=6).pack(side="left")

        ttk.Label(opt, text="(~sec/req):").pack(side="left", padx=(12,4))
        self.var_rate = tk.DoubleVar(value=16.0)
        ttk.Entry(opt, textvariable=self.var_rate, width=6, state="readonly").pack(side="left")

        self.var_auto_tune = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, text="Auto-tune rate", variable=self.var_auto_tune).pack(side="left", padx=(12,0))

        ttk.Label(opt, text="Max IOCs:").pack(side="left", padx=(16,4))
        self.var_max = tk.IntVar(value=0)
        ttk.Spinbox(opt, from_=0, to=200000, increment=1, textvariable=self.var_max, width=8).pack(side="left")

        prov = ttk.Frame(frm); prov.grid(row=5, column=0, columnspan=3, sticky="w", pady=(8,0))
        ttk.Label(prov, text="Providers:").pack(side="left")
        self.var_use_vt = tk.BooleanVar(value=True)
        ttk.Checkbutton(prov, text="VirusTotal", variable=self.var_use_vt).pack(side="left", padx=(8,0))

        btns = ttk.Frame(frm); btns.grid(row=6, column=0, columnspan=3, sticky="w", pady=(10,0))
        self.btn_run  = ttk.Button(btns, text="Scan & Check", command=self._on_run); self.btn_run.pack(side="left")
        self.btn_stop = ttk.Button(btns, text="Stop", command=self._on_stop, state="disabled"); self.btn_stop.pack(side="left", padx=(8,0))

        prog_row = ttk.Frame(frm); prog_row.grid(row=7, column=0, columnspan=3, sticky="ew", pady=(8,0))
        self.progress = ttk.Progressbar(prog_row, mode="determinate", maximum=100); self.progress.pack(fill="x")
        self.var_prog_label = tk.StringVar(value="Idle"); ttk.Label(prog_row, textvariable=self.var_prog_label).pack(anchor="w")

        frm.columnconfigure(1, weight=1)

        # Table
        tbl = ttk.Frame(self, padding=(10,0,10,0)); tbl.pack(fill="both", expand=True)
        cols = ("kind","value","verdict","malicious","suspicious","harmless","undetected","reputation","last_analysis_date","source","link","error")
        self.tree = ttk.Treeview(tbl, columns=cols, show="headings", height=14)
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=120 if c not in ("value","link") else 260, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True)
        vsb = ttk.Scrollbar(tbl, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set); vsb.pack(side="right", fill="y")

        # Bottom: log + export
        bottom = ttk.Frame(self, padding=10); bottom.pack(fill="both")
        left = ttk.Frame(bottom); left.pack(side="left", fill="both", expand=True)
        ttk.Label(left, text="Log:").pack(anchor="w")
        self.txt_log = tk.Text(left, height=10, wrap="word"); self.txt_log.pack(fill="both", expand=True)
        log_vsb = ttk.Scrollbar(left, orient="vertical", command=self.txt_log.yview)
        self.txt_log.configure(yscrollcommand=log_vsb.set); log_vsb.place(in_=self.txt_log, relx=1.0, rely=0, relheight=1.0, x=0)

        right = ttk.Frame(bottom); right.pack(side="left", fill="y", padx=(10,0))
        ttk.Label(right, text="Export:").pack(anchor="w")
        ttk.Button(right, text="Save as CSV…",  command=lambda: self._export("csv")).pack(fill="x", pady=2)
        ttk.Button(right, text="Save as JSON…", command=lambda: self._export("json")).pack(fill="x", pady=2)
        ttk.Separator(right, orient="horizontal").pack(fill="x", pady=6)
        ttk.Button(right, text="Open Output…", command=self._open_existing_output).pack(fill="x", pady=2)
        ttk.Button(right, text="Clear Table", command=self._clear_table).pack(fill="x", pady=8)

    # UI helpers

    def _browse_input(self):
        path = filedialog.askopenfilename(title="Choose a log file")
        if not path:
            path = filedialog.askdirectory(title="…or choose a directory with logs")
        if path:
            self.var_input.set(path)

    def _browse_output(self):
        initial = self.var_output.get() or "ioc_results.csv"
        fpath = filedialog.asksaveasfilename(
            title="Save results as",
            defaultextension=".csv",
            initialfile=initial,
            filetypes=[("CSV","*.csv"),("JSON","*.json"),("All files","*.*")]
        )
        if fpath:
            self.var_output.set(fpath)

    def _browse_cache(self):
        fpath = filedialog.asksaveasfilename(
            title="Choose cache file",
            defaultextension=".json",
            initialfile=self.var_cache.get() or DEFAULT_CACHE_FILE,
            filetypes=[("JSON","*.json"),("All files","*.*")]
        )
        if fpath:
            self.var_cache.set(fpath)

    def _append_log(self, text: str):
        self._log_queue.put(text)

    def _after_poll_logs(self):
        try:
            while True:
                line = self._log_queue.get_nowait()
                self.txt_log.insert("end", line + "\n"); self.txt_log.see("end")
        except queue.Empty:
            pass
        self.after(80, self._after_poll_logs)

    def _set_busy(self, busy: bool):
        self.btn_run.configure(state="disabled" if busy else "normal")
        self.btn_stop.configure(state="normal" if busy else "disabled")

    def _clear_table(self):
        for i in self.tree.get_children(): self.tree.delete(i)
        self.results = []; self.var_prog_label.set("Cleared"); self.progress["value"] = 0

    def _populate_table(self, results: List[IOCResult]):
        self._clear_table()
        for r in results:
            self.tree.insert("", "end", values=(
                r.kind, r.value, r.verdict, r.malicious, r.suspicious, r.harmless, r.undetected,
                r.reputation if r.reputation is not None else "",
                r.last_analysis_date or "", r.source, r.link or "", r.error or ""
            ))

    # Run

    def _on_run(self):
        # Key: UI → config → env, then sanitize/validate
        raw_key = (self.var_apikey.get() or "").strip()
        if not raw_key:
            raw_key = (self.cfg.get("vt_api_key") or os.getenv("VT_API_KEY", "") or "").strip()
        try:
            self.api_key = _sanitize_validate_api_key(raw_key)
        except ValueError as e:
            messagebox.showerror("Invalid API Key", str(e)); return

        # persist key to local config if requested
        if self.var_save_key.get():
            self.cfg["vt_api_key"] = self.api_key; save_config(self.cfg)
        else:
            if "vt_api_key" in self.cfg:
                self.cfg.pop("vt_api_key", None); save_config(self.cfg)

        input_path = self.var_input.get().strip()
        if not input_path or not os.path.exists(input_path):
            messagebox.showerror("Input Required", "Please choose a valid log file or directory."); return

        out_path = self.var_output.get().strip()
        if not out_path:
            messagebox.showerror("Output Required", "Please specify an output file (.csv or .json)."); return

        # RPM → sec/request; show hint
        try:
            rpm = max(0.0, float(self.var_rpm.get()))
            rate = 60.0 / rpm if rpm > 0 else 0.0
            self.var_rate.set(round(rate, 3))
        except Exception:
            messagebox.showerror("Invalid RPM", "Please enter a valid number for Requests/min."); return

        try:
            max_iocs = max(0, int(self.var_max.get()))
        except Exception:
            messagebox.showerror("Invalid Max", "Please enter a valid integer for Max IOCs."); return

        self._stop_flag.clear(); self._set_busy(True)
        self._append_log("[INFO] Starting…")
        try:
            self._append_log(f"[INFO] Using VT key length={len(self.api_key)} (starts with {self.api_key[:4]}****)")
        except Exception:
            pass
        self.progress["value"] = 0
        self.var_prog_label.set("Scanning logs… (tip: lower 'Rate' and enable fewer IOC kinds to go faster)")
        self.results = []

        args = {
            "input": input_path,
            "output": out_path,
            "cache": self.var_cache.get().strip() or DEFAULT_CACHE_FILE,
            "skip_private": self.var_skip_private.get(),
            "rate": rate,
            "rpm": rpm,
            "auto_tune": self.var_auto_tune.get(),
            "verbose": self.var_verbose.get(),
            "use_vt": self.var_use_vt.get(),
            "inc": {
                "ip": self.var_inc_ip.get(),
                "domain": self.var_inc_dom.get(),
                "hash": self.var_inc_hash.get(),
                "url": self.var_inc_url.get(),
            },
            "max_iocs": max_iocs,
        }

        self._worker_thread = threading.Thread(target=self._worker_run, args=(args,), daemon=True)
        self._worker_thread.start()

    def _on_stop(self):
        if self._worker_thread and self._worker_thread.is_alive():
            self._append_log("[INFO] Stop requested. Finishing current request…")
            self._stop_flag.set()

    def _worker_run(self, args: dict):
        try:
            # Session with pooling
            session = requests.Session()
            adapter = requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100)
            session.mount('https://', adapter); session.mount('http://', adapter)

            # 1) Collect IOCs
            iocs = collect_iocs_from_path(args["input"], verbose_cb=(self._append_log if args["verbose"] else None))

            # Scope
            for k in list(iocs.keys()):
                if not args["inc"].get(k, False): iocs[k] = set()

            if args["skip_private"]:
                iocs["ip"] = {ip for ip in iocs["ip"] if not is_private_or_reserved(ip)}

            # Flatten & sort
            flat: List[Tuple[str, str]] = []
            flat += [("ip", v) for v in sorted(iocs["ip"], key=lambda x: tuple(int(p) for p in x.split(".")))]
            flat += [("domain", v) for v in sorted(iocs["domain"])]
            flat += [("hash", v) for v in sorted(iocs["hash"])]
            flat += [("url", v) for v in sorted(iocs["url"])]

            if args["max_iocs"] > 0 and len(flat) > args["max_iocs"]:
                flat = flat[:args["max_iocs"]]

            if not flat:
                self._append_log("[INFO] No IOCs found. Nothing to do."); self._finish_progress("No IOCs found"); return

            total = len(flat)
            self._set_progress(0, f"Found {total} IOCs. Loading cache…")

            # 2) Cache
            cache = load_cache(args["cache"])

            # 3) Providers
            providers: List[Provider] = []
            if args["use_vt"]:
                providers.append(VirusTotalProvider(self.api_key, session))
            if not providers:
                self._append_log("[INFO] No providers enabled."); self._finish_progress("Nothing to do"); return

            # 4) Queries (batched concurrency + rate limiter)
            results: List[IOCResult] = []
            limiter = RateLimiter(args["rate"], auto_tune=bool(args.get("auto_tune", False)))

            def task_lookup(kind_value_idx):
                kind, value, idx_local = kind_value_idx
                # cache check
                for prov in providers:
                    ck = f"{prov.name}:{kind}:{value}"
                    if ck in cache:
                        try:
                            return idx_local, IOCResult(**cache[ck]), True
                        except Exception:
                            pass
                # rate-limit then query first provider
                prov = providers[0]
                limiter.wait()
                res = prov.lookup(kind, value)
                ck = f"{prov.name}:{kind}:{value}"
                cache[ck] = asdict(res)
                # adapt on 429
                if res.error and "429" in str(res.error):
                    limiter.observe_rate_limit()
                else:
                    limiter.observe_success()
                return idx_local, res, False

            max_workers = min(16, max(1, os.cpu_count() or 4))
            BATCH = max(16, min(200, max_workers * 4))
            complete = 0; last_ui = 0

            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                i = 0
                while i < total and not self._stop_flag.is_set():
                    batch_items = flat[i:i+BATCH]
                    futs = [ex.submit(task_lookup, (k, v, i+1+j)) for j, (k, v) in enumerate(batch_items)]
                    for fut in as_completed(futs):
                        if self._stop_flag.is_set(): break
                        idx_local, res, from_cache = fut.result()
                        results.append(res); complete += 1
                        if complete - last_ui >= 5 or complete == total:
                            lbl = f"[{complete}/{total}] {res.kind}:{res.value} → {res.verdict}{' (cache)' if from_cache else ''}"
                            self._set_progress(int(complete * 100 / total), lbl); last_ui = complete
                    # flush cache per batch
                    try: save_cache(args["cache"], cache)
                    except Exception: pass
                    i += BATCH

            self.results = results

            # 5) Write output
            try:
                _, ext = os.path.splitext(args["output"])
                if ext.lower() == ".json": write_json(results, args["output"])
                else:                      write_csv(results, args["output"])
                self._append_log(f"[DONE] Wrote results to: {args['output']}")
                self._append_log(f"[DONE] Cache stored at: {args['cache']}")
            except Exception as e:
                self._append_log(f"[ERROR] Failed to write output: {e}")

            # 6) Populate table
            self.after(0, lambda: self._populate_table(self.results))

            # 7) Summary
            counts: Dict[str,int] = {"malicious":0,"suspicious":0,"clean":0,"unknown":0}
            kinds:  Dict[str,int] = {"ip":0,"domain":0,"hash":0,"url":0}
            for r in self.results:
                counts[r.verdict] = counts.get(r.verdict,0)+1
                kinds[r.kind] = kinds.get(r.kind,0)+1
            self._append_log("[SUMMARY] Verdict counts:")
            for k in ["malicious","suspicious","clean","unknown"]:
                self._append_log(f"  {k}: {counts.get(k,0)}")
            self._append_log("[SUMMARY] Kind counts:")
            for k in ["ip","domain","hash","url"]:
                self._append_log(f"  {k}: {kinds.get(k,0)}")

            self._finish_progress("Done")
        finally:
            self.after(0, lambda: self._set_busy(False))

    def _set_progress(self, percent: int, label: str):
        self.after(0, lambda: (self.progress.configure(value=max(0, min(100, percent))),
                               self.var_prog_label.set(label)))

    def _finish_progress(self, label: str):
        self._set_progress(100, label)

    # Export

    def _export(self, kind: str):
        if not self.results:
            messagebox.showinfo("No Results", "Nothing to export yet."); return
        if kind == "csv":
            fp = filedialog.asksaveasfilename(title="Save as CSV", defaultextension=".csv",
                                              initialfile="ioc_results.csv", filetypes=[("CSV","*.csv"),("All files","*.*")])
            if not fp: return
            try: write_csv(self.results, fp); messagebox.showinfo("Exported", f"Saved {len(self.results)} rows to:\n{fp}")
            except Exception as e: messagebox.showerror("Export Error", str(e))
        elif kind == "json":
            fp = filedialog.asksaveasfilename(title="Save as JSON", defaultextension=".json",
                                              initialfile="ioc_results.json", filetypes=[("JSON","*.json"),("All files","*.*")])
            if not fp: return
            try: write_json(self.results, fp); messagebox.showinfo("Exported", f"Saved {len(self.results)} rows to:\n{fp}")
            except Exception as e: messagebox.showerror("Export Error", str(e))

    def _open_existing_output(self):
        out = self.var_output.get().strip()
        if not out or not os.path.exists(out):
            messagebox.showinfo("Not Found", "Output file does not exist yet."); return
        try:
            _, ext = os.path.splitext(out); results: List[IOCResult] = []
            if ext.lower() == ".json":
                with open(out, "r", encoding="utf-8") as f: arr = json.load(f)
                for row in arr: results.append(IOCResult(**row))
            else:
                with open(out, "r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        results.append(IOCResult(
                            kind=row.get("kind","ip"), value=row.get("value",""),
                            verdict=row.get("verdict","unknown"),
                            malicious=int(row.get("malicious",0) or 0),
                            suspicious=int(row.get("suspicious",0) or 0),
                            harmless=int(row.get("harmless",0) or 0),
                            undetected=int(row.get("undetected",0) or 0),
                            reputation=(int(row["reputation"]) if (row.get("reputation") not in (None,"","None")) else None),
                            last_analysis_date=row.get("last_analysis_date") or None,
                            source=row.get("source") or "VirusTotal",
                            link=row.get("link") or None, error=row.get("error") or None
                        ))
            self._populate_table(results); self._append_log(f"[INFO] Loaded {len(results)} rows from: {out}")
        except Exception as e:
            messagebox.showerror("Open Error", str(e))

# -----------------------------
# CLI (pre-fill UI)
# -----------------------------

def parse_cli_args():
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--input","-i");  p.add_argument("--output","-o");  p.add_argument("--cache")
    p.add_argument("--rate", type=float);  p.add_argument("--rpm", type=float, help="Requests per minute; overrides --rate if provided")
    p.add_argument("--auto-tune", action="store_true", help="Adaptive backoff on 429 responses")
    p.add_argument("--max", type=int, dest="max_iocs");  p.add_argument("--skip-private", action="store_true");  p.add_argument("--verbose", action="store_true")
    p.add_argument("--ip", action="store_true"); p.add_argument("--domain", action="store_true"); p.add_argument("--hash", action="store_true"); p.add_argument("--url", action="store_true")
    return p.parse_args()

def main():
    args = parse_cli_args()
    app = VTGUI()
    if args.input: app.var_input.set(args.input)
    if args.output: app.var_output.set(args.output)
    if args.cache: app.var_cache.set(args.cache)
    if args.rpm is not None:
        try: app.var_rpm.set(float(args.rpm)); app.var_rate.set(round(60.0/float(args.rpm), 3) if args.rpm>0 else 0.0)
        except Exception: pass
    elif args.rate is not None:
        app.var_rate.set(args.rate)
        try: app.var_rpm.set(0.0 if args.rate<=0 else round(60.0/float(args.rate), 3))
        except Exception: pass
    if args.max_iocs is not None: app.var_max.set(args.max_iocs)
    if args.skip_private: app.var_skip_private.set(True)
    if args.verbose: app.var_verbose.set(True)
    if getattr(args, "auto_tune", False): app.var_auto_tune.set(True)
    if any([args.ip, args.domain, args.hash, args.url]):
        app.var_inc_ip.set(bool(args.ip)); app.var_inc_dom.set(bool(args.domain))
        app.var_inc_hash.set(bool(args.hash)); app.var_inc_url.set(bool(args.url))
    app.mainloop()

if __name__ == "__main__":
    main()
