#!/usr/bin/env python3
"""
vt_log_ip_check_gui.py

GUI for:
  - Collecting IP addresses from log files (file or directory)
  - Checking each IP with VirusTotal (v3 API)
  - Viewing, filtering, and exporting results (CSV/JSON)
  - Local JSON cache to avoid re-querying the same IPs

Requirements:
  - Python 3.8+
  - pip install requests python-dateutil
  - Set environment variable: VT_API_KEY=your_key_here

Notes:
  - Free VT API is rate-limited. Default rate delay is 16s between requests.
  - The GUI runs VT queries on a worker thread so the UI stays responsive.
"""

import argparse
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
from typing import Dict, Iterable, List, Optional, Set

import requests
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import pathlib

CONFIG_PATH = os.path.expanduser("~/.vt_gui_config.json")

def load_config() -> dict:
    try:
        p = pathlib.Path(CONFIG_PATH)
        if p.exists():
            return json.loads(p.read_text(encoding="utf8"))
    except Exception:
        pass
    return{}

def save_config(cfg: dict) -> None:
    try:
        pathlib.Path(CONFIG_PATH).write_text(json.dumps(cfg, indent=2), encoding="utf8")
    except Exception:
        pass

# -----------------------------
# Core logic (same as CLI base)
# -----------------------------

VT_API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

# Pragmatic IPv4 regex
IPV4_REGEX = re.compile(
    r'(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)'
)

DEFAULT_CACHE_FILE = "cache_ip.json"


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
        # GUI prints to log, but keep stderr fallback
        print(f"[WARN] Failed to write cache: {e}", file=sys.stderr)


def is_private_or_reserved(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_link_local
        )
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
                # Skip overly large files (50MB+)
                try:
                    if os.path.getsize(full) > 50 * 1024 * 1024:
                        continue
                except Exception:
                    pass
                yield full


def collect_ips_from_path(path: str, verbose_cb=None) -> Set[str]:
    """
    verbose_cb: optional callable(str) for GUI log
    """
    all_ips: Set[str] = set()
    for fp in iter_files(path):
        try:
            with open(fp, "r", errors="ignore", encoding="utf-8") as f:
                content = f.read()
            ips = find_ips_in_text(content)
            if verbose_cb and ips:
                verbose_cb(f"[INFO] {fp}: found {len(ips)} IPs")
            all_ips.update(ips)
        except Exception as e:
            if verbose_cb:
                verbose_cb(f"[WARN] Could not read {fp}: {e}")
    return all_ips


def vt_fetch_ip(ip: str, api_key: str, session: requests.Session) -> VTResult:
    headers = {"x-apikey": api_key}
    url = VT_API_URL.format(ip=ip)
    try:
        r = session.get(url, headers=headers, timeout=30)
        if r.status_code == 404:
            return VTResult(ip=ip, verdict="unknown", error="Not found in VT")
        if r.status_code in (401, 403):
            return VTResult(ip=ip, verdict="unknown", error=f"Auth error {r.status_code}: check API key/plan")
        if r.status_code == 429:
            return VTResult(ip=ip, verdict="unknown", error="Rate limited (HTTP 429)")
        r.raise_for_status()
        data = r.json()
        attr = data.get("data", {}).get("attributes", {}) or {}

        stats = attr.get("last_analysis_stats", {}) or {}
        rep = attr.get("reputation")
        lad = attr.get("last_analysis_date")
        lad_iso = datetime.fromtimestamp(lad, tz=timezone.utc).isoformat() if lad else None

        link = f"https://www.virustotal.com/gui/ip-address/{ip}"

        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))

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


# -----------------------------
# GUI Application
# -----------------------------

class VTGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("VirusTotal Log IP Checker")
        self.geometry("1024x680")
        self.minsize(900, 600)

        self._worker_thread: Optional[threading.Thread] = None
        self._stop_flag = threading.Event()
        self._log_queue = queue.Queue()

        # State
        self.results: List[VTResult] = []
        cfg = load_config()
        self.api_key = cfg.get("vt_api_key") or os.getenv("VT_API_KEY", "")
        self.cfg = cfg

        # UI
        self._build_ui()
        self._after_poll_logs()

    def _build_ui(self):
        # --- Top frame: Inputs ---
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="x")

        # Input path
        ttk.Label(frm, text="Input (log file or directory):").grid(row=0, column=0, sticky="w")
        self.var_input = tk.StringVar()
        ent_input = ttk.Entry(frm, textvariable=self.var_input)
        ent_input.grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Button(frm, text="Browse…", command=self._browse_input).grid(row=0, column=2, sticky="w")


        # Output path
        ttk.Label(frm, text="Output file:").grid(row=1, column=0, sticky="w")
        self.var_output = tk.StringVar(value="vt_results.csv")
        ent_output = ttk.Entry(frm, textvariable=self.var_output)
        ent_output.grid(row=1, column=1, sticky="ew", padx=6)
        ttk.Button(frm, text="Save As…", command=self._browse_output).grid(row=1, column=2, sticky="w")

        # Cache path
        ttk.Label(frm, text="Cache file:").grid(row=2, column=0, sticky="w")
        self.var_cache = tk.StringVar(value=DEFAULT_CACHE_FILE)
        ent_cache = ttk.Entry(frm, textvariable=self.var_cache)
        ent_cache.grid(row=2, column=1, sticky="ew", padx=6)
        ttk.Button(frm, text="Choose…", command=self._browse_cache).grid(row=2, column=2, sticky="w")

        # API key input (masked) + remember toggle
        ttk.Label(frm, text="VirusTotal API Key:").grid(row=3, column=0, sticky="w")
        self.var_apikey = tk.StringVar(value=self.api_key)
        ent_api = ttk.Entry(frm, textvariable=self.var_apikey, show="*", width=36)
        ent_api.grid(row=3, column=1, sticky="w", padx=6)
        self.var_save_key = tk.BooleanVar(value=bool(self.api_key))
        ttk.Checkbutton(frm, text="Save key to local config", variable=self.var_save_key).grid(row=3, column=2, sticky="w")

        # Options row
        opt = ttk.Frame(frm)
        opt.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(8, 0))

        self.var_skip_private = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, text="Skip private/reserved IPs", variable=self.var_skip_private).pack(side="left")

        self.var_verbose = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, text="Verbose", variable=self.var_verbose).pack(side="left", padx=(12, 0))

        ttk.Label(opt, text="Rate (sec/request):").pack(side="left", padx=(16, 4))
        self.var_rate = tk.DoubleVar(value=16.0)
        ttk.Spinbox(opt, from_=0.0, to=120.0, increment=0.5, textvariable=self.var_rate, width=6).pack(side="left")

        ttk.Label(opt, text="Max IPs:").pack(side="left", padx=(16, 4))
        self.var_max = tk.IntVar(value=0)
        ttk.Spinbox(opt, from_=0, to=100000, increment=1, textvariable=self.var_max, width=8).pack(side="left")

        # Run/Stop buttons
        btns = ttk.Frame(frm)
        btns.grid(row=5, column=0, columnspan=3, sticky="w", pady=(10, 0))
        self.btn_run = ttk.Button(btns, text="Scan & Check", command=self._on_run)
        self.btn_run.pack(side="left")
        self.btn_stop = ttk.Button(btns, text="Stop", command=self._on_stop, state="disabled")
        self.btn_stop.pack(side="left", padx=(8, 0))

        # Progress
        prog_row = ttk.Frame(frm)
        prog_row.grid(row=6, column=0, columnspan=3, sticky="ew", pady=(8, 0))
        self.progress = ttk.Progressbar(prog_row, mode="determinate", maximum=100)
        self.progress.pack(fill="x")
        self.var_prog_label = tk.StringVar(value="Idle")
        ttk.Label(prog_row, textvariable=self.var_prog_label).pack(anchor="w")

        # Configure columns scaling
        frm.columnconfigure(1, weight=1)

        # --- Middle: Results table ---
        tbl_frame = ttk.Frame(self, padding=(10, 0, 10, 0))
        tbl_frame.pack(fill="both", expand=True)

        cols = ("ip", "verdict", "malicious", "suspicious", "harmless", "undetected",
                "reputation", "last_analysis_date", "link", "error")
        self.tree = ttk.Treeview(tbl_frame, columns=cols, show="headings", height=12)
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=120 if c != "link" else 220, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True)

        vsb = ttk.Scrollbar(tbl_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")

        # --- Bottom: log + export ---
        bottom = ttk.Frame(self, padding=10)
        bottom.pack(fill="both")

        left = ttk.Frame(bottom)
        left.pack(side="left", fill="both", expand=True)

        ttk.Label(left, text="Log:").pack(anchor="w")
        self.txt_log = tk.Text(left, height=10, wrap="word")
        self.txt_log.pack(fill="both", expand=True)
        log_vsb = ttk.Scrollbar(left, orient="vertical", command=self.txt_log.yview)
        self.txt_log.configure(yscrollcommand=log_vsb.set)
        log_vsb.place(in_=self.txt_log, relx=1.0, rely=0, relheight=1.0, x=0)

        right = ttk.Frame(bottom)
        right.pack(side="left", fill="y", padx=(10, 0))
        ttk.Label(right, text="Export:").pack(anchor="w")
        ttk.Button(right, text="Save as CSV…", command=lambda: self._export("csv")).pack(fill="x", pady=2)
        ttk.Button(right, text="Save as JSON…", command=lambda: self._export("json")).pack(fill="x", pady=2)
        ttk.Separator(right, orient="horizontal").pack(fill="x", pady=6)
        ttk.Button(right, text="Open Output…", command=self._open_existing_output).pack(fill="x", pady=2)
        ttk.Button(right, text="Clear Table", command=self._clear_table).pack(fill="x", pady=8)

    # ---------- UI Helpers ----------

    def _browse_input(self):
        path = filedialog.askopenfilename(title="Choose a log file")
        if not path:
            # maybe choose a directory instead
            path = filedialog.askdirectory(title="…or choose a directory with logs")
        if path:
            self.var_input.set(path)

    def _browse_output(self):
        initial = self.var_output.get() or "vt_results.csv"
        fpath = filedialog.asksaveasfilename(
            title="Save results as",
            defaultextension=".csv",
            initialfile=initial,
            filetypes=[("CSV", "*.csv"), ("JSON", "*.json"), ("All files", "*.*")]
        )
        if fpath:
            self.var_output.set(fpath)

    def _browse_cache(self):
        fpath = filedialog.asksaveasfilename(
            title="Choose cache file",
            defaultextension=".json",
            initialfile=self.var_cache.get() or DEFAULT_CACHE_FILE,
            filetypes=[("JSON", "*.json"), ("All files", "*.*")]
        )
        if fpath:
            self.var_cache.set(fpath)

    def _append_log(self, text: str):
        # enqueue to be appended from main thread
        self._log_queue.put(text)

    def _after_poll_logs(self):
        try:
            while True:
                line = self._log_queue.get_nowait()
                self.txt_log.insert("end", line + "\n")
                self.txt_log.see("end")
        except queue.Empty:
            pass
        self.after(80, self._after_poll_logs)

    def _set_busy(self, busy: bool):
        state = "disabled" if busy else "normal"
        self.btn_run.configure(state="disabled" if busy else "normal")
        self.btn_stop.configure(state="normal" if busy else "disabled")

    def _clear_table(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.results = []
        self.var_prog_label.set("Cleared")
        self.progress["value"] = 0

    def _populate_table(self, results: List[VTResult]):
        self._clear_table()
        for r in results:
            self.tree.insert("", "end", values=(
                r.ip, r.verdict, r.malicious, r.suspicious, r.harmless, r.undetected,
                r.reputation if r.reputation is not None else "",
                r.last_analysis_date or "",
                r.link or "",
                r.error or ""
            ))

    # ---------- Run logic ----------

    def _on_run(self):
        self.api_key = (self.var_apikey.get() or "").strip() or os.getenv("VT_API_KEY", "")
        if not self.api_key:
            messagebox.showerror("VirusTotal API Key Missing",
                                 "Please set your VirusTotal API key in the VT_API_KEY environment variable.")
            return
        
        # persist key to local config if requested
        if self.var_save_key.get():
            self.cfg["vt_api_key"] = self.api_key
            save_config(self.cfg)
        else:
            # if user unticks, remove save key
            if "vt_api_key" in self.cfg:
                self.cfg.pop("vt_api_key", None)
                save_config(self.cfg)

        input_path = self.var_input.get().strip()
        if not input_path or not os.path.exists(input_path):
            messagebox.showerror("Input Required", "Please choose a valid log file or directory.")
            return

        out_path = self.var_output.get().strip()
        if not out_path:
            messagebox.showerror("Output Required", "Please specify an output file (.csv or .json).")
            return

        try:
            rate = max(0.0, float(self.var_rate.get()))
        except Exception:
            messagebox.showerror("Invalid Rate", "Please enter a valid rate (seconds per request).")
            return

        try:
            max_ips = max(0, int(self.var_max.get()))
        except Exception:
            messagebox.showerror("Invalid Max", "Please enter a valid integer for Max IPs.")
            return

        self._stop_flag.clear()
        self._set_busy(True)
        self._append_log("[INFO] Starting…")
        self.progress["value"] = 0
        self.var_prog_label.set("Scanning logs…")
        self.results = []

        args = {
            "input": input_path,
            "output": out_path,
            "cache": self.var_cache.get().strip() or DEFAULT_CACHE_FILE,
            "skip_private": self.var_skip_private.get(),
            "rate": rate,
            "max_ips": max_ips,
            "verbose": self.var_verbose.get(),
        }

        self._worker_thread = threading.Thread(target=self._worker_run, args=(args,), daemon=True)
        self._worker_thread.start()

    def _on_stop(self):
        if self._worker_thread and self._worker_thread.is_alive():
            self._append_log("[INFO] Stop requested. Finishing current request…")
            self._stop_flag.set()

    def _worker_run(self, args: dict):
        try:
            session = requests.Session()
            # 1) Collect IPs
            all_ips = collect_ips_from_path(args["input"], verbose_cb=(self._append_log if args["verbose"] else None))
            if args["skip_private"]:
                all_ips = {ip for ip in all_ips if not is_private_or_reserved(ip)}

            ips_sorted = sorted(all_ips, key=lambda x: tuple(int(p) for p in x.split(".")))
            if args["max_ips"] > 0:
                ips_sorted = ips_sorted[:args["max_ips"]]

            if not ips_sorted:
                self._append_log("[INFO] No IPs found. Nothing to do.")
                self._finish_progress("No IPs found")
                return

            total = len(ips_sorted)
            self._set_progress(0, f"Found {total} IPs. Loading cache…")

            # 2) Load cache
            cache = load_cache(args["cache"])

            # 3) Query VT
            results: List[VTResult] = []
            for idx, ip in enumerate(ips_sorted, start=1):
                if self._stop_flag.is_set():
                    self._append_log("[INFO] Stopping early by request.")
                    break

                if ip in cache:
                    if args["verbose"]:
                        self._append_log(f"[CACHE] {ip}")
                    results.append(VTResult(**cache[ip]))
                    self._set_progress(int(idx * 100 / total), f"[{idx}/{total}] Cached: {ip}")
                    continue

                if args["verbose"]:
                    self._append_log(f"[{idx}/{total}] Querying VT for {ip} …")

                res = vt_fetch_ip(ip, self.api_key, session)
                results.append(res)
                cache[ip] = asdict(res)
                save_cache(args["cache"], cache)

                self._set_progress(int(idx * 100 / total), f"[{idx}/{total}] {ip} → {res.verdict}")

                if idx < total and not self._stop_flag.is_set():
                    time.sleep(args["rate"])

            self.results = results

            # 4) Write output chosen
            try:
                _, ext = os.path.splitext(args["output"])
                if ext.lower() == ".json":
                    write_json(results, args["output"])
                else:
                    write_csv(results, args["output"])
                self._append_log(f"[DONE] Wrote results to: {args['output']}")
                self._append_log(f"[DONE] Cache stored at: {args['cache']}")
            except Exception as e:
                self._append_log(f"[ERROR] Failed to write output: {e}")

            # 5) Populate table in UI thread
            self.after(0, lambda: self._populate_table(self.results))

            # Summary
            counts = {"malicious": 0, "suspicious": 0, "clean": 0, "unknown": 0}
            for r in self.results:
                counts[r.verdict] = counts.get(r.verdict, 0) + 1
            self._append_log("[SUMMARY] Verdict counts:")
            for k in ["malicious", "suspicious", "clean", "unknown"]:
                self._append_log(f"  {k}: {counts.get(k, 0)}")

            self._finish_progress("Done")
        finally:
            self.after(0, lambda: self._set_busy(False))

    def _set_progress(self, percent: int, label: str):
        self.after(0, lambda: (self.progress.configure(value=max(0, min(100, percent))),
                               self.var_prog_label.set(label)))

    def _finish_progress(self, label: str):
        self._set_progress(100, label)

    # ---------- Export helpers ----------

    def _export(self, kind: str):
        if not self.results:
            messagebox.showinfo("No Results", "Nothing to export yet.")
            return
        if kind == "csv":
            fp = filedialog.asksaveasfilename(
                title="Save as CSV",
                defaultextension=".csv",
                initialfile="vt_results.csv",
                filetypes=[("CSV", "*.csv"), ("All files", "*.*")]
            )
            if not fp:
                return
            try:
                write_csv(self.results, fp)
                messagebox.showinfo("Exported", f"Saved {len(self.results)} rows to:\n{fp}")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))
        elif kind == "json":
            fp = filedialog.asksaveasfilename(
                title="Save as JSON",
                defaultextension=".json",
                initialfile="vt_results.json",
                filetypes=[("JSON", "*.json"), ("All files", "*.*")]
            )
            if not fp:
                return
            try:
                write_json(self.results, fp)
                messagebox.showinfo("Exported", f"Saved {len(self.results)} rows to:\n{fp}")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))

    def _open_existing_output(self):
        out = self.var_output.get().strip()
        if not out or not os.path.exists(out):
            messagebox.showinfo("Not Found", "Output file does not exist yet.")
            return
        try:
            # Reload and show in table (handy if user edited externally)
            _, ext = os.path.splitext(out)
            results: List[VTResult] = []
            if ext.lower() == ".json":
                with open(out, "r", encoding="utf-8") as f:
                    arr = json.load(f)
                for row in arr:
                    results.append(VTResult(**row))
            else:
                with open(out, "r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        results.append(VTResult(
                            ip=row.get("ip", ""),
                            verdict=row.get("verdict", "unknown"),
                            malicious=int(row.get("malicious", 0) or 0),
                            suspicious=int(row.get("suspicious", 0) or 0),
                            harmless=int(row.get("harmless", 0) or 0),
                            undetected=int(row.get("undetected", 0) or 0),
                            reputation=(int(row["reputation"]) if (row.get("reputation") not in (None, "", "None")) else None),
                            last_analysis_date=row.get("last_analysis_date") or None,
                            link=row.get("link") or None,
                            error=row.get("error") or None
                        ))
            self._populate_table(results)
            self._append_log(f"[INFO] Loaded {len(results)} rows from: {out}")
        except Exception as e:
            messagebox.showerror("Open Error", str(e))


# -----------------------------
# Optional CLI wrapper:
# Allows: python vt_log_ip_check_gui.py --input ... (pre-fill fields)
# -----------------------------
def parse_cli_args():
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--input", "-i")
    p.add_argument("--output", "-o")
    p.add_argument("--cache")
    p.add_argument("--rate", type=float)
    p.add_argument("--max", type=int, dest="max_ips")
    p.add_argument("--skip-private", action="store_true")
    p.add_argument("--verbose", action="store_true")
    return p.parse_args()


def main():
    args = parse_cli_args()
    app = VTGUI()
    # Pre-fill if provided
    if args.input:
        app.var_input.set(args.input)
    if args.output:
        app.var_output.set(args.output)
    if args.cache:
        app.var_cache.set(args.cache)
    if args.rate is not None:
        app.var_rate.set(args.rate)
    if args.max_ips is not None:
        app.var_max.set(args.max_ips)
    if args.skip_private:
        app.var_skip_private.set(True)
    if args.verbose:
        app.var_verbose.set(True)
    app.mainloop()


if __name__ == "__main__":
    main()