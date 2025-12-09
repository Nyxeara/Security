#!/usr/bin/env python3
"""
android_hardener_pro_max.py
Pro Max Ultimate - Read-only deep Android Host Hardener scanner (non-destructive).

Run as root for best coverage:
  su -c 'python3 android_hardener_pro_max.py [--deep] [--fast] [--output FILE]'

Options:
  --output FILE         Save JSON report to FILE
  --save-baseline FILE  Save current snapshot as baseline to FILE
  --compare-baseline FILE  Compare current snapshot to baseline FILE and highlight diffs
  --quiet               Produce only machine-friendly JSON (to stdout)
  --fast                Skip very deep filesystem traversal (faster)
  --deep                Allow deeper and longer scans (slower, more thorough)
"""

import os
import sys
import json
import argparse
import hashlib
import fnmatch
import subprocess
import time
import stat
from datetime import datetime, timezone

# ---------------- Configuration: expanded ----------------
REPORT_VERSION = "2.0-pro-max"

# core watched and search paths (expanded)
WATCH_PATHS = [
    "/system/build.prop",
    "/system/etc/hosts",
    "/system/etc/resolv.conf",
    "/system/etc/init",
    "/system/etc/init.d",
    "/system/bin",
    "/system/xbin",
    "/vendor",
    "/data/system/packages.xml",
    "/data/system/users/0/settings_secure.xml",
    "/data/system/users/0/settings_global.xml",
    "/data/system/users/0/settings_system.xml",
    "/sys/fs/selinux/enforce",
    "/etc/hosts",
    "/data/app",
    "/data/local/tmp",
    "/cache",
    "/data/dalvik-cache",
]

# search roots expanded
SEARCH_ROOTS = [
    "/data", "/sdcard", "/mnt", "/storage", "/system", "/vendor", "/odm",
    "/data/local/tmp", "/cache", "/data/app", "/data/dalvik-cache", "/data/misc",
    "/data/media/0", "/dev/block", "/proc", "/sys"
]

# exclude dirs to avoid infinite/huge traversal (but deep scan may override some)
EXCLUDE_DIRS = {"/proc", "/sys", "/dev", "/data/data", "/data/user_de", "/storage/emulated"}

# patterns and heuristics expanded
SUSPICIOUS_BIN_NAMES = [
    "su", "magisk", "magiskinit", "magiskd", "magiskpolicy", "magiskhide",
    "busybox", "kitchen", "supersu", "daemonsu", "xposed", "frida", "rootcloak",
    "titanium", "vmos", "parallel", "shadow", "hacker", "riru"
]

SUSPICIOUS_FILE_PATTERNS = [
    "*.so", "*.jar", "*.dex", "*.apk", "*.so.*"
]

KEYLOGGER_PATTERNS = [
    "keylog", "keylogger", "keystroke", "inputhook", "frida", "xposed",
    "hook", "spy", "monitor", "logger", "keytap", "keycatch"
]

CRED_FILENAME_PATTERNS = [
    "passwd", "shadow", "id_rsa", "id_dsa", ".pem", ".p12", ".pfx", "secret", "credentials", "keys", ".key"
]

NETWORK_INDICATOR_FILES = [
    "/etc/hosts", "/system/etc/hosts", "/data/misc/dhcp", "/etc/resolv.conf", "/system/etc/resolv.conf"
]

# emoji legend (used in human report)
EMOJI = {
    "suspicious_bin": "⚠️",
    "hidden": "👻",
    "root": "🛠️",
    "keylogger": "🕵️",
    "selinux": "🔐",
    "network": "🌐",
    "changed": "✨",
    "error": "❌",
    "ok": "✅",
    "credentials": "🔑",
    "writable": "🔓",
    "socket": "🔌",
    "apk": "📦",
}

# ---------------- Utilities ----------------

def now_ts():
    """Timezone-aware ISO 8601 UTC with Z."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def safe_read(path, max_bytes=1024*200):
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
            try:
                return data.decode("utf-8", errors="replace"), None
            except Exception:
                # return repr of binary chunk
                return repr(data[:1024]), None
    except Exception as e:
        return None, str(e)

def file_hash(path, algo="sha256", max_read=None):
    try:
        h = hashlib.new(algo)
        with open(path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest(), None
    except Exception as e:
        return None, str(e)

def stat_info(path):
    try:
        st = os.lstat(path)
        return {
            "mode": oct(st.st_mode & 0o7777),
            "uid": st.st_uid,
            "gid": st.st_gid,
            "size": st.st_size,
            "mtime": st.st_mtime,
            "is_symlink": os.path.islink(path),
        }, None
    except Exception as e:
        return None, str(e)

def run_cmd_list(cmd_list, timeout=8):
    try:
        proc = subprocess.run(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, shell=False)
        out = proc.stdout.decode("utf-8", errors="replace")
        err = proc.stderr.decode("utf-8", errors="replace")
        return out, err, proc.returncode
    except Exception as e:
        return "", str(e), -1

# ---------------- Lower-level checks ----------------

def check_paths(paths):
    results = {}
    for p in paths:
        entry = {"path": p, "exists": False}
        if os.path.exists(p):
            entry["exists"] = True
            si, serr = stat_info(p)
            entry["stat"] = si or {}
            entry["stat_err"] = serr
            if os.path.isfile(p):
                txt, rerr = safe_read(p, max_bytes=512*1024)
                entry["content_snippet"] = txt if txt is not None else None
                entry["read_error"] = rerr
                h, herr = file_hash(p)
                entry["sha256"] = h
                entry["hash_error"] = herr
            elif os.path.isdir(p):
                try:
                    entry["children"] = os.listdir(p)
                except Exception as e:
                    entry["children_err"] = str(e)
        else:
            entry["note"] = "missing"
        results[p] = entry
    return results

def check_selinux():
    data = {}
    enforce_path = "/sys/fs/selinux/enforce"
    if os.path.exists(enforce_path):
        txt, err = safe_read(enforce_path, max_bytes=64)
        data["enforce_file"] = txt.strip() if txt else None
        data["enforce_file_err"] = err
    out, err, rc = run_cmd_list(["getenforce"])
    if rc == 0 and out:
        data["getenforce"] = out.strip()
    else:
        data["getenforce_err"] = err.strip() if err else f"rc={rc}"
    return data

def gather_iptables():
    data = {}
    out, err, rc = run_cmd_list(["iptables-save"])
    if rc == 0 and out:
        data["iptables-save"] = out
    else:
        data["iptables-save_err"] = err.strip() if err else f"rc={rc}"
    out2, err2, rc2 = run_cmd_list(["nft", "list", "ruleset"])
    if rc2 == 0 and out2:
        data["nft_ruleset"] = out2
    else:
        data["nft_ruleset_err"] = err2.strip() if err2 else f"rc={rc2}"
    return data

def list_processes(sample_limit=500):
    """Collect basic /proc info, cmdline, exe, status for processes (sample limited)."""
    procs = []
    try:
        for pid in sorted(filter(lambda x: x.isdigit(), os.listdir("/proc")), key=int)[:sample_limit]:
            pdir = os.path.join("/proc", pid)
            try:
                stat_txt, _ = safe_read(os.path.join(pdir, "status"), max_bytes=8192)
                cmdline_txt, _ = safe_read(os.path.join(pdir, "cmdline"), max_bytes=8192)
                exe_link = None
                try:
                    exe_link = os.readlink(os.path.join(pdir, "exe"))
                except Exception:
                    exe_link = None
                procs.append({
                    "pid": int(pid),
                    "status": stat_txt,
                    "cmdline": (cmdline_txt or "").replace("\x00", " ").strip(),
                    "exe": exe_link,
                })
            except Exception:
                continue
    except Exception:
        pass
    suspicious = []
    for p in procs:
        low = (p.get("cmdline") or "").lower() + " " + (p.get("exe") or "").lower()
        if any(name in low for name in SUSPICIOUS_BIN_NAMES + ["xposed", "frida", "hook"]):
            suspicious.append(p)
    return {"count": len(procs), "sample": procs[:200], "suspicious": suspicious}

def find_suspicious_binaries(root_paths, fast=False, deep=False, max_found=20000):
    found = {"bins": [], "sos": [], "hidden": [], "apks": [], "candidates": []}
    visited = 0
    max_visit = 200000 if deep else (20000 if not fast else 5000)
    for root in root_paths:
        if not os.path.exists(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root, topdown=True):
            visited += 1
            # throttle
            if visited > max_visit or len(found["bins"]) + len(found["sos"]) + len(found["apks"]) > max_found:
                return found
            # skip exclude dirs
            if any(dirpath.startswith(x) for x in EXCLUDE_DIRS):
                continue
            # skip obvious caches when not deep
            if not deep and any(x in dirpath for x in ["/.cache", "/cache", "/dalvik-cache"]):
                continue
            for fname in filenames:
                lower = fname.lower()
                full = os.path.join(dirpath, fname)
                # suspicious binaries by exact or suffix match
                if any(lower == s or lower.endswith(s) for s in SUSPICIOUS_BIN_NAMES):
                    si, _ = stat_info(full)
                    found["bins"].append({"path": full, "stat": si})
                # suspicious libs/apks/dex/jar
                if fnmatch.fnmatch(fname, "*.so") or fnmatch.fnmatch(fname, "*.jar") or fnmatch.fnmatch(fname, "*.dex"):
                    flagged = any(p in full for p in ["/data/", "/sdcard/", "/storage/", "/mnt/", "/cache", "/tmp"])
                    si, _ = stat_info(full)
                    found["sos"].append({"path": full, "in_writable": flagged, "stat": si})
                if fnmatch.fnmatch(fname, "*.apk"):
                    si, _ = stat_info(full)
                    found["apks"].append({"path": full, "stat": si})
                # hidden files
                if fname.startswith(".") and len(fname) > 1:
                    found["hidden"].append(full)
                # general candidate suspicious names (keylogger etc)
                if any(pat in lower for pat in KEYLOGGER_PATTERNS + ["monitor", "spy", "inject", "hook"]):
                    si, _ = stat_info(full)
                    found["candidates"].append({"path": full, "stat": si})
    return found

def check_common_su_locations():
    hits = []
    common = [
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
        "/magisk/.magisk", "/data/adb/magisk", "/cache/magisk", "/dev/magisk",
        "/apex/com.android.runtime/bin/su", "/system/bin/.ext", "/system/xbin/.ext"
    ]
    for p in common:
        if os.path.exists(p):
            si, err = stat_info(p)
            hits.append({"path": p, "stat": si, "stat_err": err})
    return hits

def check_ld_preload_and_env(sample_limit=200):
    data = {}
    preload_path = "/etc/ld.so.preload"
    if os.path.exists(preload_path):
        txt, err = safe_read(preload_path, max_bytes=4096)
        data["ld.so.preload"] = txt
        data["ld.so.preload_err"] = err
    # scan /proc/*/environ for LD_* envs
    env_hits = []
    try:
        for pid in filter(lambda x: x.isdigit(), os.listdir("/proc")):
            if len(env_hits) >= sample_limit:
                break
            try:
                env_txt, _ = safe_read(os.path.join("/proc", pid, "environ"), max_bytes=4096)
                if env_txt and ("LD_PRELOAD" in env_txt or "LD_LIBRARY_PATH" in env_txt or "LD_AUDIT" in env_txt):
                    env_hits.append({"pid": int(pid), "env_sample": env_txt.replace("\x00", " ")[:400]})
            except Exception:
                continue
    except Exception:
        pass
    data["proc_env_hits"] = env_hits
    return data

def parse_packages_xml(path="/data/system/packages.xml"):
    if not os.path.exists(path):
        return {"error": "missing"}
    txt, err = safe_read(path, max_bytes=1024*1024)
    if txt is None:
        return {"error": err}
    packages = []
    for line in txt.splitlines():
        line = line.strip()
        if line.startswith("<package "):
            try:
                name = None
                if "name=\"" in line:
                    name = line.split("name=\"",1)[1].split("\"",1)[0]
                packages.append({"line": line[:400], "name": name})
            except Exception:
                packages.append({"line": line[:400]})
    return {"packages_count_heuristic": len(packages), "samples": packages[:500]}

def scan_init_scripts(init_dirs):
    findings = {}
    for d in init_dirs:
        if os.path.exists(d) and os.path.isdir(d):
            entries = {}
            try:
                for fname in os.listdir(d):
                    full = os.path.join(d, fname)
                    if os.path.isfile(full):
                        txt, err = safe_read(full, max_bytes=64*1024)
                        entries[fname] = {
                            "path": full,
                            "readable": txt is not None,
                            "snippet": (txt or "")[:2048],
                            "read_error": err
                        }
            except Exception as e:
                findings[d] = {"error": str(e)}
            else:
                findings[d] = entries
    return findings

def detect_keylogger_indicators(search_paths, fast=False):
    ky = []
    max_hits = 500 if not fast else 150
    for root in search_paths:
        if not os.path.exists(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            if any(dirpath.startswith(x) for x in EXCLUDE_DIRS):
                continue
            for fname in filenames:
                low = fname.lower()
                if any(p in low for p in KEYLOGGER_PATTERNS):
                    ky.append(os.path.join(dirpath, fname))
                    if len(ky) >= max_hits:
                        return ky
            # shallow control for speed
            if fast and len(ky) > 50:
                return ky
    return ky

def find_world_writable_and_777(search_roots, fast=False, deep=False):
    findings = []
    max_visit = 200000 if deep else (20000 if not fast else 5000)
    visited = 0
    for root in search_roots:
        if not os.path.exists(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            visited += 1
            if visited > max_visit:
                return findings
            if any(dirpath.startswith(x) for x in EXCLUDE_DIRS):
                continue
            # check dir itself
            try:
                st = os.lstat(dirpath)
                mode = st.st_mode
                if bool(mode & stat.S_IWOTH) or (mode & 0o777) == 0o777:
                    findings.append({"path": dirpath, "mode": oct(mode & 0o7777)})
            except Exception:
                pass
            for fname in filenames:
                full = os.path.join(dirpath, fname)
                try:
                    st = os.lstat(full)
                    mode = st.st_mode
                    if bool(mode & stat.S_IWOTH) or (mode & 0o777) == 0o777:
                        findings.append({"path": full, "mode": oct(mode & 0o7777)})
                except Exception:
                    continue
    return findings

def find_setuid_sgid(search_roots, fast=False, deep=False):
    findings = []
    max_visit = 200000 if deep else (20000 if not fast else 5000)
    visited = 0
    for root in search_roots:
        if not os.path.exists(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            visited += 1
            if visited > max_visit:
                return findings
            if any(dirpath.startswith(x) for x in EXCLUDE_DIRS):
                continue
            for fname in filenames:
                full = os.path.join(dirpath, fname)
                try:
                    st = os.lstat(full)
                    mode = st.st_mode
                    if bool(mode & stat.S_ISUID) or bool(mode & stat.S_ISGID):
                        findings.append({"path": full, "mode": oct(mode & 0o7777)})
                except Exception:
                    continue
    return findings

def check_network_indicators():
    """Quick /proc/net inspection for listening ports and unix sockets."""
    info = {"tcp_listen": [], "udp_listen": [], "unix_sockets": []}
    try:
        tcp_txt, _ = safe_read("/proc/net/tcp", max_bytes=20000)
        udp_txt, _ = safe_read("/proc/net/udp", max_bytes=20000)
        unix_txt, _ = safe_read("/proc/net/unix", max_bytes=20000)
        info["tcp_raw"] = tcp_txt
        info["udp_raw"] = udp_txt
        info["unix_raw"] = unix_txt
        # basic parsing: find lines with LISTEN
        if tcp_txt:
            for line in tcp_txt.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    local_hex = parts[1]
                    state = parts[3]
                    # state '0A' == LISTEN
                    if state.upper() == "0A":
                        info["tcp_listen"].append(line.strip())
        if udp_txt:
            for line in udp_txt.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    info["udp_listen"].append(line.strip())
        if unix_txt:
            for line in unix_txt.splitlines()[1:]:
                info["unix_sockets"].append(line.strip())
    except Exception:
        pass
    return info

def find_sensitive_names(search_roots, fast=False):
    """Find files with names that look like keys, credentials, tokens, backups, databases, logs."""
    found = []
    max_visit = 200000 if not fast else 20000
    visited = 0
    for root in search_roots:
        if not os.path.exists(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            visited += 1
            if visited > max_visit:
                return found
            if any(dirpath.startswith(x) for x in EXCLUDE_DIRS):
                continue
            for fname in filenames:
                low = fname.lower()
                if any(pat in low for pat in CRED_FILENAME_PATTERNS):
                    found.append(os.path.join(dirpath, fname))
            if fast and len(found) > 200:
                return found
    return found

def scan_apks_for_risky_strings(apk_list, max_bytes=300000):
    """Best-effort: scan APK file bytes for known dangerous permission strings or URLs. Non-parsing approach."""
    risky = []
    risky_keywords = [
        "android.permission.READ_SMS", "android.permission.SEND_SMS",
        "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
        "android.permission.RECORD_AUDIO", "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_SECURE_SETTINGS", "android.permission.SYSTEM_ALERT_WINDOW",
        "http://", "https://", "tel:", "su", "magisk", "frida", "xposed", "keylog", "hook"
    ]
    for apk in apk_list:
        path = apk.get("path")
        entry = {"path": path, "hits": []}
        try:
            with open(path, "rb") as f:
                data = f.read(max_bytes)
                lower = data.decode("latin-1", errors="replace").lower()
                for kw in risky_keywords:
                    if kw.lower() in lower:
                        entry["hits"].append(kw)
        except Exception as e:
            entry["error"] = str(e)
        if entry.get("hits"):
            risky.append(entry)
    return risky

# --------------- Snapshot / baseline / compare ---------------

def snapshot_all(args):
    snap = {
        "generated_at": now_ts(),
        "report_version": REPORT_VERSION,
        "paths": check_paths(WATCH_PATHS),
        "selinux": check_selinux(),
        "iptables": gather_iptables(),
        "processes": list_processes(sample_limit=1000 if args.deep else 400),
        "suspicious_bins": find_suspicious_binaries(SEARCH_ROOTS, fast=args.fast, deep=args.deep),
        "su_hits": check_common_su_locations(),
        "ldenv": check_ld_preload_and_env(),
        "packages_xml": parse_packages_xml("/data/system/packages.xml"),
        "init_scripts": scan_init_scripts(["/system/etc/init", "/system/etc/init.d", "/vendor/etc/init"]),
        "keylogger_indicators": detect_keylogger_indicators(SEARCH_ROOTS, fast=args.fast),
        "world_writable": find_world_writable_and_777(SEARCH_ROOTS, fast=args.fast, deep=args.deep),
        "setuid_sgid": find_setuid_sgid(SEARCH_ROOTS, fast=args.fast, deep=args.deep),
        "network": check_network_indicators(),
        "sensitive_names": find_sensitive_names(SEARCH_ROOTS, fast=args.fast),
    }
    # extra: scan APK contents for risky strings (best-effort)
    try:
        apks = snap["suspicious_bins"].get("apks", [])
        snap["apk_risky_hits"] = scan_apks_for_risky_strings(apks[:500])
    except Exception:
        snap["apk_risky_hits_err"] = "apk scan failed"
    return snap

def compare_baseline(old, new):
    diffs = {"files_added": [], "files_removed": [], "files_changed": []}
    old_paths = set(old.get("paths", {}).keys())
    new_paths = set(new.get("paths", {}).keys())
    for p in sorted(new_paths - old_paths):
        diffs["files_added"].append(p)
    for p in sorted(old_paths - new_paths):
        diffs["files_removed"].append(p)
    for p in sorted(old_paths & new_paths):
        oldh = old["paths"][p].get("sha256")
        newh = new["paths"][p].get("sha256")
        if oldh and newh and oldh != newh:
            diffs["files_changed"].append({"path": p, "old": oldh, "new": newh})
        old_exist = old["paths"][p].get("exists")
        new_exist = new["paths"][p].get("exists")
        if old_exist != new_exist:
            diffs.setdefault("existence_changes", []).append({"path": p, "old": old_exist, "new": new_exist})
    # quick suspicious counts
    diffs["suspicious_bins_count_old"] = len(old.get("suspicious_bins", {}).get("bins", []))
    diffs["suspicious_bins_count_new"] = len(new.get("suspicious_bins", {}).get("bins", []))
    diffs["apks_count_old"] = len(old.get("suspicious_bins", {}).get("apks", []))
    diffs["apks_count_new"] = len(new.get("suspicious_bins", {}).get("apks", []))
    return diffs

# ---------------- Human text report with emojis ----------------

def short_path(p, maxlen=80):
    if not p:
        return ""
    if len(p) <= maxlen:
        return p
    return "..." + p[-(maxlen-3):]

def produce_text_report(snap, baseline_diff=None, quiet=False):
    lines = []
    lines.append("🔎 Android Host Hardener — Pro Max Ultimate (read-only)")
    lines.append("Generated: " + snap.get("generated_at", "unknown"))
    lines.append("Report version: " + snap.get("report_version", "unknown"))
    lines.append("")

    # SELinux
    lines.append(f"{EMOJI['selinux']} SELinux:")
    s = snap.get("selinux", {})
    lines.append(f"  enforce file: {s.get('enforce_file')} {EMOJI['ok'] if s.get('getenforce','').lower().startswith('en') else EMOJI['error']}")
    lines.append(f"  getenforce: {s.get('getenforce', s.get('getenforce_err'))}")
    lines.append("")

    # Important paths checked
    lines.append("🗂 Important paths (existence and sha256 where readable):")
    for p, info in snap.get("paths", {}).items():
        lines.append(" - {} : exists={} size={} sha256={}".format(
            p,
            info.get("exists"),
            info.get("stat", {}).get("size", "?"),
            info.get("sha256", "n/a")
        ))
    lines.append("")

    # Network rules
    lines.append(f"{EMOJI['network']} Network & firewall summary:")
    ipt = snap.get("iptables", {})
    if "iptables-save" in ipt:
        lines.append(f"  iptables-save: present ({len(ipt['iptables-save'])} bytes)")
    else:
        lines.append(f"  iptables-save: not available ({ipt.get('iptables-save_err')})")
    if "nft_ruleset" in ipt:
        lines.append(f"  nft ruleset: present ({len(ipt['nft_ruleset'])} bytes)")
    else:
        lines.append(f"  nft: not available ({ipt.get('nft_ruleset_err')})")
    lines.append("  Listening TCP entries (sample):")
    for t in (snap.get("network", {}).get("tcp_listen") or [])[:20]:
        lines.append(f"   - {short_path(t,120)} {EMOJI['socket']}")
    lines.append("")

    # Processes
    proc = snap.get("processes", {})
    lines.append(f"🖥️ Processes scanned: {proc.get('count')} (suspicious heuristics shown)")
    for sproc in proc.get("suspicious", [])[:40]:
        tag = EMOJI['suspicious_bin']
        lines.append(f"  - PID {sproc.get('pid')}: cmd='{short_path(sproc.get('cmdline'), 120)}' exe='{short_path(sproc.get('exe'),80)}' {tag}")
    lines.append("")

    # Suspicious binaries & libraries
    sb = snap.get("suspicious_bins", {})
    lines.append(f"{EMOJI['suspicious_bin']} Suspicious binaries found: {len(sb.get('bins', []))}")
    for b in sb.get("bins", [])[:80]:
        lines.append(f"  - {b.get('path')} {EMOJI['root'] if any(x in b.get('path','').lower() for x in ['magisk','su','supersu']) else EMOJI['suspicious_bin']}")
    lines.append(f"{EMOJI['apk']} APK files scanned: {len(sb.get('apks', []))}")
    for a in sb.get("apks", [])[:60]:
        lines.append(f"  - {short_path(a.get('path'))} {EMOJI['apk']}")
    lines.append(f"{EMOJI['hidden']} Hidden files found (leading dot): {len(sb.get('hidden', []))}")
    for h in sb.get("hidden", [])[:40]:
        lines.append(f"  - {h} {EMOJI['hidden']}")
    lines.append("")

    # APK risky hits
    apk_hits = snap.get("apk_risky_hits", [])
    lines.append(f"{EMOJI['apk']} APK risky string hits: {len(apk_hits)}")
    for hit in apk_hits[:50]:
        lines.append(f"  - {short_path(hit.get('path'))} hits={hit.get('hits')}")
    lines.append("")

    # Keylogger indicators
    klog = snap.get("keylogger_indicators", [])
    lines.append(f"{EMOJI['keylogger']} Keylogger/spy indicators (names): {len(klog)}")
    for k in klog[:80]:
        lines.append(f"  - {k} {EMOJI['keylogger']}")
    lines.append("")

    # World-writable / 0777
    ww = snap.get("world_writable", [])
    lines.append(f"{EMOJI['writable']} World-writable / 0777 files and dirs: {len(ww)}")
    for w in ww[:80]:
        lines.append(f"  - {w.get('path')} mode={w.get('mode')} {EMOJI['writable']}")
    lines.append("")

    # SUID/SGID
    suid = snap.get("setuid_sgid", [])
    lines.append(f"{EMOJI['suspicious_bin']} Files with SUID/SGID bits: {len(suid)}")
    for s in suid[:60]:
        lines.append(f"  - {s.get('path')} mode={s.get('mode')} {EMOJI['suspicious_bin']}")
    lines.append("")

    # Sensitive filenames
    sens = snap.get("sensitive_names", [])
    lines.append(f"{EMOJI['credentials']} Files with credential-like names: {len(sens)}")
    for s in sens[:80]:
        lines.append(f"  - {s} {EMOJI['credentials']}")
    lines.append("")

    # su/magisk hits
    suhits = snap.get("su_hits", [])
    lines.append(f"{EMOJI['root']} Common 'su' / magisk hits: {len(suhits)}")
    for s in suhits:
        lines.append(f"  - {s.get('path')} mode={s.get('stat',{}).get('mode')} {EMOJI['root']}")
    lines.append("")

    # LD env hits
    ldenv = snap.get("ldenv", {})
    lines.append(f"🧩 LD env / preload hits: {len(ldenv.get('proc_env_hits', []))} processes show suspicious LD envs")
    for e in ldenv.get("proc_env_hits", [])[:60]:
        lines.append(f"  - PID {e.get('pid')}: {short_path(e.get('env_sample'))} {EMOJI['suspicious_bin']}")
    if ldenv.get("ld.so.preload"):
        lines.append(f"  - /etc/ld.so.preload content present {EMOJI['suspicious_bin']}")
    lines.append("")

    # Baseline diff summary
    if baseline_diff:
        lines.append("📊 Baseline comparison summary:")
        lines.append(json.dumps(baseline_diff, indent=2))
    lines.append("")
    lines.append("⚠️ Note: This is heuristic and read-only. Investigate flagged items manually and with other tools (adb, apksigner, /system analysis).")
    return "\n".join(lines)

# ---------------- CLI / main ----------------

def main():
    parser = argparse.ArgumentParser(description="Pro Max Ultimate read-only Android Host Hardener scanner.")
    parser.add_argument("--output", "-o", help="Save JSON report to FILE", metavar="FILE")
    parser.add_argument("--save-baseline", help="Save current snapshot as baseline to FILE", metavar="FILE")
    parser.add_argument("--compare-baseline", help="Compare current snapshot to baseline FILE", metavar="FILE")
    parser.add_argument("--quiet", action="store_true", help="Minimal console output; useful when piping JSON")
    parser.add_argument("--fast", action="store_true", help="Faster scan, skip deeper traversal")
    parser.add_argument("--deep", action="store_true", help="Deeper, slower scan with more coverage")
    args = parser.parse_args()

    # Basic root check
    euid = os.geteuid() if hasattr(os, "geteuid") else 0
    if euid != 0:
        print("WARNING: This script is intended to run as root to read protected paths. Some checks may fail.", file=sys.stderr)

    start = time.time()
    snap = snapshot_all(args)
    elapsed = time.time() - start
    snap["scan_elapsed_seconds"] = elapsed

    baseline_diff = None
    if args.compare_baseline:
        try:
            with open(args.compare_baseline, "r") as f:
                old = json.load(f)
            baseline_diff = compare_baseline(old, snap)
        except Exception as e:
            baseline_diff = {"error": f"failed to load baseline: {e}"}

    if args.save_baseline:
        try:
            with open(args.save_baseline, "w") as f:
                json.dump(snap, f, indent=2)
        except Exception as e:
            print("Failed to save baseline: {}".format(e), file=sys.stderr)

    output_obj = {"snapshot": snap, "baseline_diff": baseline_diff}

    if args.output:
        try:
            with open(args.output, "w") as f:
                json.dump(output_obj, f, indent=2)
            if not args.quiet:
                print("Saved JSON report to", args.output)
        except Exception as e:
            print("Failed to write output file: {}".format(e), file=sys.stderr)

    if args.quiet and not args.output:
        print(json.dumps(output_obj))
        return

    report = produce_text_report(snap, baseline_diff)
    print(report)

if __name__ == "__main__":
    main()
    #As the creator and coder behind this program, I, Nyxeara, have designed this system with a singular purpose: to empower devices with the strongest possible defense against threats, intrusions, and unauthorized access. Every line of code reflects precision, resilience, and security-first thinking.

#This program is not just software—it is a shield, built to protect, monitor, and safeguard against anything that could compromise your digital world. My commitment is to ensure that every user benefits from unmatched protection, with technology working silently and efficiently in the background.

#Security is no longer optional—it is a necessity. With this program, your devices are not just defended; they are fortified."_

#  — Nyxeara, Coder & Cybersecurity Architect.