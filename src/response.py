#!/usr/bin/env python3
# src/response.py
"""
Safe Response / Kill module.

- By default DRY_RUN = True (no real kills). Use loader.py --auto-kill to enable real kills.
- All actions are logged to logs/actions.log.
"""

import os
import time
import signal
from datetime import datetime

LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "logs"))
os.makedirs(LOG_DIR, exist_ok=True)
ACTIONS_LOG = os.path.join(LOG_DIR, "actions.log")
open(ACTIONS_LOG, "a").close()

# Safety defaults
DRY_RUN = True      # If True -> only log, don't actually kill
AUTO_KILL = False   # if True and DRY_RUN False -> perform real kills
MAX_KILLS_PER_MINUTE = 5

# Whitelist common system names / root UID
_WHITELIST_COMM = {"systemd", "init", "sshd", "bash", "code", "gnome-shell", "python3"}
_WHITELIST_UID = {0}

_kill_history = []  # timestamps of kills (for rate limiting)


def _log(msg: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    try:
        with open(ACTIONS_LOG, "a") as f:
            f.write(line + "\n")
            f.flush()
    except Exception as e:
        print("[response._log] failed to write actions.log:", e)


def enable_auto_kill():
    """Enable actual kill behavior (use only in disposable VM)."""
    global AUTO_KILL, DRY_RUN
    AUTO_KILL = True
    DRY_RUN = False
    _log("AUTO_KILL enabled: REAL kills WILL be performed. Use only in disposable VM!")


def disable_auto_kill():
    global AUTO_KILL, DRY_RUN
    AUTO_KILL = False
    DRY_RUN = True
    _log("AUTO_KILL disabled: DRY_RUN mode (no real kills).")


def _rate_ok():
    now = time.time()
    cutoff = now - 60
    while _kill_history and _kill_history[0] < cutoff:
        _kill_history.pop(0)
    return len(_kill_history) < MAX_KILLS_PER_MINUTE


def _record_kill():
    _kill_history.append(time.time())


def _proc_info(pid):
    """Return (exists, comm, uid) using /proc (no psutil required)."""
    try:
        with open(f"/proc/{pid}/comm", "r") as f:
            comm = f.read().strip()
        uid = None
        with open(f"/proc/{pid}/status", "r") as f:
            for line in f:
                if line.startswith("Uid:"):
                    uid = int(line.split()[1])
                    break
        return True, comm, uid
    except Exception:
        return False, None, None


def _is_whitelisted(comm, uid):
    if comm and comm in _WHITELIST_COMM:
        return True
    if uid is not None and uid in _WHITELIST_UID:
        return True
    return False


def kill_process(pid: int, reason: str = "detected by ransomware detector"):
    """
    Attempt to kill PID. Behavior:
    - If DRY_RUN True: log that we WOULD kill and return True (recorded).
    - If AUTO_KILL True and rate-limit ok & not whitelisted: attempt SIGTERM then SIGKILL.
    Returns True if action logged/taken, False otherwise.
    """
    exists, comm, uid = _proc_info(pid)
    if not exists:
        _log(f"[ACTION] PID {pid} not present (skip). Reason: {reason}")
        return False

    if _is_whitelisted(comm, uid):
        _log(f"[ACTION] PID {pid} ({comm}) is whitelisted (uid={uid}) — not killed. Reason: {reason}")
        return False

    if not _rate_ok():
        _log(f"[ACTION] Rate limit hit — skipping kill for PID {pid} ({comm}).")
        return False

    # Dry-run path: just log
    if DRY_RUN or not AUTO_KILL:
        _log(f"[DRY_RUN] would kill PID {pid} ({comm}) uid={uid} — reason: {reason}")
        return True

    # Real kill flow
    try:
        os.kill(pid, signal.SIGTERM)
        _log(f"[KILL] SIGTERM sent to PID {pid} ({comm}). Waiting up to 3s...")
    except PermissionError:
        _log(f"[ERROR] Permission denied sending SIGTERM to PID {pid} ({comm}).")
        return False
    except ProcessLookupError:
        _log(f"[INFO] PID {pid} disappeared before kill.")
        return False
    except Exception as e:
        _log(f"[ERROR] SIGTERM error for PID {pid}: {e}")
        return False

    # wait up to ~3s
    for _ in range(6):
        time.sleep(0.5)
        exists2, _, _ = _proc_info(pid)
        if not exists2:
            _log(f"[KILL] PID {pid} ({comm}) terminated after SIGTERM.")
            _record_kill()
            return True

    # force kill
    try:
        os.kill(pid, signal.SIGKILL)
        _log(f"[KILL] SIGKILL sent to PID {pid} ({comm}).")
        _record_kill()
        return True
    except Exception as e:
        _log(f"[ERROR] Failed SIGKILL on PID {pid}: {e}")
        return False
