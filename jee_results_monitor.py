# -*- coding: utf-8 -*-
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Clean logs by disabling the unverified certificate thing
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

"""
JEE Main 2026 Session 1 — Results Monitor  (v2 — structural fingerprinting)
=============================================================================
Monitors the NTA score-card login page and alerts the moment the page
structure changes — signalling that results are likely live.

Why structural fingerprinting?
  The login page contains a dynamic CAPTCHA & session token that change on
  every request, making a naive full-page hash useless (constant false
  positives).  Instead we extract only the *skeleton* of the page — scripts,
  stylesheets, form structure, headings, links, title — and hash that.
  When NTA deploys the results, the skeleton will change.

Detection layers:
  1. Structural hash of the HTML skeleton
  2. Form action URL changes
  3. New/removed JS & CSS assets
  4. New links (e.g. "Download Score Card")
  5. Page <title> change
  6. POST probe — test whether a dummy login still redirects to
     /ErrorPage/CustomError  (when results go live, the redirect target
     or response will change)

Anti-false-alarm:
  • Each layer produces a confidence score  (0-100)
  • Alert fires only when  cumulative_score ≥ 60  AND  ≥ 2 layers triggered
  • Change must persist across 3 consecutive checks (spaced 10 s apart)
  • 5 min cooldown between alert bursts

Usage:
    python jee_results_monitor.py                 # default 300 s interval
    python jee_results_monitor.py --interval 15   # every 15 s
    python jee_results_monitor.py --no-sound       # silent mode
    python jee_results_monitor.py --test           # one-shot stability test
"""

import os
os.environ['PYGAME_HIDE_SUPPORT_PROMPT'] = '1'

import argparse
import hashlib
import time
import datetime
import json
import random
import re
import ctypes
import pygame
import tkinter as tk
import requests
import ssl
from http.client import HTTPSConnection
from urllib.parse import urlencode

# ── Configuration ──────────────────────────────────────────────────────
LOGIN_URL  = "https://cnr.nic.in/results26/JEEMAIN2026S1P1/Login"
LOGIN_PATH = "/results26/JEEMAIN2026S1P1/Login"
ERROR_PATH = "/Results26/ErrorPage/CustomError"
BASE_HOST  = "cnr.nic.in"

LOG_FILE   = "jee_monitor_log.jsonl"
STATE_FILE = "jee_monitor_state.json"
ALARM_FILE = "alarm.mp3"

# How many consecutive "change detected" checks are required before alert
CONFIRMATION_THRESHOLD = 3
# Seconds between rapid confirmation re-checks
CONFIRMATION_INTERVAL  = 60
# Minimum seconds between alert bursts
ALERT_COOLDOWN_SECS    = 300

# ── HTTP helper ────────────────────────────────────────────────────────

def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,*/*",
    "Accept-Language": "en-US,en;q=0.9",
}


# This object acts like a browser tab, keeping cookies alive
session = requests.Session()
session.headers.update(_HEADERS)

def http_get(path, host=BASE_HOST):
    url = f"https://{host}{path}"
    try:
        # allow_redirects=False so we can detect if NTA 
        # is trying to send us to an error page (302 redirect)
        resp = session.get(url, timeout=20, allow_redirects=False, verify=False)
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        return resp.status_code, hdrs, resp.text
    except Exception as e:
        return None, {}, str(e)

def http_post(path, form_data, host=BASE_HOST):
    """Sends POST data using the cookies from the previous GET"""
    url = f"https://{host}{path}"
    try:
        resp = session.post(url, data=form_data, timeout=20, allow_redirects=False, verify=False)
        rhdrs = {k.lower(): v for k, v in resp.headers.items()}
        return resp.status_code, rhdrs, resp.text
    except Exception as e:
        return None, {}, str(e)


def get_response_signature(url):
    try:
        r = requests.get(url, timeout=15, allow_redirects=True)
        body = r.content
        return {
            "status": r.status_code,
            "length": len(body),
            "hash": hashlib.sha256(body).hexdigest(),
            "final_url": r.url
        }
    except Exception as e:
        return {"error": str(e)}

# ── Logging / alerts ──────────────────────────────────────────────────

def timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log(msg, level="INFO"):
    ts = timestamp()
    line = f"[{ts}] [{level}] {msg}"
    try:
        print(line, flush=True)
    except UnicodeEncodeError:
        print(line.encode("ascii", errors="replace").decode("ascii"))
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": ts, "level": level, "msg": msg}) + "\n")


def alert_user(message, sound_enabled=True):
    log(f"ALERT >>> {message}", "ALERT")

    pygame.mixer.init()
    pygame.mixer.music.load(ALARM_FILE)
    pygame.mixer.music.set_volume(1.0)   # max volume
    pygame.mixer.music.play(loops=-1)     # -1 = loop forever

    # Keep the program running while playing
    try:
        while pygame.mixer.music.get_busy():
            time.sleep(1)
    except KeyboardInterrupt:
        pygame.mixer.music.stop()
    root = tk.Tk()
    root.attributes("-fullscreen", True)
    root.configure(bg="black")

    msg = f"JEE MAIN 2026 RESULTS PAGE CHANGED!\n\n{message}"

    label = tk.Label(root,
                     text=msg,
                     fg="red",
                     bg="black",
                     font=("Arial", 48, "bold"),
                     justify="center")
    label.pack(expand=True)

    root.mainloop()

# ── Structural fingerprinting ─────────────────────────────────────────

# Regex helpers (compiled once)
_RE_TITLE      = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_RE_SCRIPT_SRC = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', re.I)
_RE_LINK_HREF  = re.compile(r'<link[^>]+href\s*=\s*["\']([^"\']+)["\']', re.I)
_RE_FORM       = re.compile(r"<form\b([^>]*)>", re.I)
_RE_FORM_ACTION = re.compile(r'action\s*=\s*["\']([^"\']*)["\']', re.I)
_RE_INPUT_NAME = re.compile(r'<input[^>]+name\s*=\s*["\']([^"\']+)["\']', re.I)
_RE_HEADING    = re.compile(r"<h([1-6])[^>]*>(.*?)</h\1>", re.I | re.S)
_RE_ANCHOR     = re.compile(r'<a\b[^>]*href\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.I | re.S)

# Volatile patterns to strip from input names
_VOLATILE_INPUTS = {"__requestverificationtoken", "captchacode", "captchavalue",
                    "captchainputtext", "captchaid", "captchatoken"}


def _strip_tags(html):
    """Minimal tag stripper for heading/anchor text."""
    return re.sub(r"<[^>]+>", "", html).strip()


def extract_skeleton(html):
    """
    Parse the HTML and return a dict of structural elements (the
    'skeleton').  Everything volatile (CAPTCHA, tokens) is excluded.
    """
    skeleton = {}

    # Title
    m = _RE_TITLE.search(html)
    skeleton["title"] = _strip_tags(m.group(1)).strip() if m else ""

    # Script sources
    skeleton["scripts"] = sorted(set(_RE_SCRIPT_SRC.findall(html)))

    # Stylesheet links (filter out non-CSS)
    all_links = _RE_LINK_HREF.findall(html)
    skeleton["stylesheets"] = sorted(set(
        l for l in all_links
        if l.endswith(".css") or "stylesheet" in html[max(0, html.lower().find(l)-80):html.lower().find(l)].lower()
    ))

    # Form structure
    forms = []
    for fm in _RE_FORM.finditer(html):
        form_tag = fm.group(1)
        action_m = _RE_FORM_ACTION.search(form_tag)
        action = action_m.group(1) if action_m else ""
        forms.append({"action": action})

    # Input names (excluding volatile ones)
    input_names = _RE_INPUT_NAME.findall(html)
    skeleton["input_names"] = sorted(set(
        n for n in input_names
        if n.lower() not in _VOLATILE_INPUTS
    ))

    skeleton["forms"] = forms

    # Headings
    headings = []
    for hm in _RE_HEADING.finditer(html):
        text = _strip_tags(hm.group(2)).strip()
        if text:
            headings.append(f"h{hm.group(1)}:{text}")
    skeleton["headings"] = headings

    # Anchors (skip javascript: hrefs and captcha-related)
    anchors = []
    for am in _RE_ANCHOR.finditer(html):
        href = am.group(1).strip()
        text = _strip_tags(am.group(2)).strip()
        if href.startswith("javascript:"):
            continue
        if "captcha" in href.lower() or "captcha" in text.lower():
            continue
        anchors.append({"href": href, "text": text})
    skeleton["anchors"] = anchors

    return skeleton


def skeleton_hash(skeleton):
    """Deterministic hash of the skeleton dict."""
    canonical = json.dumps(skeleton, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def skeleton_diff(old, new):
    """
    Compare two skeletons, return a list of human-readable diff strings.
    """
    diffs = []

    if old.get("title") != new.get("title"):
        diffs.append(f"Title: '{old.get('title')}' -> '{new.get('title')}'")

    for key in ("scripts", "stylesheets"):
        old_set = set(old.get(key, []))
        new_set = set(new.get(key, []))
        added   = new_set - old_set
        removed = old_set - new_set
        if added:
            diffs.append(f"{key} ADDED: {added}")
        if removed:
            diffs.append(f"{key} REMOVED: {removed}")

    old_inputs = set(old.get("input_names", []))
    new_inputs = set(new.get("input_names", []))
    if old_inputs != new_inputs:
        diffs.append(f"Input names changed: added={new_inputs - old_inputs}, removed={old_inputs - new_inputs}")

    old_forms = old.get("forms", [])
    new_forms = new.get("forms", [])
    if old_forms != new_forms:
        diffs.append(f"Forms changed: {old_forms} -> {new_forms}")

    if old.get("headings") != new.get("headings"):
        diffs.append(f"Headings changed: {old.get('headings')} -> {new.get('headings')}")

    old_anchors = set(json.dumps(a, sort_keys=True) for a in old.get("anchors", []))
    new_anchors = set(json.dumps(a, sort_keys=True) for a in new.get("anchors", []))
    if old_anchors != new_anchors:
        added   = new_anchors - old_anchors
        removed = old_anchors - new_anchors
        if added:
            diffs.append(f"Links ADDED: {added}")
        if removed:
            diffs.append(f"Links REMOVED: {removed}")

    return diffs

# ── Detection layers ──────────────────────────────────────────────────
def layer_forgot_password_link(baseline_skel, current_skel):
    """Layer 7: Detect change in 'Forgot Password' link target."""
    def find_href(skel):
        for a in skel.get("anchors", []):
            if "forgot" in a.get("text", "").lower() and "password" in a.get("text", "").lower():
                return a.get("href", "")
        return None

    old_href = find_href(baseline_skel)
    new_href = find_href(current_skel)

    if old_href != new_href:
        return 35, f"Forgot-password link changed: {old_href} -> {new_href}"
    return 0, "Forgot-password link unchanged"


def layer_structural_hash(baseline_skel, current_skel):
    """Layer 1: compare skeleton hashes."""
    bh = skeleton_hash(baseline_skel)
    ch = skeleton_hash(current_skel)
    if bh != ch:
        diffs = skeleton_diff(baseline_skel, current_skel)
        return 40, f"Structural hash changed ({bh} -> {ch}): {'; '.join(diffs)}"
    return 0, "Structural hash unchanged"


def layer_form_action(baseline_skel, current_skel):
    """Layer 2: form action URL changed."""
    bf = [f.get("action", "") for f in baseline_skel.get("forms", [])]
    cf = [f.get("action", "") for f in current_skel.get("forms", [])]
    if bf != cf:
        return 30, f"Form action changed: {bf} -> {cf}"
    return 0, "Form actions unchanged"


def layer_assets(baseline_skel, current_skel):
    """Layer 3: new or removed JS/CSS assets."""
    old_assets = set(baseline_skel.get("scripts", []) + baseline_skel.get("stylesheets", []))
    new_assets = set(current_skel.get("scripts", []) + current_skel.get("stylesheets", []))
    added   = new_assets - old_assets
    removed = old_assets - new_assets
    if added or removed:
        score = 25 if added else 15
        return score, f"Assets changed: +{added or '{}'} -{removed or '{}'}"
    return 0, "Assets unchanged"


def layer_links(baseline_skel, current_skel):
    """Layer 4: new links appeared (e.g. 'Download Score Card')."""
    old_hrefs = {a["href"] for a in baseline_skel.get("anchors", [])}
    new_hrefs = {a["href"] for a in current_skel.get("anchors", [])}
    added = new_hrefs - old_hrefs
    if added:
        # Check for result-related keywords in the new link text
        new_anchors = [a for a in current_skel.get("anchors", []) if a["href"] in added]
        result_keywords = ["score", "result", "download", "rank", "marks", "percentile"]
        has_result_link = any(
            any(kw in a.get("text", "").lower() for kw in result_keywords)
            for a in new_anchors
        )
        score = 35 if has_result_link else 15
        return score, f"New links: {[a for a in new_anchors]}"
    return 0, "Links unchanged"


def layer_title(baseline_skel, current_skel):
    """Layer 5: page title changed."""
    bt = baseline_skel.get("title", "")
    ct = current_skel.get("title", "")
    if bt != ct:
        return 20, f"Title changed: '{bt}' -> '{ct}'"
    return 0, "Title unchanged"

def layer_forgot_password_content(baseline_skel, current_skel, baseline_sig):
    """Layer 8: Detect content change in forgot-password target page."""

    def find_href(skel):
        for a in skel.get("anchors", []):
            t = a.get("text","").lower()
            if "forgot" in t and "password" in t:
                return a.get("href")
        return None

    href = find_href(current_skel)
    if not href:
        return 0, "Forgot-password link not found"

    current_sig = get_response_signature(href)

    if "error" in current_sig:
        return 10, f"Error fetching forgot page: {current_sig['error']}"

    if baseline_sig != current_sig:
        return 40, f"Forgot-password page changed: {baseline_sig} -> {current_sig}"

    return 0, "Forgot-password page unchanged"


def layer_post_probe(baseline_post_sig):
    """
    Layer 6: POST a dummy login form and check whether the error
    redirect behaviour has changed.
    baseline_post_sig = (status, redirect_location_contains_error)
    """
    dummy_data = {
        "ApplicationNumber": "000000000000",
        "Password": "dummyTest1!",
    }
    status, headers, body = http_post(LOGIN_PATH, dummy_data)

    if status is None:
        return 0, f"POST probe network error: {body}", (None, None)

    location = headers.get("location", "")
    is_error_redirect = (
        status in (301, 302, 303, 307, 308)
        and ("error" in location.lower() or "customerror" in location.lower())
    )
    # Also check if the body itself is the error page (inline serving)
    if not is_error_redirect and status == 200:
        is_error_redirect = "page session failed" in body.lower() or "custom error" in body.lower()

    current_sig = (status, is_error_redirect)

    if baseline_post_sig is None:
        # First run, just record
        return 0, f"POST baseline recorded: status={status}, error_redirect={is_error_redirect}", current_sig

    if current_sig != baseline_post_sig:
        # Behaviour changed!
        if not is_error_redirect and baseline_post_sig[1]:
            # Was error redirect, now it's NOT → strong signal
            return 35, f"POST probe: error redirect GONE (was {baseline_post_sig} now {current_sig})", current_sig
        else:
            return 15, f"POST probe behaviour changed: {baseline_post_sig} -> {current_sig}", current_sig

    return 0, f"POST probe unchanged: status={status}, error_redirect={is_error_redirect}", current_sig

# ── State management ──────────────────────────────────────────────────

def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    return {
        "check_count": 0,
        "first_check": None,
        "baseline_skeleton": None,
        "baseline_hash": None,
        "baseline_post_sig": None,
        "baseline_fp_sig": None,  #save to json
        "consecutive_detections": 0,
        "last_alert_time": None,
    }

def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

# ── Core check ────────────────────────────────────────────────────────

def run_check(state, sound_enabled=True):
    """
    Single check cycle.  Returns True if a confirmed alert was fired.
    """
    state["check_count"] += 1
    if not state["first_check"]:
        state["first_check"] = timestamp()

    n = state["check_count"]
    log(f"--- Check #{n} ---")

    # 1) Fetch the login page
    status, headers, body = http_get(LOGIN_PATH)
    if status is None:
        log(f"Network error: {body}", "ERROR")
        save_state(state)
        return False

    log(f"HTTP {status} | Body: {len(body)} chars")

    # If we got a redirect itself (not just the page), follow it once to
    # see what the target looks like
    if status in (301, 302, 303, 307, 308):
        location = headers.get("location", "")
        log(f"Redirect -> {location}")
        if "error" in location.lower() or "customerror" in location.lower():
            log("Login page itself redirects to error — results NOT out", "INFO")
            state["consecutive_detections"] = 0
            save_state(state)
            return False
        else:
            log(f"Unexpected redirect target: {location}", "WARN")

    # 2) Extract skeleton
    current_skel = extract_skeleton(body)
    current_hash = skeleton_hash(current_skel)
    

    # 3) Baseline handling
    if state["baseline_skeleton"] is None:
        log(f"First run — capturing baseline (hash: {current_hash})")
        state["baseline_skeleton"] = current_skel
        state["baseline_hash"] = current_hash
        # Also capture POST baseline
        _, post_msg, post_sig = layer_post_probe(None)
        log(f"  {post_msg}")
        state["baseline_post_sig"] = list(post_sig) if post_sig else None
        save_state(state)
        return False

    baseline_skel = state["baseline_skeleton"]


    # 4) Run all detection layers
    layers = []

    score1, msg1 = layer_structural_hash(baseline_skel, current_skel)
    layers.append(("StructuralHash", score1, msg1))

    score2, msg2 = layer_form_action(baseline_skel, current_skel)
    layers.append(("FormAction", score2, msg2))

    score3, msg3 = layer_assets(baseline_skel, current_skel)
    layers.append(("Assets", score3, msg3))

    score4, msg4 = layer_links(baseline_skel, current_skel)
    layers.append(("Links", score4, msg4))

    score5, msg5 = layer_title(baseline_skel, current_skel)
    layers.append(("Title", score5, msg5))

    post_baseline = tuple(state["baseline_post_sig"]) if state.get("baseline_post_sig") else None
    score6, msg6, new_post_sig = layer_post_probe(post_baseline)
    layers.append(("PostProbe", score6, msg6))
    score7, msg7 = layer_forgot_password_link(baseline_skel, current_skel)
    layers.append(("ForgotLink", score7, msg7))
    score8, msg8 = layer_forgot_password_content(
            baseline_skel,
            current_skel,
            state.get("baseline_fp_sig") #FIX: Use the permanent JSON memory
        )
    layers.append(("ForgotPage", score8, msg8))



    # Log each layer
    for name, score, msg in layers:
        level = "CHANGE" if score > 0 else "INFO"
        log(f"  [{name}] score={score:3d} | {msg}", level)

    total_score = sum(s for _, s, _ in layers)
    triggered   = sum(1 for _, s, _ in layers if s > 0)

    log(f"  Total confidence: {total_score}/100 | Layers triggered: {triggered}/8")


    # 5) Decision
    is_change = total_score >= 60 and triggered >= 2

    if is_change:
        state["consecutive_detections"] += 1
        log(f"  CHANGE DETECTED — consecutive count: {state['consecutive_detections']}/{CONFIRMATION_THRESHOLD}", "WARN")
    else:
        if state["consecutive_detections"] > 0:
            log(f"  Change NOT confirmed — resetting consecutive count from {state['consecutive_detections']}")
        state["consecutive_detections"] = 0

    # 6) Fire alert only after consecutive threshold
    if state["consecutive_detections"] >= CONFIRMATION_THRESHOLD:
        # Cooldown check
        last_alert = state.get("last_alert_time")
        now = time.time()
        if last_alert and (now - last_alert) < ALERT_COOLDOWN_SECS:
            remaining = int(ALERT_COOLDOWN_SECS - (now - last_alert))
            log(f"  Alert suppressed (cooldown: {remaining}s remaining)", "INFO")
        else:
            state["last_alert_time"] = now
            diffs = skeleton_diff(baseline_skel, current_skel)
            detail = "; ".join(diffs) if diffs else "POST behaviour changed"
            msg = f"JEE MAIN 2026 RESULTS PAGE CHANGED! ({detail})  >>> {LOGIN_URL}"
            alert_user(msg, sound_enabled)
            save_state(state)
            return True

    save_state(state)
    return False

# ── Test mode ─────────────────────────────────────────────────────────

def run_test():
    """
    One-shot test: fetch the page 3 times rapidly, show the extracted
    skeleton each time, and verify the hash is stable (proving volatile
    content is properly stripped).
    """
    print("=" * 65)
    print("  JEE Results Monitor — Stability Test")
    print("=" * 65)
    print()

    hashes = []
    for i in range(3):
        print(f"--- Fetch #{i+1} ---")
        status, headers, body = http_get(LOGIN_PATH)
        if status is None:
            print(f"  NETWORK ERROR: {body}")
            hashes.append(None)
            continue

        print(f"  HTTP {status} | Body: {len(body)} chars")

        if status in (301, 302, 303, 307, 308):
            loc = headers.get("location", "")
            print(f"  Redirect -> {loc}")
            if "error" in loc.lower():
                print("  (error redirect — this is the pre-results state)")
            continue

        skel = extract_skeleton(body)
        h = skeleton_hash(skel)
        hashes.append(h)

        print(f"  Title      : {skel['title']}")
        print(f"  Scripts    : {skel['scripts']}")
        print(f"  Stylesheets: {skel['stylesheets']}")
        print(f"  Forms      : {skel['forms']}")
        print(f"  Inputs     : {skel['input_names']}")
        print(f"  Headings   : {skel['headings']}")
        print(f"  Anchors    : {skel['anchors']}")
        print(f"  Skel hash  : {h}")
        print()

        if i < 2:
            time.sleep(2)

    # POST probe
    print("--- POST probe ---")
    dummy_data = {"ApplicationNumber": "000000000000", "Password": "dummyTest1!"}
    status, headers, body = http_post(LOGIN_PATH, dummy_data)
    if status is None:
        print(f"  NETWORK ERROR: {body}")
    else:
        location = headers.get("location", "")
        print(f"  HTTP {status} | Location: {location or '(none)'}")
        is_error = "error" in location.lower() or "customerror" in location.lower()
        if not is_error and status == 200:
            is_error = "page session failed" in body.lower() or "custom error" in body.lower()
        print(f"  Error redirect: {is_error}")
    print()

    # Stability verdict
    valid = [h for h in hashes if h is not None]
    if len(valid) >= 2 and len(set(valid)) == 1:
        print("RESULT: STABLE — hash is consistent across fetches.")
        print(f"        Skeleton hash: {valid[0]}")
        print("        Volatile content (CAPTCHA/tokens) correctly stripped.")
    elif len(valid) >= 2:
        print("WARNING: UNSTABLE — hash differs between fetches!")
        print(f"         Hashes: {valid}")
        print("         There may be additional volatile elements to filter.")
    else:
        print("WARNING: Could not fetch enough pages to verify stability.")


# ── Main ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Monitor JEE Main 2026 results page (v2 — structural fingerprinting)"
    )
    parser.add_argument(
        "--interval", type=int, default=300,
        help="Seconds between checks (default: 300)"
    )
    parser.add_argument(
        "--no-sound", action="store_true",
        help="Disable sound alerts"
    )
    parser.add_argument(
        "--test", action="store_true",
        help="One-shot stability test (fetch 3x, compare skeletons)"
    )
    parser.add_argument(
        "--reset", action="store_true",
        help="Delete saved state and start fresh"
    )
    args = parser.parse_args()

    if args.test:
        run_test()
        return

    if args.reset:
        for f in (STATE_FILE, LOG_FILE):
            if os.path.exists(f):
                os.remove(f)
                print(f"Deleted {f}")
        print("State reset. Run again without --reset to start monitoring.")
        return

    sound_enabled = not args.no_sound

    print("=" * 65)
    print("  JEE Main 2026 Session 1 — Results Monitor  v2")
    print(f"  Interval: {args.interval}s | Sound: {'ON' if sound_enabled else 'OFF'}")
    print(f"  Target : {LOGIN_URL}")
    print(f"  Log    : {os.path.abspath(LOG_FILE)}")
    print(f"  Anti-false-alarm: {CONFIRMATION_THRESHOLD} consecutive confirms required")
    print("=" * 65)
    print()

    state = load_state()

    # Clear old state from v1 if present
    if "last_hash" in state or "results_detected" in state:
        log("Detected v1 state file — resetting for v2", "WARN")
        state = load_state.__wrapped__() if hasattr(load_state, '__wrapped__') else {
            "check_count": 0,
            "first_check": None,
            "baseline_skeleton": None,
            "baseline_hash": None,
            "baseline_post_sig": None,
            "consecutive_detections": 0,
            "last_alert_time": None,
        }

    try:
        while True:
            detected = run_check(state, sound_enabled)
            if detected:
                log("Alert fired. Continuing to monitor...")
            print()
            jitter = random.uniform(-30, 30)
            time.sleep(max(1, args.interval + jitter))
    except KeyboardInterrupt:
        log("Monitor stopped by user.")
        print(f"\nStopped. Total checks: {state['check_count']}")


if __name__ == "__main__":
    main()

