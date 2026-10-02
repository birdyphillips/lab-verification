#!/usr/bin/env python3
"""
Lab Network Verification Script — vCMTS & iCMTS
Stage 1: Ping all devices via jump server
Stage 2: Verify SSH connectivity to each device
Stage 3: Run full checks + pull running config

Usage:
    python Lab_verification_and_trouble_shooting.py [--device <alias|hostname>] [--debug]

    Aliases: apa, apc, ara, asa, cts, dtr

Requirements:
    pip install paramiko python-dotenv
"""

import argparse
import getpass
import logging
import os
import re
import socket
import sys
import time
import traceback
import urllib.error
import urllib.request

import paramiko
import paramiko.transport
import paramiko.rsakey
import paramiko.message
from dotenv import load_dotenv

# Re-register ssh-rsa — paramiko 5.x removed it
if "ssh-rsa" not in paramiko.transport.Transport._key_info:
    paramiko.transport.Transport._key_info["ssh-rsa"] = paramiko.rsakey.RSAKey

# Re-register curve25519-sha256 bare name — Erlang SSH uses it without @libssh.org suffix
try:
    _c25519 = paramiko.transport.Transport._kex_info.get("curve25519-sha256@libssh.org")
    if _c25519 and "curve25519-sha256" not in paramiko.transport.Transport._kex_info:
        paramiko.transport.Transport._kex_info["curve25519-sha256"] = _c25519
except Exception:
    pass

# Backport diffie-hellman-group14-sha1 — iCMTS E6000 only offers this + group1-sha1
try:
    from hashlib import sha1 as _sha1
    from paramiko.kex_group14 import KexGroup14SHA256 as _KexGroup14SHA256

    class KexGroup14SHA1(_KexGroup14SHA256):
        name      = "diffie-hellman-group14-sha1"
        hash_algo = staticmethod(_sha1)

    if "diffie-hellman-group14-sha1" not in paramiko.transport.Transport._kex_info:
        paramiko.transport.Transport._kex_info["diffie-hellman-group14-sha1"] = KexGroup14SHA1
except Exception:
    pass

# Patch _verify_key to accept ssh-rsa SHA-1 signatures and store host key
_orig_verify_key = paramiko.transport.Transport._verify_key
def _patched_verify_key(self, host_key, sig):
    try:
        return _orig_verify_key(self, host_key, sig)
    except Exception as e:
        if "ssh-rsa" in str(e) or "Signature verification" in str(e):
            # Store host key manually so get_remote_server_key() works
            try:
                msg      = paramiko.message.Message(host_key)
                key_type = msg.get_text()
                key_map  = paramiko.transport.Transport._key_info
                if key_type in key_map:
                    self.host_key = key_map[key_type](data=host_key)
            except Exception:
                pass
            return
        raise
paramiko.transport.Transport._verify_key = _patched_verify_key

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_DIR  = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, f"lab_verify_{time.strftime('%Y%m%d_%H%M%S')}.log")

log = logging.getLogger("lab_verify")
log.setLevel(logging.DEBUG)

_fmt = logging.Formatter("%(asctime)s  %(levelname)-8s  %(message)s",
                         datefmt="%Y-%m-%d %H:%M:%S")
_fh  = logging.FileHandler(LOG_FILE, encoding="utf-8")
_fh.setLevel(logging.DEBUG)
_fh.setFormatter(_fmt)

_ch = logging.StreamHandler(sys.stdout)
_ch.setLevel(logging.INFO)
_ch.setFormatter(logging.Formatter("%(message)s"))

log.addHandler(_fh)
log.addHandler(_ch)


def enable_paramiko_debug():
    pk = logging.getLogger("paramiko")
    pk.setLevel(logging.DEBUG)
    pk.addHandler(_fh)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
DISABLED_ALGORITHMS = {
    "kex": ["curve25519-sha256", "diffie-hellman-group1-sha1",
            "diffie-hellman-group14-sha1"]
}

load_dotenv()

JUMP_HOST  = os.getenv("JUMP_HOST", "")
JUMP_PORT  = 22
USERNAME   = os.getenv("JUMP_USER", "")
KEY_PATH   = os.path.expanduser(os.getenv("SSH_KEY_PATH", "~/.ssh/id_rsa"))
CONFIG_DIR     = os.path.join(os.path.dirname(__file__), "configs")
BASELINE_DIR   = os.path.join(os.path.dirname(__file__), "Baseline_Config")

# Mirrors shell aliases
ALIASES = {
    "apa": "apa01k1dccc",
    "apc": "apc01k1dccc",
    "ara": "ara01k1dccc",
    "asa": "asa01k1dccc",
    "cts": "cts01k1dccc",
    "dtr": "dtr01k1dccc",
}

DEVICES = {
    "apc01k1dccc": {
        "label": "vCMTS (apc)",
        "checks": [
            ("Running config", "show running-config"),
        ],
    },
    "apa01k1dccc": {
        "label": "APA Switch (apa)",
        "checks": [
            ("Interface status",       "show int desc"),
            ("Bundle-Ether1 (to ASA)", "show bundle Bundle-Ether1"),
            ("Bundle-Ether101 (N1)",   "show bundle Bundle-Ether101"),
            ("Bundle-Ether102 (N2)",   "show bundle Bundle-Ether102"),
            ("Bundle-Ether103 (N3)",   "show bundle Bundle-Ether103"),
            ("LLDP FH0/0/0/24",       "show lldp neighbors FourHundredGigE0/0/0/24"),
        ],
    },
    "ara01k1dccc": {
        "label": "ARA Switch (ara)",
        "checks": [
            ("Interface status",       "show int desc"),
            ("Bundle-Ether1 (to ASA)", "show bundle Bundle-Ether1"),
            ("LLDP Hu0/0/1/0",        "show lldp neighbors HundredGigE0/0/1/0"),
            ("LLDP Hu0/0/1/1",        "show lldp neighbors HundredGigE0/0/1/1"),
        ],
    },
    "asa01k1dccc": {
        "label": "ASA Switch (asa)",
        "checks": [
            ("Running config", "show running-config"),
        ],
    },
    "cts01k1dccc": {
        "label": "iCMTS E6000 (cts)",
        "checks": [
            ("Running config", "terminal length 0\nshow running-config"),
        ],
    },
    "dtr01k1dccc": {
        "label": "DTR01 Router (dtr)",
        "checks": [
            ("Running config", "show running-config"),
        ],
    },
}

# Per-device prompt patterns (compiled regex matching end of buffer)
PROMPT_PATTERNS = {
    "apc01k1dccc": re.compile(
        ("(?:^|\\r|\\n)" + re.escape(USERNAME) + "@apc01k1dccc>\\s*$").encode(),
        re.MULTILINE
    ),
    "apa01k1dccc": re.compile(rb"RP/[^\r\n]+#\s*$"),
    "ara01k1dccc": re.compile(rb"RP/[^\r\n]+#\s*$"),
    "asa01k1dccc": re.compile(rb"RP/[^\r\n]+#\s*$"),
    "cts01k1dccc": re.compile(rb"cts01k1dccc#\s*$"),
    "dtr01k1dccc": re.compile(rb"RP/[^\r\n]+#\s*$"),
}
DEFAULT_PROMPT = re.compile(rb"[>#$]\s*$")

NO_PAGE_DEVICES = {"apa01k1dccc", "ara01k1dccc", "asa01k1dccc", "dtr01k1dccc"}

# Devices that skip kbd-interactive and go straight to password
PASSWORD_ONLY_DEVICES = {"apc01k1dccc"}  # Erlang SSH disconnects on kbd rejection

# Devices that need legacy kex (iCMTS E6000 only offers group14-sha1 / group1-sha1)
LEGACY_KEX_DEVICES = {"cts01k1dccc"}
SSH_TEST_COMMANDS = {
    "apc01k1dccc": "show version brief",
    "apa01k1dccc": "show version brief",
    "ara01k1dccc": "show version brief",
    "asa01k1dccc": "show version brief",
    "cts01k1dccc": "show version",
    "dtr01k1dccc": "show version brief",
}

CONFIG_COMMANDS = {
    "apc01k1dccc": "show running-config",
    "apa01k1dccc": "show running-config",
    "ara01k1dccc": "show running-config",
    "asa01k1dccc": "show running-config",
    "cts01k1dccc": "terminal length 0\nshow running-config",
    "dtr01k1dccc": "show running-config",
}

# Devices that paginate with --More-- (send space to continue)
PAGINATED_DEVICES = {"apc01k1dccc"}

CRITICAL_LINKS = [
    ("apa01k1dccc", "FH0/0/0/24",  "up"),
    ("apa01k1dccc", "BE1",         "up"),
    ("apa01k1dccc", "BE101",       "up"),
    ("apa01k1dccc", "BE102",       "up"),
    ("apa01k1dccc", "BE103",       "up"),
    ("ara01k1dccc", "BE1",         "up"),
    ("ara01k1dccc", "Hu0/0/1/0",   "up"),
]

_PS_IP  = os.getenv("PACKETSTORM_IP", "")
_BB_IP  = os.getenv("BYTEBLOWER_IP", "")
_LA_IP  = os.getenv("LATENCY_ANALYZER_IP", "")

WEB_SERVICES = {
    "PacketStorm":     {"label": f"PacketStorm ({_PS_IP})",        "method": "http_via_jump", "url":  f"http://{_PS_IP}/xgui/login.jsp"},
    "ByteBlower":      {"label": f"ByteBlower ({_BB_IP})",         "method": "ping_via_jump", "host": _BB_IP},
    "LatencyAnalyzer": {"label": f"Latency Analyzer ({_LA_IP})",   "method": "http_local",    "url":  f"http://{_LA_IP}/"},
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def separator(title: str = "", width: int = 72):
    if title:
        log.info(f"\n{'='*width}\n  {title}\n{'='*width}")
    else:
        log.info("-" * width)


def load_key(path: str):
    log.debug(f"[KEY] Loading from {path}")
    if not os.path.exists(path):
        log.warning(f"[KEY] Not found: {path}")
        return None
    for cls in (paramiko.RSAKey, paramiko.Ed25519Key):
        try:
            return cls.from_private_key_file(path)
        except Exception as e:
            log.debug(f"[KEY] {cls.__name__} failed: {e}")
    return None


def open_jump_channel(jump: paramiko.SSHClient, host: str, port: int = 22):
    log.debug(f"[CHANNEL] Opening channel to {host}:{port}")
    transport = jump.get_transport()
    if not transport or not transport.is_active():
        raise RuntimeError("Jump transport is not active")
    # Resolve hostname to IPv4 explicitly to avoid IPv6 connection issues
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        ipv4 = infos[0][4][0]
        log.debug(f"[CHANNEL] Resolved {host} -> {ipv4} (IPv4)")
        dest = (ipv4, port)
    except Exception:
        log.debug(f"[CHANNEL] IPv4 resolution failed for {host}, using hostname")
        dest = (host, port)
    return transport.open_channel("direct-tcpip", dest, ("127.0.0.1", 0))


def _apply_profile(t: paramiko.Transport, legacy_kex: bool):
    if legacy_kex:
        # iCMTS E6000 — only offers group14-sha1 and group1-sha1
        t._preferred_kex     = ("diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1")
        t._preferred_keys    = ("ssh-rsa", "rsa-sha2-256")
        t._preferred_ciphers = ("aes128-ctr", "aes256-ctr", "3des-cbc")
    else:
        t._preferred_kex = (
            "curve25519-sha256", "curve25519-sha256@libssh.org",
            "ecdh-sha2-nistp256", "ecdh-sha2-nistp384",
            "diffie-hellman-group14-sha256",
        )
        t._preferred_keys    = ("ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa", "rsa-sha2-256")
        t._preferred_ciphers = ("aes128-ctr", "aes256-ctr", "aes128-gcm@openssh.com")


def make_transport(chan, legacy_kex: bool = False) -> paramiko.Transport:
    t = paramiko.Transport(chan)
    _apply_profile(t, legacy_kex)
    return t


def _kbd_handler(password: str):
    """Return a keyboard-interactive handler that answers every prompt with the password.
    Also handles the case where the server sends zero prompts (just a banner) by
    returning an empty list — paramiko will then call again with the real prompts.
    """
    def handler(title, instructions, fields):
        log.debug(f"[AUTH] kbd-interactive: title={title!r} fields={len(fields)}")
        return [password] * len(fields)
    return handler


def ssh_via_jump(jump: paramiko.SSHClient, host: str, username: str,
                 password: str) -> paramiko.SSHClient:
    log.debug(f"[SSH] Connecting to {host}")
    legacy   = host in LEGACY_KEX_DEVICES
    pw_only  = host in PASSWORD_ONLY_DEVICES
    authed   = False

    chan      = open_jump_channel(jump, host)
    transport = make_transport(chan, legacy_kex=legacy)
    transport.start_client(timeout=15)
    transport.get_remote_server_key()

    if not pw_only:
        try:
            transport.auth_interactive_dumb(username, _kbd_handler(password))
            authed = True
            log.debug(f"[SSH] {host} auth OK (keyboard-interactive)")
        except paramiko.AuthenticationException:
            log.debug(f"[SSH] {host} kbd-interactive failed")
        except Exception as exc:
            log.debug(f"[SSH] {host} kbd-interactive error: {exc}")

    if not authed:
        # Reopen transport if the server closed it after kbd rejection (Erlang / Cisco)
        if not transport.is_active():
            log.debug(f"[SSH] {host} transport closed — reopening for password auth")
            chan2      = open_jump_channel(jump, host)
            transport = make_transport(chan2, legacy_kex=legacy)
            transport.start_client(timeout=15)
        try:
            transport.auth_password(username, password)
            authed = True
            log.debug(f"[SSH] {host} auth OK (password)")
        except paramiko.AuthenticationException:
            transport.close()
            raise

    if not authed:
        transport.close()
        raise paramiko.AuthenticationException(f"All auth methods failed for {host}")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client._transport = transport
    client._is_device = True
    return client


def _shell_recv_until_prompt(shell, timeout: int, idle_gap: float = 5.0,
                             host: str = "") -> bytes:
    """Read until the device prompt is seen or idle for idle_gap seconds.
    For paginated devices: keep sending space on --More-- until no more
    --More-- appears, then wait out the idle_gap for the final prompt.
    For non-paginated devices: stop as soon as the prompt regex matches.
    """
    PROMPT    = PROMPT_PATTERNS.get(host, DEFAULT_PROMPT)
    paginated = host in PAGINATED_DEVICES
    buf       = b""
    deadline  = time.time() + timeout
    last_rx   = time.time()
    saw_more  = False  # have we ever seen --More-- on this command?

    while time.time() < deadline:
        if shell.recv_ready():
            chunk   = shell.recv(65535)
            buf    += chunk
            last_rx = time.time()

            if paginated and b"--More--" in buf:
                buf      = buf.replace(b"--More--", b"")
                saw_more = True
                shell.send(" ")
                time.sleep(0.1)
                continue

            # Non-paginated, or paginated but no --More-- in this chunk:
            # only check prompt if we haven't been paging (or paging is done
            # and idle_gap will catch the tail — handled by the elif below)
            if not saw_more and PROMPT.search(buf):
                time.sleep(0.3)
                if shell.recv_ready():
                    buf += shell.recv(65535)
                break

        elif time.time() - last_rx > idle_gap:
            # Idle timeout — for paginated devices this is how we know
            # the last page has fully arrived (no more --More-- coming)
            break
        else:
            time.sleep(0.2)
    return buf


def _open_shell(client, host: str = "") -> object:
    """Open an interactive shell, drain the banner, disable pagination on IOS-XR."""
    t     = client._transport
    shell = t.open_session()
    shell.get_pty(term="vt100", width=200, height=50)
    shell.invoke_shell()
    time.sleep(1)
    shell.recv(4096)  # drain banner/prompt
    if host in NO_PAGE_DEVICES:
        shell.send("terminal length 0\n")
        time.sleep(0.5)
        shell.recv(4096)  # drain the echo + prompt
    return shell


def _shell_run(shell, cmd: str, timeout: int = 60, host: str = "") -> str:
    """Send one command to an already-open shell and return the output."""
    for line in cmd.splitlines():
        shell.send(line + "\n")
        time.sleep(0.5)
    buf = _shell_recv_until_prompt(shell, timeout=timeout, host=host)
    return re.sub(r"\x1b\[[0-9;]*[mABCDHJKfsu]", "", buf.decode(errors="replace")).strip()


def run_command(client, cmd: str, host: str = "", timeout: int = 30) -> str:
    """Run a command, using invoke_shell (persistent per-client shell).
    Falls back to exec_command only for jump server (no _transport attribute)."""
    log.debug(f"[CMD] {host} $ {cmd}")

    # Jump server — it's a native SSHClient (not built via ssh_via_jump), use exec_command
    if not getattr(client, "_is_device", False):
        _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        out = (stdout.read() + stderr.read()).decode(errors="replace").strip()
        log.debug(f"[CMD] {host} exec_command OK ({len(out)} chars)")
        return out

    # Device clients — use persistent shell stored on the client object
    if not hasattr(client, "_shell") or client._shell is None or client._shell.closed:
        client._shell = _open_shell(client, host=host)

    out = _shell_run(client._shell, cmd, timeout=max(timeout, 60), host=host)
    log.debug(f"[CMD] {host} shell OK ({len(out)} chars)")
    return out


def check_link_state(output: str, iface: str, expected: str) -> bool:
    for line in output.splitlines():
        if iface in line:
            ok = expected.lower() in line.lower()
            log.debug(f"[LINK] {iface} {'PASS' if ok else 'FAIL'}  line={line.strip()}")
            return ok
    log.debug(f"[LINK] {iface} not found in output")
    return False


# ---------------------------------------------------------------------------
# Stage 1 — Ping
# ---------------------------------------------------------------------------

def stage_ping(jump: paramiko.SSHClient, targets: dict) -> dict:
    """Ping each device from the jump server. Returns {host: bool}."""
    separator("Stage 1 — Ping Reachability (via jump server)")
    results = {}
    for host in targets:
        try:
            out = run_command(jump, f"ping -c 3 -W 2 {host}", host="jump", timeout=15)
            ok  = " 0% packet loss" in out
        except Exception:
            ok  = False
            log.debug(f"[PING] {host} traceback:\n{traceback.format_exc()}")
        results[host] = ok
        log.info(f"  [{'PASS' if ok else 'FAIL'}]  ping {host}")
    return results


# ---------------------------------------------------------------------------
# Stage 2 — SSH connectivity test
# ---------------------------------------------------------------------------

def stage_ssh(jump: paramiko.SSHClient, targets: dict, ping_results: dict,
              username: str, password: str) -> dict:
    """Test SSH login to each device. Returns {host: bool}."""
    separator("Stage 2 — SSH Connectivity")
    results = {}
    for host in targets:
        if not ping_results.get(host):
            log.info(f"  [SKIP]  ssh {host}  (ping failed)")
            results[host] = False
            continue
        try:
            client = ssh_via_jump(jump, host, username, password)
            client._shell = None
            cmd = SSH_TEST_COMMANDS.get(host, "show version brief")
            run_command(client, cmd, host=host, timeout=15)
            if hasattr(client, "_shell") and client._shell:
                client._shell.close()
            client.close()
            results[host] = True
            log.info(f"  [PASS]  ssh {host}")
        except Exception as exc:
            results[host] = False
            log.info(f"  [FAIL]  ssh {host}  ({exc})")
            log.debug(f"[SSH] {host} traceback:\n{traceback.format_exc()}")
    return results


# ---------------------------------------------------------------------------
# Stage 3 — Full checks + config pull
# ---------------------------------------------------------------------------

def stage_verify(jump: paramiko.SSHClient, targets: dict, ssh_results: dict,
                 username: str, password: str) -> dict:
    """Run all device checks. Returns {host: {label: output}}."""
    separator("Stage 3 — Device Verification")
    all_results = {}
    for host, info in targets.items():
        if not ssh_results.get(host):
            log.info(f"\n  [SKIP]  {info['label']} ({host}) — SSH not available")
            all_results[host] = {}
            continue

        separator(f"{info['label']}  ({host})")
        results = {}
        try:
            client = ssh_via_jump(jump, host, username, password)
            client._shell = None  # will be lazily opened on first run_command
        except Exception:
            log.error(f"  [ERROR] Cannot connect to {host}")
            log.debug(traceback.format_exc())
            all_results[host] = {}
            continue

        for label, cmd in info["checks"]:
            log.info(f"\n  >> {label}\n     CMD: {cmd}")
            try:
                out = run_command(client, cmd, host=host)
            except Exception:
                out = "[ERROR] command failed"
                log.debug(traceback.format_exc())
            log.info(out)
            results[label] = out

        if hasattr(client, "_shell") and client._shell:
            client._shell.close()
        client.close()
        all_results[host] = results
        time.sleep(1)

    return all_results


def stage_configs(jump: paramiko.SSHClient, targets: dict, ssh_results: dict,
                  username: str, password: str):
    """Pull and save running config from each reachable device."""
    separator("Stage 3b — Pulling Running Configs")
    os.makedirs(CONFIG_DIR, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")

    for host in targets:
        if host not in DEVICES:
            log.info(f"  [SKIP]  {host} — not in device list")
            continue
        if not ssh_results.get(host):
            log.info(f"  [SKIP]  {host} — SSH not available")
            continue

        cmd    = CONFIG_COMMANDS.get(host, "show running-config")
        prefix = "current"
        short  = next((a for a, h in ALIASES.items() if h == host), host)
        log.info(f"\n  >> {host}")
        log.debug(f"[CONFIG] cmd={cmd}")
        try:
            client = ssh_via_jump(jump, host, username, password)
            client._shell = None

            config = run_command(client, cmd, host=host, timeout=120)

            if hasattr(client, "_shell") and client._shell:
                client._shell.close()
            client.close()

            # Extract device-reported config date (IOS-XR / iCMTS pattern)
            device_date = "unknown"
            for line in config.splitlines():
                if "last configuration change" in line.lower():
                    device_date = line.strip()
                    break

            path = os.path.join(CONFIG_DIR, f"{prefix}_{short}_{timestamp}.txt")
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"! Pulled from  : {host}\n")
                f.write(f"! Pull date    : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"! Device date  : {device_date}\n")
                f.write(f"! {'='*60}\n")
                f.write(config)
            log.info(f"  [SAVED] {path}  ({len(config)} chars)")
        except Exception:
            log.error(f"  [ERROR] Config pull failed for {host}")
            log.debug(traceback.format_exc())


# ---------------------------------------------------------------------------
# Web services
# ---------------------------------------------------------------------------

def check_web_services(jump: paramiko.SSHClient):
    separator("Web Service Reachability")
    for name, cfg in WEB_SERVICES.items():
        label  = cfg["label"]
        method = cfg["method"]
        try:
            if method == "http_local":
                req    = urllib.request.urlopen(cfg["url"], timeout=10)
                status = f"PASS  HTTP {req.status}"
            elif method == "http_via_jump":
                out  = run_command(jump,
                    f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 10 '{cfg['url']}'",
                    host="jump", timeout=20)
                # Output may include shell echo + prompt — extract the last numeric token
                tokens = [t.strip() for t in re.split(r'[\s\r\n]+', out) if t.strip()]
                code   = next((t for t in reversed(tokens) if t.isdigit()), "")
                status = (f"PASS  HTTP {code}" if code and int(code) > 0
                          else f"FAIL  curl returned: {out[:80]}")
            elif method == "ping_via_jump":
                out    = run_command(jump, f"ping -c 3 -W 3 {cfg['host']}",
                                     host="jump", timeout=20)
                status = ("PASS  ping OK" if " 0% packet loss" in out
                          else "FAIL  packet loss detected")
            else:
                status = f"FAIL  unknown method"
        except urllib.error.HTTPError as e:
            status = f"PASS  HTTP {e.code} (host reachable)"
        except Exception as exc:
            status = f"FAIL  {exc}"
            log.debug(traceback.format_exc())

        log.info(f"  [{status[:4]}]  {label:35s}")
        log.info(f"         {status}")


# ---------------------------------------------------------------------------
# Critical link summary
# ---------------------------------------------------------------------------

def evaluate_critical_links(all_results: dict):
    separator("Critical Link Summary")
    all_pass = True
    for host, iface, expected in CRITICAL_LINKS:
        output = all_results.get(host, {}).get("Interface status", "")
        if not output or "[ERROR]" in output:
            log.info(f"  [SKIP]  {host:20s}  {iface:20s}  no data (SSH failed)")
            continue
        ok     = check_link_state(output, iface, expected)
        status = "PASS" if ok else "FAIL"
        if not ok:
            all_pass = False
        log.info(f"  [{status}]  {host:20s}  {iface:20s}  expected={expected}")
    log.info("")
    log.info("  All critical links UP." if all_pass
             else "  WARNING: One or more critical links are DOWN — see details above.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="CTEC Lab Network Verifier")
    parser.add_argument("--device", default=None,
                        help=f"Alias ({', '.join(ALIASES)}) or full hostname")
    parser.add_argument("--debug", action="store_true",
                        help="Enable paramiko debug logging")
    args = parser.parse_args()

    if args.debug:
        enable_paramiko_debug()

    log.info(f"\nCTEC Lab Network Verifier")
    log.info(f"Jump host : {JUMP_HOST}")
    log.info(f"Username  : {USERNAME}")
    log.info(f"Log file  : {LOG_FILE}\n")

    # --- Connect to jump server ---
    key  = load_key(KEY_PATH)
    jump = paramiko.SSHClient()
    jump.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    separator(f"Connecting to {JUMP_HOST}")
    if key:
        log.info(f"  Trying SSH key: {KEY_PATH}")
        try:
            jump.connect(JUMP_HOST, port=JUMP_PORT, username=USERNAME,
                         pkey=key, timeout=20, banner_timeout=20,
                         disabled_algorithms=DISABLED_ALGORITHMS)
            log.info(f"  Connected to {JUMP_HOST} (key auth)")
            time.sleep(1)
        except Exception:
            log.warning("  Key auth failed, falling back to password...")
            log.debug(traceback.format_exc())
            key = None

    if key is None:
        jump_credential = os.getenv('JUMP_PASS') or getpass.getpass(f"Jump server password for {USERNAME}@{JUMP_HOST}: ")
        try:
            jump.connect(JUMP_HOST, port=JUMP_PORT, username=USERNAME,
                         password=jump_credential, timeout=20, banner_timeout=20,
                         disabled_algorithms=DISABLED_ALGORITHMS)
            log.info(f"  Connected to {JUMP_HOST} (password auth)")
            time.sleep(1)
        except Exception:
            log.error("[JUMP] Connection failed")
            log.debug(traceback.format_exc())
            sys.exit(1)

    # --- Lab device password ---
    password = os.getenv('DEVICE_PASSWORD') or getpass.getpass(f"Lab device password for {USERNAME}: ")

    # --- Resolve targets ---
    if args.device:
        resolved = ALIASES.get(args.device, args.device)
        if resolved not in DEVICES:
            log.error(f"Unknown device '{args.device}'. "
                      f"Aliases: {', '.join(ALIASES)}")
            jump.close()
            sys.exit(1)
        targets = {resolved: DEVICES[resolved]}
    else:
        targets = DEVICES

    # -----------------------------------------------------------------------
    # Stage 1 — Ping
    # -----------------------------------------------------------------------
    ping_results = stage_ping(jump, targets)

    # -----------------------------------------------------------------------
    # Stage 2 — SSH
    # -----------------------------------------------------------------------
    ssh_results = stage_ssh(jump, targets, ping_results, USERNAME, password)

    # -----------------------------------------------------------------------
    # Stage 3 — Full checks + configs
    # -----------------------------------------------------------------------
    all_results = stage_verify(jump, targets, ssh_results, USERNAME, password)
    stage_configs(jump, targets, ssh_results, USERNAME, password)

    # Web checks must run before jump.close() — they use the jump SSH connection
    if not args.device:
        check_web_services(jump)

    jump.close()

    if not args.device:
        evaluate_critical_links(all_results)

    separator("Verification Complete")
    log.info(f"\n  Full debug log: {LOG_FILE}")

    # --- Run config comparison ---
    import subprocess
    compare_script = os.path.join(os.path.dirname(__file__), "compare_configs.py")
    if os.path.exists(compare_script):
        log.info("\nRunning config comparison...")
        cmd = [sys.executable, compare_script, "--no-pull"]
        if args.device:
            cmd += ["--device", args.device]
        subprocess.run(cmd)
    else:
        log.warning(f"  [WARN] compare_configs.py not found, skipping comparison")


if __name__ == "__main__":
    main()
