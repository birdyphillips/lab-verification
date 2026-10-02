#!/usr/bin/env python3
"""
SSH Connectivity Tester — apc01k1dccc (Erlang) & cts01k1dccc (iCMTS E6000)
Connects via ctec-jump and tries multiple kex/auth combinations to find what works.

Usage:
    python ssh_test_apc_cts.py

Requirements:
    pip install paramiko python-dotenv
"""

import getpass
import logging
import os
import re
import socket
import sys
import time
import traceback

import paramiko
import paramiko.transport
import paramiko.rsakey
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Logging — console + file
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("ssh_test_debug.log", encoding="utf-8"),
    ]
)
log = logging.getLogger("ssh_test")

# ---------------------------------------------------------------------------
# Re-register removed algorithms
# ---------------------------------------------------------------------------
if "ssh-rsa" not in paramiko.transport.Transport._key_info:
    paramiko.transport.Transport._key_info["ssh-rsa"] = paramiko.rsakey.RSAKey

try:
    _c25519 = paramiko.transport.Transport._kex_info.get("curve25519-sha256@libssh.org")
    if _c25519 and "curve25519-sha256" not in paramiko.transport.Transport._kex_info:
        paramiko.transport.Transport._kex_info["curve25519-sha256"] = _c25519
except Exception:
    pass

# Backport diffie-hellman-group14-sha1 using SHA-1 instead of SHA-256
try:
    from hashlib import sha1
    from paramiko.kex_group14 import KexGroup14SHA256

    class KexGroup14SHA1(KexGroup14SHA256):
        name = "diffie-hellman-group14-sha1"
        hash_algo = staticmethod(sha1)

    if "diffie-hellman-group14-sha1" not in paramiko.transport.Transport._kex_info:
        paramiko.transport.Transport._kex_info["diffie-hellman-group14-sha1"] = KexGroup14SHA1
    log.debug("Registered diffie-hellman-group14-sha1 (SHA-1 backport)")
except Exception as e:
    log.warning(f"Could not register group14-sha1: {e}")

# Patch _verify_key to accept ssh-rsa SHA-1 signatures
_orig_verify_key = paramiko.transport.Transport._verify_key
def _patched_verify_key(self, host_key, sig):
    try:
        return _orig_verify_key(self, host_key, sig)
    except Exception as e:
        if "ssh-rsa" in str(e) or "Signature verification" in str(e):
            log.debug(f"[VERIFY] Accepting ssh-rsa key without SHA-1 verification: {e}")
            # Manually store the host key so get_remote_server_key() works
            msg = paramiko.message.Message(host_key)
            key_type = msg.get_text()
            key_map = paramiko.transport.Transport._key_info
            if key_type in key_map:
                try:
                    self.host_key = key_map[key_type](data=host_key)
                except Exception as ke:
                    log.debug(f"[VERIFY] Could not parse host key: {ke}")
            return
        raise
paramiko.transport.Transport._verify_key = _patched_verify_key

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
load_dotenv()
JUMP_HOST = os.getenv("JUMP_HOST", "")
JUMP_PORT = 22
USERNAME  = os.getenv("JUMP_USER", "")
KEY_PATH  = os.path.expanduser(os.getenv("SSH_KEY_PATH", "~/.ssh/id_rsa"))

TARGETS = {
    "apc01k1dccc": {
        "note": "Harmonic vCMTS — Erlang SSH, ed25519 host key, password auth",
        "commands": ["show system", "show running-config"],
        "kex_profiles": [
            {
                "name": "curve25519 + ed25519 (expected)",
                "kex":  ("curve25519-sha256", "curve25519-sha256@libssh.org",
                         "ecdh-sha2-nistp256"),
                "keys": ("ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"),
                "ciphers": ("aes128-ctr", "aes256-ctr", "aes128-gcm@openssh.com"),
            },
            {
                "name": "ecdh-nistp256 + ed25519",
                "kex":  ("ecdh-sha2-nistp256", "ecdh-sha2-nistp384"),
                "keys": ("ssh-ed25519", "ecdsa-sha2-nistp256"),
                "ciphers": ("aes128-ctr", "aes256-ctr", "aes128-gcm@openssh.com"),
            },
        ],
        "auth": "password_only",   # Erlang SSH: kbd rejected, go straight to password
    },
    "cts01k1dccc": {
        "note": "iCMTS E6000 — Cisco IOS, ssh-rsa host key, very old kex",
        "commands": ["terminal length 0", "show running-config"],
        "kex_profiles": [
            {
                "name": "group14-sha256 + ssh-rsa (preferred)",
                "kex":  ("diffie-hellman-group14-sha256",
                         "diffie-hellman-group-exchange-sha256",
                         "ecdh-sha2-nistp256"),
                "keys": ("ssh-rsa", "rsa-sha2-256", "ecdsa-sha2-nistp256"),
                "ciphers": ("aes128-ctr", "aes256-ctr", "aes128-cbc"),
            },
            {
                "name": "group14-sha1 + ssh-rsa (legacy E6000)",
                "kex":  ("diffie-hellman-group14-sha1",
                         "diffie-hellman-group1-sha1"),
                "keys": ("ssh-rsa", "rsa-sha2-256"),
                "ciphers": ("aes128-ctr", "aes256-ctr", "3des-cbc"),
            },
            {
                "name": "ecdh-nistp256 + ssh-rsa",
                "kex":  ("ecdh-sha2-nistp256", "ecdh-sha2-nistp384",
                         "diffie-hellman-group14-sha256"),
                "keys": ("ssh-rsa", "rsa-sha2-256"),
                "ciphers": ("aes128-ctr", "aes256-ctr"),
            },
        ],
        "auth": "kbd_then_password",
    },
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_key(path: str):
    if not os.path.exists(path):
        return None
    for cls in (paramiko.RSAKey, paramiko.Ed25519Key):
        try:
            return cls.from_private_key_file(path)
        except Exception:
            continue
    return None


def open_channel(jump: paramiko.SSHClient, host: str, port: int = 22):
    transport = jump.get_transport()
    # Try IPv4 first
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        dest  = (infos[0][4][0], port)
        log.debug(f"[CHANNEL] {host} resolved to {dest[0]} (IPv4)")
    except Exception:
        dest = (host, port)
        log.debug(f"[CHANNEL] {host} using hostname (no IPv4 resolution)")
    return transport.open_channel("direct-tcpip", dest, ("127.0.0.1", 0))


def try_connect(jump: paramiko.SSHClient, host: str, profile: dict,
                auth_mode: str, username: str, password: str,
                commands: list[str] = None) -> tuple[bool, str]:
    """
    Try one kex profile + auth combination.
    Returns (success: bool, message: str).
    """
    if commands is None:
        commands = ["show version"]
    try:
        chan = open_channel(jump, host)
        t   = paramiko.Transport(chan)
        t._preferred_kex     = profile["kex"]
        t._preferred_keys    = profile["keys"]
        t._preferred_ciphers = profile["ciphers"]

        log.debug(f"  start_client ...")
        t.start_client(timeout=10)
        log.debug(f"  kex OK — negotiated: kex={t.remote_version}")

        host_key = t.get_remote_server_key()
        host_key_type = host_key.get_name() if host_key is not None else "unknown"
        log.debug(f"  host key type: {host_key_type}")

        # Auth
        authed = False
        if auth_mode != "password_only":
            try:
                def kbd_handler(title, instructions, fields):
                    log.debug(f"  kbd-interactive: fields={len(fields)}")
                    return [password] * len(fields)
                t.auth_interactive_dumb(username, kbd_handler)
                authed = True
                log.debug(f"  auth OK (keyboard-interactive)")
            except paramiko.AuthenticationException as e:
                log.debug(f"  kbd-interactive failed: {e}")
            except Exception as e:
                log.debug(f"  kbd-interactive error: {e}")

        if not authed:
            # Erlang SSH disconnects after kbd failure — open fresh transport
            if not t.is_active():
                log.debug("  transport closed — reopening for password auth")
                chan2 = open_channel(jump, host)
                t = paramiko.Transport(chan2)
                t._preferred_kex     = profile["kex"]
                t._preferred_keys    = profile["keys"]
                t._preferred_ciphers = profile["ciphers"]
                t.start_client(timeout=10)
            try:
                t.auth_password(username, password)
                authed = True
                log.debug(f"  auth OK (password)")
            except paramiko.AuthenticationException as e:
                log.debug(f"  password auth failed: {e}")

        if not authed:
            t.close()
            return False, "Authentication failed (all methods)"

        # Shell command test
        try:
            shell = t.open_session()
            shell.get_pty(term="vt100", width=200, height=50)
            shell.invoke_shell()
            time.sleep(1)
            shell.recv(4096)  # drain banner/prompt

            output_parts = []
            for cmd in commands:
                shell.send(cmd + "\n")
                time.sleep(2)
                buf = b""
                deadline = time.time() + 8
                while time.time() < deadline:
                    if shell.recv_ready():
                        buf += shell.recv(65535)
                    else:
                        time.sleep(0.2)
                output_parts.append(f"--- {cmd} ---\n" +
                    re.sub(r"\x1b\[[0-9;]*[mABCDHJKfsu]", "", buf.decode(errors="replace")))

            shell.close()
            t.close()
            combined = "\n".join(output_parts)
            log.info(f"  Command output:\n{combined}")
            return True, f"Connected + shell OK ({len(commands)} commands run)"
        except Exception as e:
            t.close()
            return True, f"Connected (auth OK) but shell failed: {e}"

    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    log.info("\n" + "="*70)
    log.info("  SSH Connectivity Tester — apc01k1dccc & cts01k1dccc")
    log.info("="*70)

    # Connect to jump
    key  = load_key(KEY_PATH)
    jump = paramiko.SSHClient()
    jump.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    log.info(f"\nConnecting to jump: {JUMP_HOST}")
    if key:
        try:
            jump.connect(JUMP_HOST, port=JUMP_PORT, username=USERNAME,
                         pkey=key, timeout=20, banner_timeout=20,
                         disabled_algorithms={"kex": ["curve25519-sha256",
                                                       "diffie-hellman-group1-sha1",
                                                       "diffie-hellman-group14-sha1"]})
            log.info(f"  Connected (key auth)")
            time.sleep(1)
        except Exception as e:
            log.warning(f"  Key auth failed: {e}, trying password...")
            key = None

    if key is None:
        pw = getpass.getpass(f"Jump password for {USERNAME}@{JUMP_HOST}: ")
        jump.connect(JUMP_HOST, port=JUMP_PORT, username=USERNAME,
                     password=pw, timeout=20, banner_timeout=20)
        log.info(f"  Connected (password auth)")
        time.sleep(1)

    password = os.getenv("DEVICE_PASSWORD") or getpass.getpass(f"Device password for {USERNAME}: ")

    # Test each target
    for host, cfg in TARGETS.items():
        log.info(f"\n{'='*70}")
        log.info(f"  Testing: {host}")
        log.info(f"  Note:    {cfg['note']}")
        log.info(f"{'='*70}")

        for i, profile in enumerate(cfg["kex_profiles"], 1):
            log.info(f"\n  Profile {i}: {profile['name']}")
            log.info(f"    kex    : {profile['kex']}")
            log.info(f"    keys   : {profile['keys']}")
            log.info(f"    auth   : {cfg['auth']}")

            ok, msg = try_connect(jump, host, profile, cfg["auth"], USERNAME, password,
                                   commands=cfg.get("commands", ["show version"]))
            status  = "PASS" if ok else "FAIL"
            log.info(f"    [{status}] {msg}")

            if ok:
                log.info(f"\n  *** WORKING PROFILE FOUND for {host} ***")
                log.info(f"      kex    : {profile['kex']}")
                log.info(f"      keys   : {profile['keys']}")
                log.info(f"      ciphers: {profile['ciphers']}")
                log.info(f"      auth   : {cfg['auth']}")
                break
            time.sleep(1)
        else:
            log.info(f"\n  *** ALL PROFILES FAILED for {host} ***")
            log.info(f"      Check ssh_test_debug.log for full details")

    jump.close()
    log.info(f"\n{'='*70}")
    log.info("  Test complete. Full debug in: ssh_test_debug.log")
    log.info(f"{'='*70}\n")


if __name__ == "__main__":
    main()
