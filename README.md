# Lab Verification

Automated SSH-based lab verification and troubleshooting toolkit for the CTEC LLD test lab. Connects to all lab devices via jump host, runs verification checks, pulls running configs, diffs against baselines, and exposes a REST API with a web dashboard.

## Project Structure

```
Lab_Verification/
├── Lab_verification_and_trouble_shooting.py  # Main verification script
├── api.py                                    # FastAPI REST wrapper
├── compare_configs.py                        # Config diff tool
├── ssh_test_apc_cts.py                       # SSH connectivity tester
├── static/
│   └── index.html                            # Web dashboard
├── Baseline_Config/                          # Baseline device configs
├── configs/                                  # Current pulled configs
├── diffs/                                    # Config diffs vs baseline
├── logs/                                     # Verification run logs
├── lab_verification.service                  # systemd service
├── lab_verification.timer                    # systemd timer
└── requirements_api.txt                      # Python dependencies
```

## Devices

| Alias | Hostname       | Role                  |
|-------|----------------|-----------------------|
| apa   | apa01k1dccc    | APA Switch (IOS-XR)   |
| apc   | apc01k1dccc    | vCMTS (Harmonic)      |
| ara   | ara01k1dccc    | ARA Switch (IOS-XR)   |
| asa   | asa01k1dccc    | ASA Switch (IOS-XR)   |
| cts   | cts01k1dccc    | iCMTS E6000 (Cisco)   |
| dtr   | dtr01k1dccc    | DTR Router (IOS-XR)   |

All devices are accessed via `ctec-jump.ctec.charterlab.com`.

## Setup

```bash
pip install -r requirements_api.txt
```

Create a `.env` file (excluded from git):

```
JUMP_HOST=ctec-jump.ctec.charterlab.com
JUMP_USER=<username>
SSH_KEY_PATH=~/.ssh/id_rsa
DEVICE_PASSWORD=<device_password>   # optional — prompted if not set
```

## Usage

### Run full lab verification
```bash
python Lab_verification_and_trouble_shooting.py
```

### Verify a single device
```bash
python Lab_verification_and_trouble_shooting.py --device apa
python Lab_verification_and_trouble_shooting.py --device cts
```

### Enable debug logging
```bash
python Lab_verification_and_trouble_shooting.py --debug
```

### Start the API + web dashboard
```bash
python -m uvicorn api:app --host 0.0.0.0 --port 8000
```
Then open `http://localhost:8000` in a browser.

### Compare configs against baseline
```bash
python compare_configs.py
python compare_configs.py --device apa
```

### Test SSH connectivity only
```bash
python ssh_test_apc_cts.py
```

## Verification Stages

1. **Ping** — pings each device from the jump server
2. **SSH** — tests login to each device
3. **Verify** — runs device-specific checks (interface status, bundle state, LLDP neighbors, running config)
4. **Config Pull** — saves running config to `configs/` with timestamp
5. **Config Diff** — compares pulled config against baseline in `Baseline_Config/`
6. **Web Services** — checks reachability of PacketStorm, ByteBlower, and Latency Analyzer

## systemd Deployment

```bash
sudo cp lab_verification.service /etc/systemd/system/
sudo cp lab_verification.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now lab_verification.timer
sudo systemctl status lab_verification.timer
```

## Notes

- Credentials are loaded from `.env` or prompted via `getpass` — never hardcoded
- IPv4 is forced on jump channel resolution to avoid IPv6 SYN black-hole hangs
- iCMTS E6000 requires legacy KEX (`diffie-hellman-group14-sha1`) — handled automatically
- Harmonic vCMTS (Erlang SSH) skips keyboard-interactive and goes straight to password auth
- Logs are written to `logs/lab_verify_<timestamp>.log`
