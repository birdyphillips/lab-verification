# How to Build a Lab Verification API + Frontend Without AI

This is a breakdown of every skill, concept, and decision you would need to build
`Lab_verification_and_trouble_shooting.py`, `api.py`, and `static/index.html` from scratch.

---

## 1. Prerequisites — What You Need to Know First

### Python
- Variables, loops, functions, classes
- Exception handling (`try/except/raise`)
- File I/O (`open`, `os.path`, `os.makedirs`)
- `subprocess` and `argparse` for CLI tools
- `logging` module — handlers, formatters, levels
- `re` (regex) — compiling patterns, `search`, `sub`
- `socket` — `getaddrinfo`, `AF_INET`
- `time` — `strftime`, `sleep`, `time()`
- `os.getenv` and `python-dotenv` for config

### Networking Fundamentals
- SSH protocol — key exchange, authentication methods (password, keyboard-interactive, public key)
- Jump hosts / bastion servers — what they are and why they exist
- TCP/IP — IPv4 vs IPv6, why IPv6 can cause hangs (SYN black-hole)
- ICMP ping — packet loss, what `0% packet loss` means
- HTTP — status codes, `curl` flags (`-s`, `-o /dev/null`, `-w`)

### Linux CLI (for the devices you're connecting to)
- IOS-XR commands: `show int desc`, `show bundle`, `show lldp neighbors`, `show running-config`
- `terminal length 0` — why you need it (disables pagination)
- Shell prompt patterns — why `RP/0/...#` looks different per device

---

## 2. Building the Core Script (`Lab_verification_and_trouble_shooting.py`)

### Step 1 — Learn Paramiko
Paramiko is the Python SSH library. You would need to read:
- [Paramiko docs](https://docs.paramiko.org)
- How `SSHClient` works vs raw `Transport`
- The difference between `exec_command` (one-shot) and `invoke_shell` (interactive)
- Why interactive shell is required for IOS-XR (stateful terminal, `terminal length 0` must persist)

**Key things to figure out on your own:**
```
# exec_command does NOT share state between calls
# invoke_shell keeps a persistent PTY session — required for multi-line commands
```

### Step 2 — Jump Host Tunneling
You would Google: *"paramiko proxy jump host tunnel"* and find that you need:
```python
transport.open_channel("direct-tcpip", dest, src)
```
Then wrap a second `Transport` around that channel to SSH into the target device.

This is not obvious — most tutorials only show direct SSH. You would likely spend
several hours on Stack Overflow finding this pattern.

### Step 3 — Legacy KEX / Algorithm Compatibility
The iCMTS E6000 only supports old key exchange algorithms that modern Paramiko removed.
You would discover this by:
1. Running the script and getting `No acceptable kex algorithm` errors
2. Googling the error + Paramiko version
3. Finding that you need to subclass `KexGroup14SHA256` and override `hash_algo`
4. Registering it manually in `Transport._kex_info`

This alone could take a full day of debugging.

### Step 4 — Prompt Detection
Each device has a different shell prompt. You would:
1. Connect manually via SSH and observe what the prompt looks like
2. Write regex patterns for each one
3. Handle `--More--` pagination (Erlang/vCMTS paginates, IOS-XR does not after `terminal length 0`)
4. Tune `idle_gap` timeouts by trial and error

### Step 5 — Auth Fallback Logic
Some devices (Erlang SSH on vCMTS) disconnect the transport if you try keyboard-interactive
and it fails. You would discover this by:
1. Getting `Transport closed` errors
2. Adding debug logging to see what the server sends back
3. Implementing the reopen-transport fallback

### Step 6 — Structure the Stages
Once SSH works, organizing into stages (ping → ssh → verify → configs) is straightforward
software design. You would sketch it on paper first:
```
Stage 1: Can I reach it? (ping)
Stage 2: Can I log in? (ssh)
Stage 3: Is it configured correctly? (verify)
Stage 3b: Save the config for diffing later
```

---

## 3. Building the API (`api.py`)

### Learn FastAPI
- Read the [FastAPI docs](https://fastapi.tiangolo.com) — Getting Started takes ~2 hours
- Understand path operations (`@app.get`, `@app.post`)
- Pydantic models for request bodies
- `Header(...)` for custom headers
- `Query(None)` for optional query params
- `HTTPException` for error responses
- `StaticFiles` mount for serving HTML
- `FileResponse` for file downloads

### Session Management
FastAPI has no built-in session store. You would need to design one:
```python
# Option A: in-memory dict (what we used — simple, lost on restart)
# Option B: Redis (persistent, scalable)
# Option C: JWT tokens (stateless)
```
For a lab tool, Option A is fine. You would figure this out by thinking through
"how do I keep the SSH connection alive between HTTP requests?"

### CORS / Static Files
You would hit a browser error trying to load the frontend and Google:
*"FastAPI serve static html files"* → find `StaticFiles` + `aiofiles` dependency.

---

## 4. Building the Frontend (`static/index.html`)

### HTML/CSS Skills Needed
- Semantic HTML structure (`header`, `aside`, `main`)
- CSS Grid for the two-column layout (`grid-template-columns: 260px 1fr`)
- CSS custom properties (`--accent`, `--bg`, etc.) for theming
- Flexbox for button rows and card headers
- `details`/`summary` for collapsible sections (no JS needed)
- CSS transitions for the toast notification
- `@keyframes` for the spinner animation

### JavaScript Skills Needed
- `fetch` API — `method`, `headers`, `body`
- `async/await` — handling promises cleanly
- DOM manipulation — `innerHTML`, `querySelector`, `getElementById`
- Event handling — `onclick`
- Template literals for building HTML strings
- State management — a plain object (`const state = {}`) is enough for a lab tool

### Design Decisions You Would Make
1. **Single-file vs multi-file** — single file is simpler to serve and deploy
2. **No framework** — vanilla JS is fine for a tool this size; React/Vue would be overkill
3. **Dark theme** — GitHub-style dark palette is easy on the eyes for terminal output
4. **Collapsible output** — `<details>` is the right HTML element, no JS required
5. **Toast notifications** — CSS opacity transition + `setTimeout` is the minimal approach
6. **Session token in memory** — `const state = { token: null }` — simple, cleared on refresh

### The Fetch Pattern You Would Write
```javascript
async function callApi(method, path, body = null) {
    const res = await fetch(path, {
        method,
        headers: {
            'Content-Type': 'application/json',
            'x-session-token': state.token
        },
        body: body ? JSON.stringify(body) : null
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
}
```
You would find this pattern on MDN or a fetch tutorial and adapt it.

---

## 5. Debugging You Would Have to Do

| Problem | How You Would Find It |
|---|---|
| `No acceptable kex algorithm` | Paramiko error message → Google → subclass fix |
| IPv6 hang on connect | 127s timeout → `strace` or Wireshark → `/etc/hosts` fix |
| `--More--` eating output | Missing data in results → add `--More--` detection |
| Erlang SSH closes transport on kbd-interactive | `Transport closed` error → reopen transport |
| `uvicorn` not on PATH | `CommandNotFoundException` → use `python -m uvicorn` |
| Browser shows `ERR_ADDRESS_INVALID` | Tried `0.0.0.0` in browser → use `localhost` |
| `StaticFiles` fails | Missing `aiofiles` → `pip install aiofiles` |

---

## 6. Tools and References You Would Use

| Tool | Purpose |
|---|---|
| [Paramiko docs](https://docs.paramiko.org) | SSH library reference |
| [FastAPI docs](https://fastapi.tiangolo.com) | API framework |
| [MDN Web Docs](https://developer.mozilla.org) | HTML/CSS/JS reference |
| Stack Overflow | Debugging every weird SSH edge case |
| Wireshark | Diagnosing IPv6 SYN black-hole |
| `python -m pdb` | Stepping through SSH auth failures |
| Postman or `curl` | Testing API endpoints before building the frontend |
| Browser DevTools (F12) | Debugging fetch calls and CSS layout |

---

## 7. Realistic Time Estimate

| Task | Estimated Time (solo, no AI) |
|---|---|
| Learn Paramiko basics + direct SSH | 1–2 days |
| Jump host tunneling | 1 day |
| Legacy KEX / algorithm compat | 1–2 days |
| Prompt detection + pagination | 1 day |
| Auth fallback logic | 0.5 day |
| Stage structure + config pull | 1 day |
| FastAPI wrapper | 1 day |
| HTML/CSS/JS frontend | 2–3 days |
| Debugging end-to-end | 1–2 days |
| **Total** | **~10–14 days** |

With AI assistance, this was built in a single session.

---

## 8. Key Takeaway

The hardest parts were not the code — they were the **edge cases**:
- Erlang SSH quirks on the vCMTS
- iCMTS E6000 legacy KEX requirements
- IPv6 DNS resolution hangs
- IOS-XR interactive shell vs exec_command

These are things you only discover by **running the code against real hardware**
and reading error messages carefully. No tutorial covers them. The debugging
experience you build doing this manually is what makes the difference between
someone who can copy code and someone who can fix it when it breaks at 2am.
