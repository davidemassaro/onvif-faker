# onvif-faker

A minimal fake [ONVIF](https://www.onvif.org/) device server, built for security testing: it impersonates an ONVIF camera over HTTP and captures any credentials a client sends to it, both **HTTP Basic Auth** and **WS-Security `UsernameToken` (PasswordText)** from the SOAP body.

Useful for checking whether a VMS/NVR (e.g. Milestone) or any ONVIF client on your network still sends credentials in the clear, in an authorized pentest/lab setup — this is **not** an ONVIF discovery or exploitation tool, it only listens and logs.

## ⚠️ Disclaimer

This is an offensive/credential-harvesting tool. Only point real clients at it on networks and devices you own or are explicitly authorized to test. Captured credentials are real secrets — never commit `credentials.txt` or share it; it's already excluded via `.gitignore`.

## How it works

- Listens on `0.0.0.0:8000` and answers every `GET`/`POST` as if it were an ONVIF device.
- No `Authorization` header → replies `401` with `WWW-Authenticate: Basic`, prompting the client to resend with credentials.
- `Authorization: Basic ...` → decodes and logs `username`/`password`.
- SOAP body with a WS-Security `UsernameToken` (`Password` of type `PasswordText`) → parses and logs `username`/`password`.
- Replies to `GetCapabilities` with a minimal but valid ONVIF SOAP response (enough to pass as a real device); every other SOAP call gets a generic SOAP fault.
- Every capture is printed to stdout and appended to `credentials.txt` with a timestamp, source, client IP and request path.

No third-party dependencies — pure Python standard library.

## Usage

```bash
python main.py
```

```
[*] ONVIF fake server in ascolto su 0.0.0.0:8000
[*] Punta Milestone a: http://<your-lan-ip>:8000/onvif/device_service
[*] Credenziali salvate in: credentials.txt
[*] Ctrl+C per fermare
```

Point your ONVIF client (e.g. Milestone XProtect, or any NVR's "add device" flow) at:

```
http://<host>:8000/onvif/device_service
```

Captured credentials land in `credentials.txt`:

```
[2026-04-09 11:39:52] source=HTTP-Basic ip=10.0.0.5 username='admin' password='changeme' path=/onvif/device_service
```

## Limitations

- HTTP only (no HTTPS/TLS), single port (8000, hardcoded in `main.py`).
- Only emulates `GetCapabilities`; any other ONVIF method gets a generic SOAP fault, which is enough to trigger most clients' auth flow but won't fool a client that validates the full capability set.
- No persistence beyond the append-only `credentials.txt` log.
