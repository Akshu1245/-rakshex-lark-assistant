#!/usr/bin/env python3
"""RaksHex Lark Assistant - Sign in with ChatGPT (open-source track).

Implements the documented dynamic-client flow:
https://developers.openai.com/siwc/token-sharing-open-source/sign-in.md

Run:  py siwc_client.py start        (Windows)
      python3 siwc_client.py start   (macOS/Linux)

Prints your sign-in link, then listens on http://127.0.0.1:1455/auth/callback
(the documented loopback). Open the link in a browser ON THIS COMPUTER, sign
in, approve - the redirect is captured automatically and the code is
exchanged. No link or code is ever pasted anywhere.
Re-running start re-authenticates; the previously issued client_id is reused
(per the documented flow) and new credentials atomically replace the old.

Credentials live only on this computer under
~/.config/rakshex-lark-assistant/ - DPAPI-encrypted on Windows, owner-only
(0600) elsewhere. The ID token is validated against OpenAI's published JWKS
(alg pinned to RS256, signature, issuer, audience, expiry, nonce) before
anything is saved. Nothing secret is printed or logged.

Python 3.10+ standard library only (plus credstore.py from this package).
"""
import base64, hashlib, html, json, os, secrets, sys, time, uuid
import urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

import credstore

AUTHORIZE = "https://auth.openai.com/api/accounts/authorize"
TOKEN_URL = "https://auth.openai.com/api/accounts/oauth/token"
JWKS_URL = "https://auth.openai.com/.well-known/jwks.json"
ISSUER = "https://auth.openai.com"
RESOURCE = "https://api.openai.com/v1"
LISTEN_HOST, LISTEN_PORT, CALLBACK_PATH = "127.0.0.1", 1455, "/auth/callback"
REDIRECT = "http://%s:%d%s" % (LISTEN_HOST, LISTEN_PORT, CALLBACK_PATH)
LISTEN_TIMEOUT = 600          # seconds the listener waits for the callback
HTTP_TIMEOUT = 30             # seconds, every network call
SCOPES = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
AGENT_NAME = "RaksHex Lark Assistant"
CONFIG_DIR = os.path.expanduser("~/.config/rakshex-lark-assistant")
PENDING = os.path.join(CONFIG_DIR, "pending.json")
CREDS = os.path.join(CONFIG_DIR, "credentials.json")
HOST_ID_FILE = os.path.join(CONFIG_DIR, "host_id")


def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def host_id():
    if os.path.exists(HOST_ID_FILE):
        return open(HOST_ID_FILE).read().strip()
    value = "urn:uuid:" + str(uuid.uuid4())
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(HOST_ID_FILE, "w") as f:
        f.write(value)
    if os.name != "nt":
        os.chmod(HOST_ID_FILE, 0o600)
    return value


def rsa_verify_rs256(message, signature, n_b64, e_b64):
    """RSASSA-PKCS1-v1_5 with SHA-256, verified with plain integer arithmetic."""
    n = int.from_bytes(b64url_decode(n_b64), "big")
    e = int.from_bytes(b64url_decode(e_b64), "big")
    s = int.from_bytes(signature, "big")
    m = pow(s, e, n).to_bytes((n.bit_length() + 7) // 8, "big")
    digest = hashlib.sha256(message).digest()
    der_prefix = bytes.fromhex("3031300d060960864801650304020105000420")
    if not m.startswith(b"\x00\x01"):
        return False
    try:
        sep = m.index(b"\x00", 2)
    except ValueError:
        return False
    padding = m[2:sep]
    return len(padding) >= 8 and all(b == 0xFF for b in padding) and m[sep + 1:] == der_prefix + digest


def validate_id_token(id_token, client_id, expected_nonce):
    """alg pinned to RS256; signature (OpenAI JWKS), issuer, audience, expiry, nonce."""
    header_b64, payload_b64, sig_b64 = id_token.split(".")
    header = json.loads(b64url_decode(header_b64))
    payload = json.loads(b64url_decode(payload_b64))
    if header.get("alg") != "RS256":
        raise ValueError("unexpected ID token alg: %r" % header.get("alg"))
    with urllib.request.urlopen(JWKS_URL, timeout=HTTP_TIMEOUT) as r:
        jwks = json.load(r)
    key = next((k for k in jwks["keys"] if k.get("kid") == header.get("kid")), None)
    if key is None:
        raise ValueError("no matching JWKS key")
    if not rsa_verify_rs256((header_b64 + "." + payload_b64).encode(), b64url_decode(sig_b64), key["n"], key["e"]):
        raise ValueError("ID token signature invalid")
    if payload.get("iss") != ISSUER:
        raise ValueError("issuer mismatch")
    aud = payload.get("aud")
    if client_id not in (aud if isinstance(aud, list) else [aud]):
        raise ValueError("audience mismatch")
    if payload.get("exp", 0) < time.time():
        raise ValueError("ID token expired")
    if payload.get("nonce") != expected_nonce:
        raise ValueError("nonce mismatch")
    return payload


def existing_client_id():
    """The client_id issued on a previous sign-in; reused for re-auth per the doc."""
    try:
        return credstore.load_json(CREDS).get("client_id")
    except (OSError, ValueError, RuntimeError):
        return None


def build_authorize_url():
    verifier = b64url(secrets.token_bytes(64))
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())
    state, nonce = b64url(secrets.token_bytes(32)), b64url(secrets.token_bytes(32))
    cid = existing_client_id()
    credstore.save_json(PENDING, {"verifier": verifier, "state": state, "nonce": nonce,
                                  "redirect_uri": REDIRECT, "host_id": host_id(),
                                  "client_id": cid, "created_at": time.time()})
    params = {
        "response_type": "code",
        "redirect_uri": REDIRECT,
        "scope": SCOPES,
        "resource": RESOURCE,
        "state": state,
        "nonce": nonce,
        "code_challenge_method": "S256",
        "code_challenge": challenge,
    }
    if cid:
        params["client_id"] = cid  # re-auth with the previously issued client_id
    else:
        params.update({"client_id": "dynamic_agent_client",
                       "agent_name_hint": AGENT_NAME,
                       "ext_agent_host_id": host_id()})
    return AUTHORIZE + "?" + urllib.parse.urlencode(params)


def complete_flow(query_string):
    """Validate callback, exchange the code, validate the ID token, store credentials.
    Returns True when ChatGPT plan usage (chatgpt.tokens.use.direct) was granted."""
    qs = urllib.parse.parse_qs(query_string)
    pend = credstore.load_json(PENDING)
    # state is validated FIRST - on error callbacks too (OAuth requirement)
    if qs.get("state", [""])[0] != pend["state"]:
        raise RuntimeError("state mismatch - rejected")
    if "error" in qs:
        raise RuntimeError("authorization returned error: %s" % qs["error"][0])
    if time.time() - pend.get("created_at", 0) > LISTEN_TIMEOUT:
        raise RuntimeError("sign-in attempt expired - run start again")
    code = qs["code"][0]
    callback_cid = qs.get("client_id", [None])[0]
    if pend.get("client_id") and callback_cid and callback_cid != pend["client_id"]:
        raise RuntimeError("callback client_id does not match the saved registration - rejected")
    client_id = callback_cid or pend.get("client_id")
    if not client_id:
        raise RuntimeError("no issued client_id in callback - registration incomplete")
    body = urllib.parse.urlencode({
        "grant_type": "authorization_code", "client_id": client_id, "code": code,
        "code_verifier": pend["verifier"], "redirect_uri": pend["redirect_uri"],
        "resource": RESOURCE}).encode()
    req = urllib.request.Request(TOKEN_URL, data=body,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
        tok = json.load(r)
    scopes = tok.get("scope", "").split()
    payload = validate_id_token(tok["id_token"], client_id, pend["nonce"])
    plan = "chatgpt.tokens.use.direct" in scopes
    record = {
        "email": payload.get("email"),
        "issuer": payload.get("iss"),
        "subject": payload.get("sub"),
        "client_id": client_id,
        "ext_agent_host_id": pend["host_id"],
        "id_token": tok["id_token"],
        "access_token": tok["access_token"],
        "refresh_token": tok.get("refresh_token"),
        "token_type": tok.get("token_type", "Bearer"),
        "expires_in": tok.get("expires_in", 3600),
        "scopes": scopes,
        "plan_enabled": plan,
        "reauth_required": False,
        "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "saved_at_epoch": time.time(),
    }
    credstore.save_json(CREDS, record)
    try:
        os.remove(PENDING)
    except OSError:
        pass
    return plan


def start(timeout=LISTEN_TIMEOUT):
    """Print the sign-in link and run the loopback listener until the callback
    arrives or the monotonic deadline passes. Returns the result dict."""
    url = build_authorize_url()
    result = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != CALLBACK_PATH:
                self.send_error(404)
                return
            try:
                result["ok"] = complete_flow(parsed.query)
                page = (b"<h3>RaksHex Lark Assistant connected.</h3>"
                        b"<p>You can close this tab and return to the terminal.</p>")
                self.send_response(200)
            except Exception as exc:
                result["error"] = str(exc)
                page = ("<h3>Sign-in failed: %s</h3><p>Return to the terminal and run start again.</p>"
                        % html.escape(str(exc))).encode()
                self.send_response(400)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(page)

        def log_message(self, *args):  # the callback URL carries the code: never log it
            pass

    server = HTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    server.timeout = 0.5
    print("Open this link in a browser ON THIS COMPUTER:\n")
    print(url)
    print("\nSign in and approve. Listening for the secure callback (%d s timeout)..." % timeout)
    deadline = time.monotonic() + timeout
    while "ok" not in result and "error" not in result:
        if time.monotonic() >= deadline:
            result["error"] = "timeout"
            break
        server.handle_request()
    server.server_close()
    return result


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "start":
        res = start()
        if res.get("ok") is True:
            print("\nConnected. ChatGPT plan usage is ENABLED for this assistant.")
            print("Credentials stored at %s (protected local storage)." % CREDS)
        elif res.get("ok") is False:
            print("\nSigned in, but ChatGPT plan usage was NOT granted (identity only).")
            print("The assistant will explain options when run; check ChatGPT Settings > Usage.")
        else:
            print("\nFailed: %s" % res.get("error", "unknown"))
            sys.exit(1)
    else:
        print("usage: siwc_client.py start")
