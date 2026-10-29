#!/usr/bin/env python3
"""Offline mocked tests for the RaksHex Lark Assistant hardening.
No real accounts, tokens or external network: a local mock server stands in for
OpenAI endpoints, and lark_oapi is stubbed. Covers: credstore, full mocked SIWC
flow (loopback listener, JWKS validation, protected storage, re-auth client_id
reuse), listener deadline, HTML escaping, owner gate / group silence / dedup /
null guards, model caching, serialized refresh, invalid_grant recovery.
Run from the package dir: python3 test_hardening.py
Requires: pip install cryptography (test-only dependency)
"""
import base64, io, json, os, sys, tempfile, threading, time, types
import urllib.error, urllib.parse, urllib.request
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import credstore, siwc_client as siwc

fails = 0
def check(name, cond, extra=""):
    global fails
    if not cond:
        fails += 1
    print(("PASS" if cond else "FAIL"), name, extra)

TMP = tempfile.mkdtemp()
def p(n): return os.path.join(TMP, n)

# --- credstore -------------------------------------------------------------
fresh = os.path.join(TMP, "brand", "new", "dir")  # does not exist yet
credstore.save_json(os.path.join(fresh, "fresh.json"), {"fresh": True})
check("save_json creates missing parent dirs (fresh machine)",
      credstore.load_json(os.path.join(fresh, "fresh.json")) == {"fresh": True})
credstore.save_json(p("c.json"), {"a": 1})
check("credstore round trip", credstore.load_json(p("c.json")) == {"a": 1})
if os.name != "nt":
    check("POSIX 0600 owner-only", oct(os.stat(p("c.json")).st_mode & 0o777) == "0o600")
    raw = open(p("c.json"), "rb").read()
    check("POSIX plaintext JSON on disk", b'"a"' in raw)
else:
    check("Windows DPAPI ciphertext on disk", b"dpapi-current-user" in open(p("c.json"), "rb").read())

# --- mocked OpenAI endpoints ------------------------------------------------
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

def b64url(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
nums = KEY.public_key().public_numbers()
JWKS = {"keys": [{"kty": "RSA", "kid": "k1", "alg": "RS256",
                  "n": b64url(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")),
                  "e": b64url(nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big"))}]}
ISSUED_CID = "oaiapp_test_client"

def make_jwt(nonce):
    h = b64url(json.dumps({"alg": "RS256", "typ": "JWT", "kid": "k1"}).encode())
    pl = b64url(json.dumps({"iss": siwc.ISSUER, "aud": ISSUED_CID, "sub": "u1",
                            "email": "o@example.com", "exp": int(time.time()) + 600,
                            "nonce": nonce}).encode())
    sig = KEY.sign((h + "." + pl).encode(), padding.PKCS1v15(), hashes.SHA256())
    return h + "." + pl + "." + b64url(sig)

class MockOpenAI(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        body = json.dumps(JWKS).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.end_headers(); self.wfile.write(body)
    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        pend = credstore.load_json(siwc.PENDING)  # nonce issued by the flow under test
        body = json.dumps({"id_token": make_jwt(pend["nonce"]), "access_token": "at-1",
                           "refresh_token": "rt-1", "token_type": "Bearer",
                           "expires_in": 3600, "scope": siwc.SCOPES}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.end_headers(); self.wfile.write(body)

siwc.CONFIG_DIR = TMP
siwc.PENDING = p("pending.json")
siwc.CREDS = p("creds.json")
siwc.HOST_ID_FILE = p("host_id")
mock = ThreadingHTTPServer(("127.0.0.1", 0), MockOpenAI)
port = mock.server_address[1]
threading.Thread(target=mock.serve_forever, daemon=True).start()
siwc.TOKEN_URL = "http://127.0.0.1:%d/token" % port
siwc.JWKS_URL = "http://127.0.0.1:%d/jwks" % port

# --- first-run authorize URL: dynamic registration --------------------------
url_first = siwc.build_authorize_url()
q = urllib.parse.parse_qs(urllib.parse.urlparse(url_first).query)
check("first run uses dynamic registration",
      q.get("client_id") == ["dynamic_agent_client"] and "agent_name_hint" in q
      and q.get("ext_agent_host_id", [""])[0].startswith("urn:uuid:"))

# --- full mocked flow through the real loopback listener --------------------
holder = {}
t = threading.Thread(target=lambda: holder.setdefault("r", siwc.start(timeout=20)))
t.start()
time.sleep(0.8)
pend = credstore.load_json(siwc.PENDING)
cb = "http://127.0.0.1:1455/auth/callback?" + urllib.parse.urlencode(
    {"code": "code-1", "state": pend["state"], "client_id": ISSUED_CID})
with urllib.request.urlopen(cb, timeout=5) as r:
    r.read()
t.join(15)
res = holder.get("r", {})
check("mocked flow completes via loopback listener", res.get("ok") is True, str(res))
creds = credstore.load_json(p("creds.json"))
check("credentials saved: identity + plan flag + client_id",
      creds.get("email") == "o@example.com" and creds.get("plan_enabled") is True
      and creds.get("client_id") == ISSUED_CID)
check("pending PKCE/state file cleaned up", not os.path.exists(p("pending.json")))
url_re = siwc.build_authorize_url()
q2 = urllib.parse.parse_qs(urllib.parse.urlparse(url_re).query)
check("re-auth reuses issued client_id (no dynamic registration)",
      q2.get("client_id") == [ISSUED_CID] and "dynamic_agent_client" not in url_re)
mock.shutdown()

# --- listener deadline -------------------------------------------------------
t0 = time.monotonic()
res = siwc.start(timeout=1)
el = time.monotonic() - t0
check("listener honors monotonic deadline", res.get("error") == "timeout" and el < 8, "(%.1fs)" % el)

# --- HTML escaping of error callback ----------------------------------------
holder = {}
t = threading.Thread(target=lambda: holder.setdefault("r", siwc.start(timeout=10)))
t.start()
time.sleep(0.8)
pend = credstore.load_json(siwc.PENDING)
page = ""
try:
    urllib.request.urlopen("http://127.0.0.1:1455/auth/callback?" + urllib.parse.urlencode(
        {"error": "<script>alert(1)</script>", "state": pend["state"]}), timeout=5)
except urllib.error.HTTPError as e:
    page = e.read().decode("utf-8", "replace")
t.join(10)
check("callback error page escapes injected markup",
      "&lt;script&gt;" in page and "<script>alert" not in page)

holder = {}
t = threading.Thread(target=lambda: holder.setdefault("r", siwc.start(timeout=10)))
t.start()
time.sleep(0.8)
page = ""
try:
    urllib.request.urlopen("http://127.0.0.1:1455/auth/callback?" + urllib.parse.urlencode(
        {"error": "access_denied", "state": "forged-state"}), timeout=5)
except urllib.error.HTTPError as e:
    page = e.read().decode("utf-8", "replace")
t.join(10)
check("state validated even on error callback",
      "state mismatch" in page and "access_denied" not in page)

holder = {}
t = threading.Thread(target=lambda: holder.setdefault("r", siwc.start(timeout=10)))
t.start()
time.sleep(0.8)
pend = credstore.load_json(siwc.PENDING)
page = ""
try:
    urllib.request.urlopen("http://127.0.0.1:1455/auth/callback?" + urllib.parse.urlencode(
        {"code": "code-2", "state": pend["state"], "client_id": "someone_elses_client"}), timeout=5)
except urllib.error.HTTPError as e:
    page = e.read().decode("utf-8", "replace")
t.join(10)
check("reauth callback client_id must match saved registration",
      "does not match the saved registration" in page)

# --- bot.py: gate, group silence, dedup, null guards -------------------------
fake = types.ModuleType("lark_oapi")
api = types.ModuleType("lark_oapi.api.im.v1")
class P2ImMessageReceiveV1: pass
class _B:
    def __getattr__(self, n): return lambda *a, **k: self
    def build(self): return self
class CreateMessageRequest:
    @staticmethod
    def builder(): return _B()
class CreateMessageRequestBody:
    @staticmethod
    def builder(): return _B()
api.P2ImMessageReceiveV1 = P2ImMessageReceiveV1
api.CreateMessageRequest = CreateMessageRequest
api.CreateMessageRequestBody = CreateMessageRequestBody
sys.modules["lark_oapi"] = fake
sys.modules["lark_oapi.api.im.v1"] = api

import bot

class SyncExec:
    def submit(self, fn, *a, **k): fn(*a, **k)
bot._executor = SyncExec()
bot.CREDS = p("bot_creds.json")
bot.REFRESH_LOCK = p("bot_creds.refresh.lock")
credstore.save_json(bot.CREDS, {"client_id": "c1", "scopes": [bot.PLAN_SCOPE],
                                "access_token": "tok", "refresh_token": "rt",
                                "expires_in": 3600, "saved_at_epoch": time.time()})
calls = []
bot.ask_openai = lambda t: calls.append(t) or "ans"
class Obj: pass
class Resp:
    def success(self): return True
bot.lark_client = Obj()
bot.lark_client.im = Obj(); bot.lark_client.im.v1 = Obj(); bot.lark_client.im.v1.message = Obj()
replies = []
bot.lark_client.im.v1.message.create = lambda req: replies.append(req) or Resp()
bot.LARK_CFG = {"owner_open_ids": ["ou_owner"]}

def mk(chat_type, text, sender="ou_owner", mid=None):
    d = Obj(); d.event = Obj()
    d.event.message = Obj(); d.event.sender = Obj(); d.event.sender.sender_id = Obj()
    m = d.event.message
    m.chat_type = chat_type; m.content = json.dumps({"text": text})
    m.message_type = "text"; m.chat_id = "oc_x"
    if mid: m.message_id = mid
    d.event.sender.sender_id.open_id = sender
    return d

calls.clear(); replies.clear()
bot.on_message(mk("p2p", "hi", "ou_attacker", "m1"))
check("non-owner p2p never reaches OpenAI", calls == [] and replies == [])

calls.clear()
bot.on_message(mk("p2p", "hello bot", "ou_owner", "m2"))
check("owner p2p served", calls == ["hello bot"] and len(replies) == 1)

calls.clear(); replies.clear()
bot.on_message(mk("group", "hi all", "ou_owner", "m3"))
check("owner group message ignored (groups disabled)", calls == [] and replies == [])

calls.clear(); replies.clear()
bot.on_message(mk("p2p", "once", "ou_owner", "m4"))
bot.on_message(mk("p2p", "once", "ou_owner", "m4"))  # redelivery
check("duplicate message_id answered once", calls == ["once"] and len(replies) == 1)

d = mk("p2p", "hi"); d.event.sender.sender_id = None
try:
    bot.on_message(d)
    check("null sender_id handled without crash", True)
except AttributeError:
    check("null sender_id handled without crash", False)

calls.clear(); replies.clear()
bot.LARK_CFG = {"owner_open_ids": []}
bot.on_message(mk("p2p", "hi", "ou_new", "m5"))
check("setup mode (empty allowlist) serves nobody", calls == [] and replies == [])
bot.LARK_CFG = {"owner_open_ids": ["ou_owner"]}

# --- identity-only honesty ---------------------------------------------------
credstore.save_json(bot.CREDS, {"client_id": "c1", "scopes": ["openid", "profile", "email"],
                                "access_token": "tok", "refresh_token": "rt",
                                "expires_in": 3600, "saved_at_epoch": time.time()})
calls.clear(); replies.clear()
bot.on_message(mk("p2p", "question", "ou_owner", "m6"))
check("identity-only: honest reply, no OpenAI call",
      calls == [] and len(replies) == 1)

# --- model caching -----------------------------------------------------------
class FakeResp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): pass
real_urlopen = urllib.request.urlopen
hits = {"models": 0}
def fake_models(req, timeout=None, **kw):
    hits["models"] += 1
    return FakeResp(json.dumps({"models": [{"slug": "gpt-x", "visibility": "list"}]}).encode())
urllib.request.urlopen = fake_models
bot._model_cache = None
m1 = bot.pick_model("tok"); m2 = bot.pick_model("tok")
urllib.request.urlopen = real_urlopen
check("model fetched once and cached", m1 == "gpt-x" and m2 == "gpt-x" and hits["models"] == 1)

# --- serialized refresh ------------------------------------------------------
credstore.save_json(bot.CREDS, {"client_id": "c1", "scopes": [bot.PLAN_SCOPE],
                                "access_token": "old", "refresh_token": "rt1",
                                "expires_in": 1, "saved_at_epoch": 0})
rc = {"n": 0}
def fake_refresh(req, timeout=None, **kw):
    rc["n"] += 1
    time.sleep(0.2)  # widen any race window
    return FakeResp(json.dumps({"access_token": "fresh", "refresh_token": "rt2",
                                "expires_in": 3600}).encode())
urllib.request.urlopen = fake_refresh
results, errs = [], []
def worker():
    try:
        results.append(bot.access_token())
    except Exception as e:
        errs.append(e)
ts = [threading.Thread(target=worker) for _ in range(5)]
[t.start() for t in ts]; [t.join() for t in ts]
urllib.request.urlopen = real_urlopen
check("concurrent refresh serialized to one HTTP call",
      rc["n"] == 1 and results == ["fresh"] * 5 and not errs, "(%d refreshes)" % rc["n"])
check("refresh rotated + stored protected", credstore.load_json(bot.CREDS)["refresh_token"] == "rt2")

# --- documented refresh-failure recovery --------------------------------------
for err_name in ("invalid_grant", "refresh_token_reused", "token_expired",
                 "invalid_refresh_token", "refresh_token_expired", "refresh_token_invalidated"):
    credstore.save_json(bot.CREDS, {"client_id": "c1", "scopes": [bot.PLAN_SCOPE],
                                    "access_token": "old", "refresh_token": "rt-dead",
                                    "expires_in": 1, "saved_at_epoch": 0})
    def fake_reject(req, timeout=None, _e=err_name, **kw):
        raise urllib.error.HTTPError(req.full_url, 400, "Bad Request", None,
                                     io.BytesIO(json.dumps({"error": _e}).encode()))
    urllib.request.urlopen = fake_reject
    try:
        bot.access_token()
        check("%s raises ReauthRequired" % err_name, False)
    except bot.ReauthRequired:
        check("%s raises ReauthRequired" % err_name, True)
stored = credstore.load_json(bot.CREDS)
check("tokens cleared, identity kept, reauth flagged",
      stored.get("reauth_required") is True and "access_token" not in stored
      and "refresh_token" not in stored and stored.get("client_id") == "c1")
def no_http(req, timeout=None, **kw):
    raise AssertionError("HTTP attempted during reauth state")
urllib.request.urlopen = no_http
try:
    bot.access_token()
    check("reauth state short-circuits without HTTP", False)
except bot.ReauthRequired:
    check("reauth state short-circuits without HTTP", True)
except AssertionError:
    check("reauth state short-circuits without HTTP", False)
urllib.request.urlopen = real_urlopen

print("FAILURES:", fails)
sys.exit(1 if fails else 0)
