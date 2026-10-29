#!/usr/bin/env python3
"""RaksHex Lark Assistant - a personal AI assistant inside Lark.

OWNER-ONLY, DIRECT MESSAGES ONLY: it answers direct (p2p) messages from the
Lark accounts listed in owner_open_ids, and nothing else. Group chats are
ignored entirely - nobody else can draw on the owner's ChatGPT plan, and no
group message ever reaches OpenAI.

Each reply is a ChatGPT plan usage request through Sign in with ChatGPT
(open-source track), using the owner's own ChatGPT Plus/Pro allowance. No
OpenAI API key, no billing.

Privacy: text of messages sent to the bot goes to OpenAI (api.openai.com) as
inference input. Do not send secrets or customer data to the bot.

Requires: py -m pip install -r requirements.txt   (lark-oapi 1.7.5, pinned)
Config:   ~/.config/rakshex-lark-assistant/credentials.json  (from siwc_client.py)
          ~/.config/rakshex-lark-assistant/lark_app.json
          ({"app_id": "...", "app_secret": "...", "owner_open_ids": ["ou_..."]})
"""
import atexit, json, os, sys, threading, time
import urllib.error, urllib.parse, urllib.request
from collections import deque
from concurrent.futures import ThreadPoolExecutor

import lark_oapi as lark
from lark_oapi.api.im.v1 import P2ImMessageReceiveV1, CreateMessageRequest, CreateMessageRequestBody

import credstore

CONFIG_DIR = os.path.expanduser("~/.config/rakshex-lark-assistant")
CREDS = os.path.join(CONFIG_DIR, "credentials.json")
LARK_APP = os.path.join(CONFIG_DIR, "lark_app.json")
REFRESH_LOCK = CREDS + ".refresh.lock"
RUN_LOCK = os.path.join(CONFIG_DIR, "bot.running.lock")
TOKEN_URL = "https://auth.openai.com/api/accounts/oauth/token"
RESOURCE = "https://api.openai.com/v1"
HTTP_TIMEOUT = 30      # seconds, every one-shot HTTP call
STREAM_TIMEOUT = 120   # seconds, the streaming Responses call
PLAN_SCOPE = "chatgpt.tokens.use.direct"
DEDUP_KEEP = 500
SYSTEM = ("You are the user's personal assistant inside Lark. Answer plainly and briefly. "
          "You have no access to their files or accounts beyond this chat.")


class ReauthRequired(RuntimeError):
    """The stored sign-in can no longer be refreshed; re-run siwc_client.py start."""


# documented refresh-failure codes that mean "sign in again" (errors-and-recovery.md)
REAUTH_ERRORS = ("invalid_grant", "refresh_token_reused", "token_expired",
                 "invalid_refresh_token", "refresh_token_expired", "refresh_token_invalidated")


_refresh_lock = threading.Lock()          # serializes refresh inside this process
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="assistant")
_model_cache = None                        # model slug, fetched once per process
LARK_CFG = {}
_seen_lock = threading.Lock()
_seen_ids = deque()
_seen_set = set()


def _note_message_id(mid):
    """Event dedup: Lark redelivers events; answer each message_id once."""
    if mid is None:
        return True
    with _seen_lock:
        if mid in _seen_set:
            return False
        _seen_ids.append(mid)
        _seen_set.add(mid)
        while len(_seen_ids) > DEDUP_KEEP:
            _seen_set.discard(_seen_ids.popleft())
        return True


def access_token():
    """A valid access token. Refresh is serialized (in-process lock + cross-process
    lock file) and atomically rotated. Refresh-token rejection (invalid_grant)
    clears the stored tokens and raises ReauthRequired."""
    with _refresh_lock:
        creds = credstore.load_json(CREDS)
        if creds.get("reauth_required"):
            raise ReauthRequired("sign-in expired; re-run siwc_client.py start")
        if creds.get("access_token") and \
                time.time() < creds.get("saved_at_epoch", 0) + creds.get("expires_in", 3600) - 300:
            return creds["access_token"]
        with credstore.file_lock(REFRESH_LOCK):
            creds = credstore.load_json(CREDS)  # re-read: another process may have refreshed
            if creds.get("reauth_required"):
                raise ReauthRequired("sign-in expired; re-run siwc_client.py start")
            if creds.get("access_token") and \
                    time.time() < creds.get("saved_at_epoch", 0) + creds.get("expires_in", 3600) - 300:
                return creds["access_token"]
            body = urllib.parse.urlencode({
                "grant_type": "refresh_token", "client_id": creds["client_id"],
                "refresh_token": creds["refresh_token"], "resource": RESOURCE}).encode()
            req = urllib.request.Request(TOKEN_URL, data=body,
                                         headers={"Content-Type": "application/x-www-form-urlencoded"})
            try:
                with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
                    tok = json.load(r)
            except urllib.error.HTTPError as e:
                detail = ""
                try:
                    detail = e.read().decode("utf-8", "replace")
                except Exception:
                    pass
                err_code = None
                try:
                    err_code = json.loads(detail).get("error")
                except ValueError:
                    pass
                if e.code in (400, 401) and (
                        err_code in REAUTH_ERRORS
                        or (err_code is None and any(x in detail for x in REAUTH_ERRORS))):
                    # refresh token rejected/reused: drop tokens, keep identity + client_id
                    for k in ("access_token", "refresh_token", "id_token"):
                        creds.pop(k, None)
                    creds["reauth_required"] = True
                    credstore.save_json(CREDS, creds)
                    raise ReauthRequired("refresh rejected (invalid_grant); re-run siwc_client.py start")
                raise
            creds.update({"access_token": tok["access_token"],
                          "refresh_token": tok.get("refresh_token", creds["refresh_token"]),
                          "expires_in": tok.get("expires_in", 3600),
                          "saved_at_epoch": time.time(),
                          "reauth_required": False})
            credstore.save_json(CREDS, creds)  # same protected writer, atomic rotation
            return creds["access_token"]


def pick_model(token):
    """Verified-at-runtime model choice: ASSISTANT_MODEL env wins; otherwise the first
    list-visible slug in the signed-in account's own catalog (GET /v1/models).
    Fetched once per process and cached."""
    global _model_cache
    env = os.environ.get("ASSISTANT_MODEL")
    if env:
        return env
    if _model_cache:
        return _model_cache
    req = urllib.request.Request(RESOURCE + "/models", headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
        catalog = json.load(r)
    for m in catalog.get("models", []):
        if m.get("visibility") == "list":
            _model_cache = m["slug"]
            return _model_cache
    raise RuntimeError("no list-visible model in this account's catalog")


def ask_openai(user_text):
    """One stateless ChatGPT plan usage request (SIWC constraints: store false, stream true).
    Request shape follows the documented example: role/content input items."""
    token = access_token()
    payload = {"model": pick_model(token),
               "store": False, "stream": True,
               "instructions": SYSTEM,
               "input": [{"role": "user", "content": user_text}]}
    req = urllib.request.Request(RESOURCE + "/responses", data=json.dumps(payload).encode(),
                                 headers={"Authorization": "Bearer " + token,
                                          "Content-Type": "application/json", "Accept": "text/event-stream"})
    try:
        ctx = urllib.request.urlopen(req, timeout=STREAM_TIMEOUT)
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", "replace")
        except Exception:
            pass
        code = None
        try:
            code = json.loads(detail).get("error", {}).get("code")
        except (ValueError, AttributeError):
            pass
        raise RuntimeError("OpenAI request failed (HTTP %s%s)" % (e.code, ": " + code if code else ""))
    out = []
    with ctx as r:
        for line in r:
            line = line.decode("utf-8", "replace").strip()
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                break
            try:
                ev = json.loads(data)
            except json.JSONDecodeError:
                continue
            if ev.get("type") == "response.output_text.delta":
                out.append(ev.get("delta", ""))
            elif ev.get("type") == "response.failed":
                err = (ev.get("response") or {}).get("error") or {}
                raise RuntimeError("response failed: %s" % (err.get("code") or "unknown_error"))
            elif ev.get("type") == "response.completed":
                resp = ev.get("response", {})
                for item in resp.get("output", []):
                    for part in item.get("content", []):
                        if part.get("type") == "output_text":
                            return part.get("text", "").strip()
    return "".join(out).strip() or "(empty response)"


def _reply(chat_id, answer):
    body = CreateMessageRequestBody.builder().receive_id(chat_id).msg_type("text") \
        .content(json.dumps({"text": answer})).build()
    req = CreateMessageRequest.builder().receive_id_type("chat_id").request_body(body).build()
    resp = lark_client.im.v1.message.create(req)
    if not resp.success():
        print("send failed:", resp.code, resp.msg, file=sys.stderr)


def _answer_and_reply(chat_id, text):
    """Runs on a worker thread so the SDK event loop is never blocked by inference."""
    try:
        creds = credstore.load_json(CREDS)
    except Exception:
        creds = {}
    try:
        if PLAN_SCOPE not in creds.get("scopes", []):
            answer = ("I'm signed in, but ChatGPT plan usage isn't enabled for me, so I can't "
                      "answer yet. Check ChatGPT Settings > Usage for this app, or re-run the "
                      "sign-in step on your computer.")
        else:
            answer = ask_openai(text)
    except ReauthRequired:
        answer = ("My saved sign-in expired and could not be renewed. Please re-run the sign-in "
                  "step on your computer (siwc_client.py start) - it reuses the existing app "
                  "registration - then message me again.")
    except Exception as e:  # surface failure honestly, never fake a reply
        answer = "I could not get a response right now (%s)." % type(e).__name__
    _reply(chat_id, answer)


def on_message(data: P2ImMessageReceiveV1):
    ev = getattr(data, "event", None)
    msg = getattr(ev, "message", None)
    if msg is None:
        return
    sender_id = getattr(getattr(ev, "sender", None), "sender_id", None)
    open_id = getattr(sender_id, "open_id", None)
    chat_id = getattr(msg, "chat_id", None)
    chat_type = getattr(msg, "chat_type", None)
    if not open_id or not chat_id or not chat_type:
        return
    if not _note_message_id(getattr(msg, "message_id", None)):
        return  # duplicate delivery
    # OWNER GATE: this assistant runs on one person's ChatGPT plan. It answers ONLY
    # Lark accounts listed in owner_open_ids. Anyone else gets silence (and their
    # message never reaches OpenAI). Empty list = setup mode: nobody is served and
    # each sender's open_id is printed to THIS local console so the owner can
    # complete the allowlist during setup. Open IDs are per-app; the bot cannot
    # know the owner's ID before first contact.
    owners = LARK_CFG.get("owner_open_ids", [])
    if open_id not in owners:
        if not owners:
            print("setup: message from open_id %s - add it to owner_open_ids in %s to allow this account"
                  % (open_id, LARK_APP), flush=True)
        return
    if chat_type != "p2p":
        return  # group chats are ignored entirely (no group audience approved)
    if getattr(msg, "message_type", None) != "text":
        return
    try:
        text = json.loads(getattr(msg, "content", "") or "").get("text", "").strip()
    except (json.JSONDecodeError, TypeError, AttributeError):
        return
    if not text:
        return
    _executor.submit(_answer_and_reply, chat_id, text)


def _load_lark_cfg():
    cfg = credstore.load_json(LARK_APP)
    if credstore.IS_WINDOWS:
        # upgrade a hand-written plaintext lark_app.json to DPAPI-protected storage
        with open(LARK_APP, "rb") as f:
            raw = json.loads(f.read())
        if not (isinstance(raw, dict) and raw.get("protection")):
            credstore.save_json(LARK_APP, cfg)
    else:
        # published package on Unix: enforce owner-only permissions on the app secret
        if os.stat(LARK_APP).st_mode & 0o777 != 0o600:
            os.chmod(LARK_APP, 0o600)
    return cfg


def _acquire_run_lock():
    """Single instance: refuse to start if the lock exists (stop the other run or
    delete the stale lock file)."""
    try:
        fd = os.open(RUN_LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(fd)
    except FileExistsError:
        print("Another instance appears to be running (lock: %s)." % RUN_LOCK)
        print("Stop it first, or delete that file if it was left behind by a crash.")
        sys.exit(1)
    atexit.register(lambda: os.path.exists(RUN_LOCK) and os.remove(RUN_LOCK))


if __name__ == "__main__":
    if not os.path.exists(CREDS):
        print("No saved sign-in. Run siwc_client.py start first.")
        sys.exit(1)
    LARK_CFG = _load_lark_cfg()
    _acquire_run_lock()
    app = LARK_CFG
    lark_client = lark.Client.builder().app_id(app["app_id"]).app_secret(app["app_secret"]) \
        .domain(lark.LARK_DOMAIN).log_level(lark.LogLevel.INFO).build()
    handler = lark.EventDispatcherHandler.builder("", "").register_p2_im_message_receive_v1(on_message).build()
    # ws.Client signature verified against lark-oapi 1.7.5 (installed): kwargs below are valid;
    # LARK_DOMAIN = https://open.larksuite.com (Lark international, not Feishu).
    ws = lark.ws.Client(app["app_id"], app["app_secret"], event_handler=handler,
                        log_level=lark.LogLevel.INFO, domain=lark.LARK_DOMAIN)
    print("RaksHex Lark Assistant listening (long connection, owner-only p2p). Ctrl-C to stop.")
    ws.start()
