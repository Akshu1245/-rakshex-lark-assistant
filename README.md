# RaksHex Lark Assistant

A small personal AI assistant that lives inside Lark. It answers direct
messages from you, and only you. Replies use your own ChatGPT Plus/Pro plan
through OpenAI's Sign in with ChatGPT (open-source track) - no OpenAI API key
and no API billing.

## What it does

- Connects to Lark over the official SDK's long connection (WebSocket) - no
  public URL or paid hosting needed; it runs wherever you run it.
- Answers ONLY direct (p2p) messages from Lark accounts in `owner_open_ids`.
  Group chats are ignored entirely: no group message is ever answered or sent
  to OpenAI, and nobody else can spend your plan.
- On each message, sends the text to the OpenAI Responses API with
  `store: false` (stateless), and replies in the same chat.

## Privacy and credential storage

- Everything you send the bot goes to OpenAI (api.openai.com) as inference
  input, under your ChatGPT account. Don't send it secrets or customer data.
- Credentials live only on this machine in `~/.config/rakshex-lark-assistant/`.
  - Windows: encrypted with DPAPI (CryptProtectData) tied to YOUR Windows user
    account. Anyone logged into a different Windows account cannot read them;
    anyone logged into the SAME Windows account can - on a shared machine, use
    your own Windows account and lock it when away.
  - macOS/Linux: owner-only 0600 file permissions.
  - Token refresh reuses the same protected writer with atomic rotation.
- OpenAI conditions: this app is open source and locally hosted; usage draws
  from your plan's normal allowance (Plus: shared five-hour limit across all
  plan-using apps). You can set a weekly limit for the app in ChatGPT
  Settings > Usage, and disconnect it there at any time.

## Setup (Windows laptop; allow a few quiet minutes)

1. Install Python 3.10+ from python.org (tick "Add python.exe to PATH").
   Check: `py --version`.
2. `py -m pip install -r requirements.txt` (one runtime dependency:
   lark-oapi 1.7.5, Lark's official SDK; everything else is Python standard
   library. The optional offline test suite additionally needs the free
   `cryptography` package - tests only, never needed to run the assistant.)
   Optional pre-flight: `py windows_check.py` - confirms DPAPI protected
   storage works on this laptop. It installs nothing and uses no network.
3. Create the Lark app in the Lark Open Platform console (bot capability,
   `im:message` and the `im:message.receive_v1` event subscription) and save
   its credentials as `%USERPROFILE%\.config\rakshex-lark-assistant\lark_app.json`:
   `{"app_id": "cli_...", "app_secret": "...", "owner_open_ids": []}`
   The bot re-saves this file DPAPI-protected on first run.
4. Sign in with ChatGPT: `py siwc_client.py start`, open the printed link in a
   browser ON THIS LAPTOP, sign in and approve. The 127.0.0.1 callback is
   captured automatically - you never copy any link or code.
5. Run: `py bot.py`
6. Send the bot one direct message in Lark. It prints your open_id to its own
   console (setup mode serves nobody). Add that value to `owner_open_ids` in
   lark_app.json and restart `py bot.py`. Done.

## If sign-in expires

The bot tells you in chat. Re-run `py siwc_client.py start` on the laptop -
it reuses the previously issued client_id (the documented re-auth route) and
atomically replaces the stored credentials. Old refresh tokens that were
rejected or rotated are cleared automatically.

## Notes

- Model choice: `ASSISTANT_MODEL` env var wins; otherwise the first
  list-visible model in your account's own catalog, fetched once per run.
- Only one instance runs at a time; if a crash leaves `bot.running.lock`
  behind, delete it from the config folder.
- macOS/Linux: same steps with `python3` instead of `py`; storage is 0600
  files instead of DPAPI.
- Platform note: the Windows code paths are covered by offline mocked tests.
  `windows_check.py` verifies the DPAPI round trip natively on your machine
  before you trust it with real credentials - run it first.

## Files

- `siwc_client.py` - Sign in with ChatGPT (dynamic open-source client
  registration, PKCE, loopback listener, ID-token validation, token exchange).
  Implements https://developers.openai.com/siwc/token-sharing-open-source/sign-in.md
- `bot.py` - the Lark assistant (long connection + owner-gated reply loop)
- `credstore.py` - protected local credential storage (DPAPI / 0600) + locks
- `test_hardening.py` - offline mocked tests (no real accounts or network auth)
- `windows_check.py` - secrets-free Windows pre-flight (Python + DPAPI check)

## License

MIT (see LICENSE).
