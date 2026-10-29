#!/usr/bin/env python3
"""Windows pre-flight check for the RaksHex Lark Assistant. SAFE TO RUN FIRST.

Exactly what it does:
- prints your Python version (needs 3.10+)
- encrypts and decrypts one short test string with Windows DPAPI (tied to YOUR
  Windows user account) to confirm protected credential storage works on THIS
  machine, writing one small probe file inside
  %USERPROFILE%\\.config\\rakshex-lark-assistant and deleting it afterwards
It installs nothing, uses no network, creates no accounts, changes no settings,
and collects no secrets. Run:  py windows_check.py
"""
import os, sys


def main():
    print("RaksHex Lark Assistant - Windows pre-flight check")
    print("Checks Python version, then a DPAPI encrypt/decrypt round trip with a")
    print("test string. No installs, no network, no secrets, no lasting changes.\n")
    ok = True
    v = sys.version_info
    vok = v >= (3, 10)
    print("Python %d.%d.%d ... %s" % (v[0], v[1], v[2], "OK" if vok else "TOO OLD (need 3.10+)"))
    ok = ok and vok
    if os.name != "nt":
        print("Not Windows: DPAPI check skipped (macOS/Linux use owner-only 0600 files).")
        print("\nResult: %s" % ("READY" if ok else "NOT READY - report this output"))
        return 0 if ok else 1
    import credstore
    probe = "rakshex-dpapi-probe"
    cfg = os.path.expanduser("~/.config/rakshex-lark-assistant")
    path = os.path.join(cfg, "dpapi_probe.json")
    made_cfg = not os.path.isdir(cfg)
    try:
        credstore.save_json(path, {"probe": probe})
        with open(path, "rb") as f:
            raw = f.read()
        back = credstore.load_json(path)["probe"]
        disk_ok = b"dpapi-current-user" in raw and probe.encode() not in raw
        round_ok = back == probe
        print("DPAPI round trip ... %s" % ("OK" if round_ok else "FAILED"))
        print("File on disk holds ciphertext only ... %s" % ("yes" if disk_ok else "NO"))
        ok = ok and round_ok and disk_ok
    except Exception as e:
        print("DPAPI round trip ... FAILED (%s: %s)" % (type(e).__name__, e))
        ok = False
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
        if made_cfg:  # leave the machine as we found it
            try:
                os.rmdir(cfg)
            except OSError:
                pass
    print("\nResult: %s" % ("READY - protected storage works on this machine"
                            if ok else "NOT READY - report this output"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
