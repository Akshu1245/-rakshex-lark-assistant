#!/usr/bin/env python3
"""Protected local storage for the RaksHex Lark Assistant.

Windows: secrets are encrypted with DPAPI (CryptProtectData, current Windows
user scope) via ctypes - the file on disk holds only ciphertext tied to the
Windows account. Anyone logged into a DIFFERENT Windows account cannot read
it; anyone logged into the SAME Windows account can, so use your own Windows
account on shared machines.
macOS/Linux: plain JSON with owner-only 0600 permissions and atomic replace.
Also provides a small cross-process lock file used to serialize token refresh.
No third-party dependencies.
"""
import base64, contextlib, json, os, time

IS_WINDOWS = os.name == "nt"

if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes
    _crypt32 = ctypes.windll.crypt32
    _kernel32 = ctypes.windll.kernel32
    _UI_FORBIDDEN = 0x1

    class _DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    _BLOB_P = ctypes.POINTER(_DATA_BLOB)
    for _fn_name in ("CryptProtectData", "CryptUnprotectData"):
        _fn = getattr(_crypt32, _fn_name)
        _fn.argtypes = [_BLOB_P, wintypes.LPCWSTR, _BLOB_P, ctypes.c_void_p,
                        ctypes.c_void_p, wintypes.DWORD, _BLOB_P]
        _fn.restype = wintypes.BOOL
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.LocalFree.restype = ctypes.c_void_p

    def _dpapi(data, protect):
        buf = ctypes.create_string_buffer(data, len(data))
        bin_in = _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
        blob_out = _DATA_BLOB()
        fn = _crypt32.CryptProtectData if protect else _crypt32.CryptUnprotectData
        if not fn(ctypes.byref(bin_in), None, None, None, None, _UI_FORBIDDEN, ctypes.byref(blob_out)):
            raise ctypes.WinError()
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            _kernel32.LocalFree(ctypes.cast(blob_out.pbData, ctypes.c_void_p))


def save_json(path, obj):
    """Atomic write. On Windows the payload is DPAPI-encrypted first.
    Creates parent directories (first run on a fresh machine)."""
    raw = json.dumps(obj, indent=2).encode("utf-8")
    if IS_WINDOWS:
        disk = json.dumps({"protection": "dpapi-current-user",
                           "blob": base64.b64encode(_dpapi(raw, True)).decode()}).encode()
    else:
        disk = raw
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(disk)
    if not IS_WINDOWS:
        os.chmod(tmp, 0o600)
    os.replace(tmp, path)  # atomic rotation
    if not IS_WINDOWS:
        os.chmod(path, 0o600)


def load_json(path):
    with open(path, "rb") as f:
        obj = json.loads(f.read())
    if isinstance(obj, dict) and obj.get("protection") == "dpapi-current-user":
        if not IS_WINDOWS:
            raise RuntimeError("this credential file is DPAPI-protected for a Windows user account")
        return json.loads(_dpapi(base64.b64decode(obj["blob"]), False))
    return obj


@contextlib.contextmanager
def file_lock(path, timeout=10.0, stale_after=120.0):
    """Cross-process advisory lock via lock-file creation; stale locks are reclaimed."""
    deadline = time.monotonic() + timeout
    fd = None
    while fd is None:
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            try:
                if time.time() - os.path.getmtime(path) > stale_after:
                    os.remove(path)
                    continue
            except OSError:
                continue
            if time.monotonic() >= deadline:
                raise TimeoutError("timed out waiting for " + path)
            time.sleep(0.1)
    os.close(fd)
    try:
        yield
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
