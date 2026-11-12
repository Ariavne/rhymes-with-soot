"""File storage helpers with at-rest encryption (AES-256-GCM, chunked).
Files without the SOOT header are rejected — there is no plaintext fallback."""
import base64
import os

MAGIC = b"SOOT"
VERSION = 1
CHUNK_SIZE = 16 * 1024 * 1024  # plaintext bytes per chunk
_HEADER_LEN = 4 + 1 + 8 + 8 + 8

_key = None


def _aesgcm():
    """Import cryptography on first use so the module loads without it installed."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as e:
        raise ImportError(
            "The 'cryptography' package is required for encrypted storage. "
            "Add it to your site's requirements.txt."
        ) from e
    return AESGCM


def resolve_key():
    """The site's 32-byte encryption key, from ENCRYPTION_KEY or
    ENCRYPTION_KEYFILE in the site config.

    The resolved key is cached for the process lifetime (a key rotation
    needs a restart). Raises when the site has configured no key.
    """
    global _key
    if _key is not None:
        return _key
    from flask import current_app, has_app_context
    if not has_app_context():
        raise RuntimeError(
            "No ENCRYPTION_KEY resolved and no app context is available; "
            "call within an app context."
        )
    hexkey = current_app.config.get("ENCRYPTION_KEY")
    if not hexkey:
        keyfile = current_app.config.get("ENCRYPTION_KEYFILE")
        if not keyfile:
            raise RuntimeError(
                "No ENCRYPTION_KEY or ENCRYPTION_KEYFILE in the site "
                "config. There is no plaintext fallback: every site must "
                "configure a 32-byte (64 hex chars) encryption key."
            )
        with open(keyfile, "r", encoding="utf-8") as f:
            hexkey = f.read().strip()
    key = bytes.fromhex(hexkey)
    if len(key) != 32:
        raise ValueError("ENCRYPTION_KEY must be 32 bytes (64 hex chars)")
    _key = key
    return key


def _absolute_path(storage_path: str) -> str:
    """Resolve a storage path under STORAGE_DIR.

    Raises ValueError when the path would escape the storage directory
    (for example a stored path containing ``..``), so a site cannot use
    these helpers to touch files outside STORAGE_DIR."""
    from flask import current_app
    base = os.path.realpath(current_app.config["STORAGE_DIR"])
    absolute = os.path.realpath(os.path.join(base, storage_path))
    if absolute != base and not absolute.startswith(base + os.sep):
        raise ValueError(f"storage path escapes STORAGE_DIR: {storage_path!r}")
    return absolute


def _user_dir(user_id: str) -> str:
    from flask import current_app
    return os.path.join(current_app.config["STORAGE_DIR"], user_id)


def generate_storage_path(user_id: str) -> str:
    """Return a storage path relative to STORAGE_DIR, scoped to the user."""
    import uuid
    return os.path.join(user_id, uuid.uuid4().hex)


def encrypt_stream(src, dst_path: str, on_progress=None) -> int:
    """Encrypt a file object's contents into ``dst_path``. Returns plaintext size.
    ``on_progress(plain_bytes_written)`` is invoked after each chunk is written."""
    aes = _aesgcm()(resolve_key())
    num_chunks = 0
    plain_size = 0
    offsets = []
    with open(dst_path, "wb") as out:
        out.write(MAGIC)
        out.write(bytes([VERSION]))
        out.write(CHUNK_SIZE.to_bytes(8, "big"))
        out.write(b"\x00" * 8)  # NUM_CHUNKS placeholder
        out.write(b"\x00" * 8)  # PLAIN_SIZE placeholder
        while True:
            block = src.read(CHUNK_SIZE)
            if not block:
                break
            offsets.append(out.tell())
            nonce = os.urandom(12)
            ct = aes.encrypt(nonce, block, None)
            out.write(nonce)
            out.write(len(ct).to_bytes(8, "big"))
            out.write(ct)
            num_chunks += 1
            plain_size += len(block)
            if on_progress is not None:
                on_progress(plain_size)
        # Patch the header now that we know the totals.
        out.seek(4 + 1 + 8)
        out.write(num_chunks.to_bytes(8, "big"))
        out.write(plain_size.to_bytes(8, "big"))
        # Append the trailing per-chunk disk-offset index for O(1) seeks.
        out.seek(0, 2)
        for off in offsets:
            out.write(off.to_bytes(8, "big"))
    return plain_size


def save_upload(uploaded_file, user_id: str, storage_path: str, on_progress=None) -> int:
    absolute = _absolute_path(storage_path)
    os.makedirs(os.path.dirname(absolute), exist_ok=True)
    return encrypt_stream(uploaded_file.stream, absolute, on_progress=on_progress)


def delete_from_disk(storage_path: str):
    absolute = _absolute_path(storage_path)
    if os.path.exists(absolute):
        os.remove(absolute)


def get_file_path(storage_path: str) -> str:
    return _absolute_path(storage_path)


def is_encrypted(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == MAGIC
    except OSError:
        return False


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a short secret with AES-256-GCM. Returns base64(nonce || ciphertext || tag)."""
    nonce = os.urandom(12)
    ct = _aesgcm()(resolve_key()).encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode("ascii")


def decrypt_secret(ciphertext: str) -> str:
    """Reverse of encrypt_secret. Raises on tamper or decode failure."""
    raw = base64.b64decode(ciphertext)
    nonce, ct = raw[:12], raw[12:]
    return _aesgcm()(resolve_key()).decrypt(nonce, ct, None).decode("utf-8")


class EncryptedFileReader:
    """A seekable file-like reader that transparently decrypts an encrypted file.
    Seeking is O(1) via the trailing per-chunk offset index."""

    def __init__(self, path: str):
        self._path = path
        self._src = open(path, "rb")
        self._buf = b""
        self._pos = 0
        self._size = 0
        self._chunk_idx = 0
        self._num_chunks = 0
        self._chunk_size = 0
        self._header_end = 0
        self._chunk_offsets = []

        magic = self._src.read(4)
        if magic != MAGIC:
            self._src.close()
            raise ValueError("not a SOOT-encrypted file")

        version = self._src.read(1)
        if not version or version[0] != VERSION:
            self._src.close()
            raise ValueError("Unsupported encrypted file version")
        self._chunk_size = int.from_bytes(self._src.read(8), "big")
        self._num_chunks = int.from_bytes(self._src.read(8), "big")
        self._size = int.from_bytes(self._src.read(8), "big")
        self._header_end = _HEADER_LEN
        if self._num_chunks > 0:
            file_size = os.path.getsize(path)
            index_len = self._num_chunks * 8
            if file_size < _HEADER_LEN + index_len:
                # Truncated: the per-chunk index was never fully written.
                self._src.close()
                raise ValueError("Corrupt or truncated encrypted file")
            self._src.seek(file_size - index_len)
            self._chunk_offsets = [
                int.from_bytes(self._src.read(8), "big")
                for _ in range(self._num_chunks)
            ]
            first = self._chunk_offsets[0]
            if not (_HEADER_LEN <= first < file_size):
                # Index bytes are garbage (file truncated after the header patch).
                self._src.close()
                raise ValueError("Corrupt or truncated encrypted file")
            # Position at chunk 0 so sequential reads start correctly.
            self._src.seek(first)

    def _decrypt_next_chunk(self) -> bytes:
        if self._chunk_idx >= self._num_chunks:
            return b""
        nonce = self._src.read(12)
        if len(nonce) < 12:
            return b""
        ct_len = int.from_bytes(self._src.read(8), "big")
        ct = self._src.read(ct_len)
        plain = _aesgcm()(resolve_key()).decrypt(nonce, ct, None)
        self._chunk_idx += 1
        return plain

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if self._pos >= self._size:
            return b""
        if size is None or size < 0:
            size = self._size - self._pos
        else:
            size = min(size, self._size - self._pos)
        while len(self._buf) < size and self._chunk_idx < self._num_chunks:
            chunk = self._decrypt_next_chunk()
            if not chunk:
                # Truncated or corrupt file: stop rather than spin.
                break
            self._buf += chunk
        out = self._buf[:size]
        self._buf = self._buf[len(out):]
        self._pos += len(out)
        return out

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            target = offset
        elif whence == 1:
            target = self._pos + offset
        else:
            target = self._size + offset
        target = max(0, min(target, self._size))

        if self._num_chunks == 0:
            self._buf = b""
            self._chunk_idx = 0
            self._pos = 0
            return 0

        chunk_idx = target // self._chunk_size
        if chunk_idx >= self._num_chunks:
            chunk_idx = self._num_chunks - 1
        self._src.seek(self._chunk_offsets[chunk_idx])
        self._chunk_idx = chunk_idx
        plain = self._decrypt_next_chunk()  # decrypts chunk_idx, advances _chunk_idx
        self._buf = plain[target - chunk_idx * self._chunk_size:]
        self._pos = target
        return self._pos

    def tell(self) -> int:
        return self._pos

    def close(self):
        if self._src and not self._src.closed:
            self._src.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()


_SERVE_BLOCK = 1024 * 1024  # streaming block for Range responses


def _content_disposition(name: str, attachment: bool) -> str:
    """Build a Content-Disposition header, RFC 5987-quoting non-ASCII names.
    The name is sanitized first so a filename cannot break out of the quoted
    value or inject a header line."""
    import unicodedata
    from werkzeug.utils import quote

    value = "attachment" if attachment else "inline"
    safe = name.replace('"', "'").replace("\r", "").replace("\n", "")
    try:
        safe.encode("ascii")
        return f'{value}; filename="{safe}"'
    except UnicodeEncodeError:
        simple = unicodedata.normalize("NFKD", safe).encode("ascii", "ignore").decode("ascii")
        quoted = quote(safe, safe="!#$&-_.^|~")
        return f'{value}; filename="{simple}"; filename*=UTF-8\'\'{quoted}'


def serve_encrypted(path: str, mimetype: str, download_name: str,
                    as_attachment: bool = False):
    """Serve a stored file (encrypted or plaintext) with RFC 7233 Range support.
    Only single byte ranges are served (the common client case); anything else
    is 416. Streams in fixed blocks so large files never load into memory."""
    from flask import request, Response
    from werkzeug.exceptions import RequestedRangeNotSatisfiable
    from werkzeug.http import parse_range_header

    reader = EncryptedFileReader(path)
    size = reader.seek(0, 2)
    headers = [
        ("Accept-Ranges", "bytes"),
        ("Content-Disposition", _content_disposition(download_name, as_attachment)),
    ]

    range_header = request.headers.get("Range")

    if not range_header or size == 0:
        def full_iter():
            try:
                reader.seek(0)
                while True:
                    block = reader.read(_SERVE_BLOCK)
                    if not block:
                        break
                    yield block
            finally:
                reader.close()
        headers.append(("Content-Length", str(size)))
        return Response(full_iter(), 200, mimetype=mimetype, headers=headers)

    range_obj = parse_range_header(range_header)
    if range_obj is None or len(range_obj.ranges) != 1:
        reader.close()
        raise RequestedRangeNotSatisfiable(size)

    # Range.ranges are (start, end) with end EXCLUSIVE.
    start, end = range_obj.ranges[0]
    if start < 0:  # suffix range: bytes=-N
        start = max(0, size + start)
        end = size
    if end is None:
        end = size
    end = min(end, size)
    if start >= end:
        reader.close()
        raise RequestedRangeNotSatisfiable(size)

    length = end - start
    reader.seek(start)
    remaining = length

    def partial_iter():
        nonlocal remaining
        try:
            while remaining > 0:
                block = reader.read(min(_SERVE_BLOCK, remaining))
                if not block:
                    break
                remaining -= len(block)
                yield block
        finally:
            reader.close()

    headers.append(("Content-Range", f"bytes {start}-{end - 1}/{size}"))
    headers.append(("Content-Length", str(length)))
    return Response(partial_iter(), 206, mimetype=mimetype, headers=headers)


# Inline-renderable types. Deliberately limited to what browsers render
# natively and that cannot execute script; this is a security boundary.
PREVIEW_TYPES = frozenset({
    "image/png", "image/jpeg", "image/gif", "image/webp",
    "video/mp4", "video/webm", "video/ogg",
    "audio/mpeg", "audio/ogg", "audio/wav", "audio/flac",
})


def detect_content_type(head: bytes, filename: str, declared: str = None) -> str:
    """Detect a file's content type from a sample of its leading bytes.
    Media types come from libmagic; everything else falls back to the declared
    type, then the filename extension."""
    import mimetypes
    try:
        import magic
        mime = magic.from_buffer(head, mime=True)
    except Exception:
        mime = None
    if mime and mime.startswith(("image/", "video/", "audio/")):
        return mime
    return declared or mimetypes.guess_type(filename)[0] or "application/octet-stream"


def serve_stored_file(path: str, filename: str, content_type: str,
                      as_attachment: bool = False):
    """Serve a stored file, deciding inline vs. attachment by policy."""
    content_type = content_type or "application/octet-stream"
    if not as_attachment and content_type in PREVIEW_TYPES:
        return serve_encrypted(path, content_type, filename, as_attachment=False)
    return serve_encrypted(path, content_type, filename, as_attachment=True)


class StorageQuotaExceeded(Exception):
    """A write would push the user over their storage quota.

    The message is human-readable (it is surfaced to the user as the 413's
    reason)."""


def storage_quota_cap(username, key="files.quota"):
    """The user's storage cap in bytes, or None when there is no quota.

    The cap is the site's number access ``key``: a user holding a value gets
    it, one holding none gets the access's declared default. When the site
    declares no such access there is no quota at all."""
    from rhymes_with_soot.access import (
        TOGGLE_VALUE, access_defs_by_key, load_accesses,
    )

    d = access_defs_by_key().get(key)
    if d is None or d.kind != "number":
        return None
    values = [v for v in load_accesses(username).get(key, set())
              if v != TOGGLE_VALUE]
    if not values:
        return d.default
    try:
        num = float(values[0])
    except (TypeError, ValueError):
        return d.default
    return int(num) if num.is_integer() else num


def check_storage_quota(username, current_bytes, added_bytes, key="files.quota"):
    """Raise StorageQuotaExceeded when current + added exceeds the cap.

    ``current_bytes`` is the user's usage so far (the site sums its own file
    rows); a write that lands exactly on the cap is allowed."""
    cap = storage_quota_cap(username, key)
    if cap is not None and current_bytes + added_bytes > cap:
        from rhymes_with_soot.util import format_size
        raise StorageQuotaExceeded(
            "not enough space: %s used, adding %s would pass the %s "
            "limit — delete something first"
            % (format_size(current_bytes), format_size(added_bytes),
               format_size(cap))
        )
