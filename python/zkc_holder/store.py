"""Credential stores (reference implementations).

NOT a production credential vault. Production holders supply their own
storage backend implementing `CredentialStore`. These stores exist so the
reference SDK and conformance suite are runnable with the standard library
alone.

Keying: issuers choose credential identifiers, so a ``credentialId`` is
unique only within its issuer. Every store keys a credential by
``(issuer_id, credential_id)``: a credential from a second issuer that reuses
an identifier is stored alongside the first, never in its place. A lookup or
deletion that names only a ``credential_id`` fails with
``AmbiguousCredentialError`` when credentials from more than one issuer carry
it; it never guesses.

`EncryptedFileCredentialStore` file format ``zkc-credential-store:v2``:

  - key derivation: a 32-byte master key from PBKDF2-HMAC-SHA256 (600,000
    iterations, 16-byte random salt per write), then
    ``enc_key = HMAC-SHA256(master, "zkc/credential-store/v2/enc")`` and
    ``mac_key = HMAC-SHA256(master, "zkc/credential-store/v2/mac")``
    (``hashlib.scrypt`` is not in every CPython build). The legacy v1 split
    of 64 PBKDF2 bytes is used only to read a v1 file for migration, so no
    v2 key ever authenticates v1 input.
  - confidentiality: SHA-256 counter-mode keystream over a 16-byte random
    nonce (stdlib has no AES)
  - integrity: encrypt-then-MAC with HMAC-SHA256 over a length-framed header
    (format version, KDF id, iteration count, salt, nonce) and the
    ciphertext; any salt or nonce length other than 16 bytes fails
    authentication before the constant-time tag comparison
  - writes: a private (0600) temporary file created exclusively in the same
    directory, fsync, then an atomic ``os.replace``; a symbolic link at the
    store path (the final path component) is refused, never followed

Symbolic-link protection covers the final path component only: a link in a
parent directory is followed. Keep the store in a directory only the holder
can write. On platforms without ``O_NOFOLLOW`` (Windows) the check is an
``lstat`` before use only.

Credential plaintext, seeds, and binding keys are never logged.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import pathlib
import re
import secrets
import sqlite3
import stat
import tempfile
from typing import Optional

from .credential import Credential
from .errors import AmbiguousCredentialError, StorageError

__all__ = [
    "CredentialStore",
    "InMemoryCredentialStore",
    "EncryptedFileCredentialStore",
    "SQLiteCredentialStore",
]

# Encrypted-file formats. v1 (unframed MAC input, keyed by credentialId
# alone) is read only to migrate it to v2; every write is v2.
_FORMAT_V1 = "zkc-credential-store:v1"
_FORMAT_V2 = "zkc-credential-store:v2"
_KDF_ID = "pbkdf2-hmac-sha256"
_KDF_ITERATIONS = 600_000
_SALT_BYTES = 16
_NONCE_BYTES = 16
_MAC_BYTES = 32
_MAC_DOMAIN_V2 = b"zkc/credential-store/mac:v2\0"
_V2_ENC_LABEL = b"zkc/credential-store/v2/enc"
_V2_MAC_LABEL = b"zkc/credential-store/v2/mac"
_V1_WRAPPER_KEYS = frozenset({"format", "salt", "nonce", "ciphertext", "mac"})
_V2_WRAPPER_KEYS = frozenset(
    {"format", "kdf", "iterations", "salt", "nonce", "ciphertext", "mac"}
)
_LOWER_HEX = re.compile(r"(?:[0-9a-f]{2})*")
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)  # a swapped-in FIFO must not block
_O_BINARY = getattr(os, "O_BINARY", 0)
_PRIVATE_FILE_MODE = 0o600
_AUTHENTICATION_FAILED = (
    "credential store authentication failed (wrong passphrase or tampering)"
)


def _store_key(credential_id: int) -> str:
    return f"{credential_id:#066x}"


def _check_lookup(credential_id, issuer_id) -> None:
    if isinstance(credential_id, bool) or not isinstance(credential_id, int):
        raise StorageError("credential_id must be an integer field element")
    if issuer_id is not None and not isinstance(issuer_id, str):
        raise StorageError("issuer_id must be a string")


def _single(matches: list) -> Optional[Credential]:
    """Resolve a credentialId-only lookup; refuse when issuers collide."""
    if not matches:
        return None
    if len(matches) > 1:
        raise AmbiguousCredentialError(
            f"{len(matches)} stored credentials from different issuers carry this "
            "credentialId; name the issuer to select one"
        )
    return matches[0]


class CredentialStore:
    """Storage interface the holder client uses.

    Implementations MUST key credentials by ``(issuer_id, credential_id)``.
    ``put`` replaces only a credential with the same issuer and identifier.
    ``get`` and ``delete`` take an optional ``issuer_id``; without it they
    MUST raise ``AmbiguousCredentialError`` when credentials from more than
    one issuer carry ``credential_id``.
    """

    def put(self, credential: Credential) -> None:
        raise NotImplementedError

    def get(self, credential_id: int, issuer_id: str = None) -> Optional[Credential]:
        raise NotImplementedError

    def list(self) -> list:
        raise NotImplementedError

    def delete(self, credential_id: int, issuer_id: str = None) -> None:
        raise NotImplementedError


class InMemoryCredentialStore(CredentialStore):
    def __init__(self):
        self._credentials = {}

    def _matches(self, credential_id: int, issuer_id) -> list:
        _check_lookup(credential_id, issuer_id)
        if issuer_id is not None:
            found = self._credentials.get((issuer_id, credential_id))
            return [] if found is None else [found]
        return [c for (_, cid), c in self._credentials.items() if cid == credential_id]

    def put(self, credential: Credential) -> None:
        self._credentials[(credential.issuer_id, credential.credential_id)] = credential

    def get(self, credential_id: int, issuer_id: str = None) -> Optional[Credential]:
        return _single(self._matches(credential_id, issuer_id))

    def list(self) -> list:
        return list(self._credentials.values())

    def delete(self, credential_id: int, issuer_id: str = None) -> None:
        found = _single(self._matches(credential_id, issuer_id))
        if found is not None:
            del self._credentials[(found.issuer_id, found.credential_id)]


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    blocks = []
    counter = 0
    while sum(len(b) for b in blocks) < length:
        blocks.append(hashlib.sha256(key + nonce + counter.to_bytes(8, "big")).digest())
        counter += 1
    return b"".join(blocks)[:length]


def _frame(*parts: bytes) -> bytes:
    """``u32be(len(p_1)) || p_1 || ... || u32be(len(p_n)) || p_n``."""
    return b"".join(len(part).to_bytes(4, "big") + part for part in parts)


def _v2_mac_input(salt: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    # Every field is length-framed, so no byte can move between the nonce
    # and the ciphertext (or any other field) without changing the input.
    return _MAC_DOMAIN_V2 + _frame(
        _FORMAT_V2.encode(),
        _KDF_ID.encode(),
        _KDF_ITERATIONS.to_bytes(4, "big"),
        salt,
        nonce,
        ciphertext,
    )


def _strict_hex(value) -> bytes:
    if not isinstance(value, str) or not _LOWER_HEX.fullmatch(value):
        raise ValueError("expected lowercase hex")
    return bytes.fromhex(value)


def _refuse_symlink(path: pathlib.Path) -> None:
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        return
    except OSError as exc:
        raise StorageError(f"could not inspect credential store path: {type(exc).__name__}") from exc
    if stat.S_ISLNK(mode):
        raise StorageError("credential store path is a symbolic link; refusing to follow it")
    if not stat.S_ISREG(mode):
        raise StorageError("credential store path is not a regular file")


def _read_private_file(path: pathlib.Path) -> Optional[bytes]:
    """Read ``path`` without following a symbolic link; ``None`` if absent.

    The open itself refuses a final-component link (``O_NOFOLLOW``) and does
    not block on a FIFO (``O_NONBLOCK``); ``fstat`` then requires a regular
    file, so a path swapped after the ``lstat`` check is still refused.
    """
    _refuse_symlink(path)
    try:
        descriptor = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_BINARY)
    except FileNotFoundError:
        return None
    except OSError as exc:
        # ELOOP: the path became a symbolic link after the check above.
        raise StorageError(f"could not open credential store: {type(exc).__name__}") from exc
    with os.fdopen(descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise StorageError("credential store path is not a regular file")
        return handle.read()


def _fsync_directory(directory: pathlib.Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write_private(path: pathlib.Path, data: bytes) -> None:
    """Replace ``path`` with ``data`` atomically, as a private (0600) file.

    The temporary file is created exclusively with an unpredictable name in
    the destination directory (``tempfile.mkstemp``: O_CREAT|O_EXCL, mode
    0600), so a planted file or symbolic link is never opened or followed.
    A symbolic link at the destination is refused; ``os.replace`` renames
    over the destination entry itself and never writes through a link.
    """
    _refuse_symlink(path)
    directory = path.parent
    try:
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=directory
        )
    except OSError as exc:
        raise StorageError(f"could not create credential store file: {type(exc).__name__}") from exc
    try:
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, _PRIVATE_FILE_MODE)
            handle = os.fdopen(descriptor, "wb")
        except BaseException:
            os.close(descriptor)
            raise
        with handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        _refuse_symlink(path)
        os.replace(temporary, path)
    except BaseException as exc:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        if isinstance(exc, OSError):
            raise StorageError(
                f"could not write credential store: {type(exc).__name__}"
            ) from exc
        raise
    try:
        _fsync_directory(directory)
    except OSError as exc:
        # Fail fast, but say what happened: the new file is already in place.
        raise StorageError(
            "credential store file was replaced, but syncing its directory failed: "
            f"{type(exc).__name__}"
        ) from exc


class EncryptedFileCredentialStore(CredentialStore):
    """Single-file encrypted JSON store (format ``zkc-credential-store:v2``).

    The decrypted payload is a JSON list of ``Credential.to_dict()`` documents,
    unique by ``(issuerId, credentialId)``. A v1 file (keyed by credentialId
    alone, unframed MAC input) is migrated on first access: it is
    authenticated, every entry is checked against its key, and the file is
    rewritten as v2 before any result is returned. Any inconsistency fails
    closed with ``StorageError`` and leaves the file unchanged.
    """

    def __init__(self, path, passphrase: bytes):
        if not passphrase:
            raise StorageError("store passphrase must be non-empty")
        self._path = pathlib.Path(path)
        self._passphrase = passphrase

    # --- crypto helpers -----------------------------------------------------

    def _cached_keys(self, version: str, salt: bytes, derive):
        # Cache per (format, salt): the KDF cost is paid once per file version.
        cache = self.__dict__.setdefault("_kdf_cache", {})
        key = (version, salt)
        if key not in cache:
            if len(cache) >= 4:
                cache.clear()
            cache[key] = derive()
        return cache[key]

    def _derive_v2_keys(self, salt: bytes):
        """v2: one 32-byte PBKDF2 block, then label-separated HMAC subkeys."""

        def derive():
            master = hashlib.pbkdf2_hmac(
                "sha256", self._passphrase, salt, _KDF_ITERATIONS, dklen=32
            )
            return (
                hmac.new(master, _V2_ENC_LABEL, hashlib.sha256).digest(),
                hmac.new(master, _V2_MAC_LABEL, hashlib.sha256).digest(),
            )

        return self._cached_keys(_FORMAT_V2, salt, derive)

    def _derive_v1_keys(self, salt: bytes):
        """Legacy v1 only (read to migrate): 64 PBKDF2 bytes split in two."""

        def derive():
            material = hashlib.pbkdf2_hmac(
                "sha256", self._passphrase, salt, _KDF_ITERATIONS, dklen=64
            )
            return material[:32], material[32:]

        return self._cached_keys(_FORMAT_V1, salt, derive)

    def _open_wrapper(self, raw: bytes):
        """Authenticate and decrypt one wrapper; return (format, plaintext)."""
        try:
            wrapper = json.loads(raw.decode())
            if not isinstance(wrapper, dict):
                raise StorageError("unrecognized credential store format")
            version = wrapper.get("format")
            if version == _FORMAT_V2:
                expected_keys = _V2_WRAPPER_KEYS
            elif version == _FORMAT_V1:
                expected_keys = _V1_WRAPPER_KEYS
            else:
                raise StorageError("unrecognized credential store format")
            if set(wrapper) != expected_keys:
                raise StorageError("credential store wrapper has unexpected fields")
            if version == _FORMAT_V2:
                iterations = wrapper["iterations"]
                if (
                    wrapper["kdf"] != _KDF_ID
                    or type(iterations) is not int
                    or iterations != _KDF_ITERATIONS
                ):
                    raise StorageError("unsupported credential store key derivation")
            salt = _strict_hex(wrapper["salt"])
            nonce = _strict_hex(wrapper["nonce"])
            ciphertext = _strict_hex(wrapper["ciphertext"])
            tag = _strict_hex(wrapper["mac"])
        except StorageError:
            raise
        except Exception as exc:
            raise StorageError(f"corrupt credential store: {type(exc).__name__}") from exc

        # Header lengths are fixed: anything else fails authentication before
        # the MAC is even computed (no boundary between nonce and ciphertext
        # can move, in either format).
        if len(salt) != _SALT_BYTES or len(nonce) != _NONCE_BYTES or len(tag) != _MAC_BYTES:
            raise StorageError(_AUTHENTICATION_FAILED)
        # Each format has its own keys, so a v2 tag can never authenticate a
        # v1 wrapper recut from the v2 MAC input (or the reverse).
        if version == _FORMAT_V2:
            enc_key, mac_key = self._derive_v2_keys(salt)
            mac_input = _v2_mac_input(salt, nonce, ciphertext)
        else:
            enc_key, mac_key = self._derive_v1_keys(salt)
            mac_input = nonce + ciphertext
        expected = hmac.new(mac_key, mac_input, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, tag):
            raise StorageError(_AUTHENTICATION_FAILED)
        plaintext = bytes(
            a ^ b for a, b in zip(ciphertext, _keystream(enc_key, nonce, len(ciphertext)))
        )
        try:
            return version, json.loads(plaintext.decode())
        except Exception as exc:
            raise StorageError("credential store payload is not valid JSON") from exc

    @staticmethod
    def _index(credentials) -> dict:
        index = {}
        for credential in credentials:
            key = (credential.issuer_id, credential.credential_id)
            if key in index:
                raise StorageError("credential store holds a duplicate (issuer, credentialId)")
            index[key] = credential
        return index

    @staticmethod
    def _decode(entry) -> Credential:
        try:
            if not isinstance(entry, dict):
                raise ValueError("credential entry is not an object")
            credential = Credential.from_dict(entry)
            if not isinstance(credential.issuer_id, str):
                raise ValueError("credential issuerId is not a string")
            return credential
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise StorageError(f"corrupt stored credential: {type(exc).__name__}") from exc

    def _read_all(self) -> dict:
        """Return ``{(issuer_id, credential_id): Credential}``."""
        raw = _read_private_file(self._path)
        if raw is None:
            return {}
        version, payload = self._open_wrapper(raw)
        if version == _FORMAT_V2:
            if not isinstance(payload, list):
                raise StorageError("credential store payload has the wrong shape")
            return self._index(self._decode(entry) for entry in payload)

        # v1: {"0x<credentialId>": credential}. Every key must name its own
        # credential; then the file is rewritten as v2 before use.
        if not isinstance(payload, dict):
            raise StorageError("credential store payload has the wrong shape")
        credentials = []
        for key, entry in payload.items():
            credential = self._decode(entry)
            if key != _store_key(credential.credential_id):
                raise StorageError("legacy credential store entry does not match its key")
            credentials.append(credential)
        index = self._index(credentials)
        try:
            self._write_all(index)
        except StorageError as exc:
            cause = exc.__cause__
            reason = (
                "directory is not writable"
                if isinstance(cause, PermissionError)
                else exc.message
            )
            raise StorageError(
                f"v1 credential store requires migration to v2; {reason}"
            ) from exc
        return index

    def _write_all(self, index: dict) -> None:
        salt = secrets.token_bytes(_SALT_BYTES)
        nonce = secrets.token_bytes(_NONCE_BYTES)
        enc_key, mac_key = self._derive_v2_keys(salt)
        documents = [
            index[key].to_dict()
            for key in sorted(index, key=lambda k: (k[0], k[1]))
        ]
        plaintext = json.dumps(documents, sort_keys=True).encode()
        ciphertext = bytes(
            a ^ b for a, b in zip(plaintext, _keystream(enc_key, nonce, len(plaintext)))
        )
        tag = hmac.new(mac_key, _v2_mac_input(salt, nonce, ciphertext), hashlib.sha256).digest()
        wrapper = {
            "format": _FORMAT_V2,
            "kdf": _KDF_ID,
            "iterations": _KDF_ITERATIONS,
            "salt": salt.hex(),
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "mac": tag.hex(),
        }
        _atomic_write_private(self._path, json.dumps(wrapper, sort_keys=True).encode())

    @staticmethod
    def _matches(index: dict, credential_id: int, issuer_id) -> list:
        _check_lookup(credential_id, issuer_id)
        if issuer_id is not None:
            found = index.get((issuer_id, credential_id))
            return [] if found is None else [found]
        return [c for (_, cid), c in index.items() if cid == credential_id]

    # --- CredentialStore ----------------------------------------------------

    def put(self, credential: Credential) -> None:
        index = self._read_all()
        stored = self._decode(credential.to_dict())
        index[(stored.issuer_id, stored.credential_id)] = stored
        self._write_all(index)

    def get(self, credential_id: int, issuer_id: str = None) -> Optional[Credential]:
        return _single(self._matches(self._read_all(), credential_id, issuer_id))

    def list(self) -> list:
        return list(self._read_all().values())

    def delete(self, credential_id: int, issuer_id: str = None) -> None:
        index = self._read_all()
        found = _single(self._matches(index, credential_id, issuer_id))
        if found is not None:
            del index[(found.issuer_id, found.credential_id)]
            self._write_all(index)


_SQLITE_STORE_VERSION = 2
_SQLITE_V1_COLUMNS = ["credential_id", "document"]
_SQLITE_V2_COLUMNS = ["issuer_id", "credential_id", "document"]
_SQLITE_V2_TABLE = (
    "CREATE TABLE {name} ("
    "  issuer_id TEXT NOT NULL,"
    "  credential_id TEXT NOT NULL,"
    "  document TEXT NOT NULL,"
    "  PRIMARY KEY (issuer_id, credential_id)"
    ")"
)


_SQLITE_SIDECARS = ("-wal", "-shm", "-journal")


def _make_private(descriptor: int, info: os.stat_result) -> None:
    """fchmod an open file to 0600 when this process's user owns it."""
    if not (hasattr(os, "fchmod") and hasattr(os, "geteuid")):
        return  # no POSIX modes (Windows)
    if info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) != _PRIVATE_FILE_MODE:
        os.fchmod(descriptor, _PRIVATE_FILE_MODE)


def _open_private(path: pathlib.Path, create: bool):
    """Open ``path`` without following a link, require a regular file, make
    it 0600 when owned; return its ``(st_dev, st_ino)``, or ``None`` if it is
    absent and ``create`` is false."""
    _refuse_symlink(path)
    flags = os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_BINARY
    if create:
        flags |= os.O_CREAT
    try:
        descriptor = os.open(path, flags, _PRIVATE_FILE_MODE)
    except FileNotFoundError:
        if create:
            raise StorageError("could not create credential store: FileNotFoundError")
        return None
    except OSError as exc:
        raise StorageError(f"could not open credential store: {type(exc).__name__}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise StorageError("credential store path is not a regular file")
        _make_private(descriptor, info)
    except OSError as exc:
        raise StorageError(f"could not secure credential store: {type(exc).__name__}") from exc
    finally:
        os.close(descriptor)
    return info.st_dev, info.st_ino


def _prepare_private_database(path: str):
    """Create or open the database file as 0600 without following a link.

    A new file is created 0600; an existing database and its existing
    ``-wal``/``-shm``/``-journal`` files are set to 0600 when this process's
    user owns them (SQLite gives new sidecar files the database file's mode).
    A ``file:`` prefix is an ordinary path here: the store never opens URIs.
    Returns the database file identity, re-checked after ``sqlite3.connect``
    re-resolves the path. ``""`` and ``":memory:"`` have no file.
    """
    if path in ("", ":memory:"):
        return None
    identity = _open_private(pathlib.Path(path), create=True)
    for suffix in _SQLITE_SIDECARS:
        _open_private(pathlib.Path(path + suffix), create=False)
    return identity


class SQLiteCredentialStore(CredentialStore):
    """Durable, transactional SQLite-backed credential store.

    A zero-dependency persistent alternative to ``InMemoryCredentialStore``:
    credentials survive process restarts (reopen the same path → state intact).
    Each credential is stored as its canonical ``Credential.to_dict()`` JSON
    keyed by ``(issuer_id, credential_id)`` (schema version 2), so the schema
    is the wire shape and recovery is just a re-read. The database file and
    its existing sidecar files are made 0600 (when this process's user owns
    them) and a symbolic link at the path is refused; protection covers the
    final path component only, so keep the database in a directory only the
    holder can write. A version-1 database (keyed by credential id
    alone) is migrated in one transaction when it is opened; a row whose
    document does not match its key, or an unrecognized schema, fails closed
    with ``StorageError`` and leaves the database unchanged.

    Durability: SQLite runs in WAL mode with ``synchronous=FULL`` and every
    write is its own committed transaction, so a put/delete that returns has
    been flushed. NOT encrypted at rest — combine with full-disk encryption, or
    use ``EncryptedFileCredentialStore`` when at-rest confidentiality (not
    durability) is the goal. Credential plaintext is never logged.

    Connections are NOT shared across threads (sqlite3 default); construct one
    store per thread, or pass ``check_same_thread=False`` and serialize access.
    """

    def __init__(self, path, check_same_thread: bool = True):
        self._path = str(path)
        identity = _prepare_private_database(self._path)
        try:
            self._conn = sqlite3.connect(self._path, check_same_thread=check_same_thread)
        except sqlite3.Error as exc:
            raise StorageError(f"could not open credential store: {type(exc).__name__}") from exc
        self._conn.row_factory = sqlite3.Row
        try:
            if identity is not None:
                self._check_identity(identity)
            self._initialize()
        except BaseException:
            self._conn.close()
            raise

    def _check_identity(self, identity) -> None:
        """``sqlite3.connect`` re-resolves the path: refuse if it changed."""
        try:
            info = os.lstat(self._path)
        except OSError as exc:
            raise StorageError(f"could not inspect credential store: {type(exc).__name__}") from exc
        if stat.S_ISLNK(info.st_mode) or (info.st_dev, info.st_ino) != identity:
            raise StorageError("credential store path changed while it was being opened")

    def _initialize(self) -> None:
        try:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._prepare_schema()
            except BaseException:
                self._conn.rollback()
                raise
            self._conn.commit()
        except sqlite3.Error as exc:
            raise StorageError(f"could not initialize credential store: {type(exc).__name__}") from exc

    def _prepare_schema(self) -> None:
        """Create, accept, or migrate the schema inside one transaction."""
        tables = {
            row[0]
            for row in self._conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        version = None
        if "store_meta" in tables:
            row = self._conn.execute(
                "SELECT value FROM store_meta WHERE key = 'version'"
            ).fetchone()
            version = None if row is None else row[0]
        if "credentials" not in tables:
            if version is not None:
                raise StorageError("credential store metadata exists without its credential table")
            self._conn.execute(_SQLITE_V2_TABLE.format(name="credentials"))
            self._set_version()
            return
        columns = [row[1] for row in self._conn.execute("PRAGMA table_info(credentials)")]
        if columns == _SQLITE_V2_COLUMNS and version == str(_SQLITE_STORE_VERSION):
            return
        if columns == _SQLITE_V1_COLUMNS and version in (None, "1"):
            self._migrate_v1()
            self._set_version()
            return
        raise StorageError("unrecognized credential store schema version")

    def _set_version(self) -> None:
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS store_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        self._conn.execute(
            "INSERT INTO store_meta(key, value) VALUES('version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (str(_SQLITE_STORE_VERSION),),
        )

    def _migrate_v1(self) -> None:
        """Re-key v1 rows by (issuer_id, credential_id); never drop a row."""
        self._conn.execute(_SQLITE_V2_TABLE.format(name="credentials_v2"))
        rows = self._conn.execute("SELECT credential_id, document FROM credentials").fetchall()
        for row in rows:
            credential = self._decode(row["document"])
            if row["credential_id"] != self._key(credential.credential_id):
                raise StorageError("legacy credential store row does not match its key")
            self._conn.execute(
                "INSERT INTO credentials_v2(issuer_id, credential_id, document) VALUES(?, ?, ?)",
                (credential.issuer_id, row["credential_id"], row["document"]),
            )
        migrated = self._conn.execute("SELECT COUNT(*) FROM credentials_v2").fetchone()[0]
        if migrated != len(rows):
            raise StorageError("credential store migration lost rows")
        self._conn.execute("DROP TABLE credentials")
        self._conn.execute("ALTER TABLE credentials_v2 RENAME TO credentials")

    @staticmethod
    def _key(credential_id: int) -> str:
        return _store_key(credential_id)

    def put(self, credential: Credential) -> None:
        document = json.dumps(credential.to_dict(), sort_keys=True)
        try:
            with self._conn:  # one committed transaction (atomic, durable)
                self._conn.execute(
                    "INSERT INTO credentials(issuer_id, credential_id, document) VALUES(?, ?, ?) "
                    "ON CONFLICT(issuer_id, credential_id) DO UPDATE SET document=excluded.document",
                    (credential.issuer_id, self._key(credential.credential_id), document),
                )
        except sqlite3.Error as exc:
            raise StorageError(f"could not persist credential: {type(exc).__name__}") from exc

    def _rows(self, credential_id: int, issuer_id) -> list:
        _check_lookup(credential_id, issuer_id)
        try:
            if issuer_id is None:
                return self._conn.execute(
                    "SELECT issuer_id, document FROM credentials WHERE credential_id = ?",
                    (self._key(credential_id),),
                ).fetchall()
            return self._conn.execute(
                "SELECT issuer_id, document FROM credentials "
                "WHERE issuer_id = ? AND credential_id = ?",
                (issuer_id, self._key(credential_id)),
            ).fetchall()
        except sqlite3.Error as exc:
            raise StorageError(f"could not read credential: {type(exc).__name__}") from exc

    def get(self, credential_id: int, issuer_id: str = None) -> Optional[Credential]:
        row = _single(self._rows(credential_id, issuer_id))
        if row is None:
            return None
        credential = self._decode(row["document"])
        if (credential.issuer_id, credential.credential_id) != (row["issuer_id"], credential_id):
            raise StorageError("stored credential does not match its key")
        return credential

    def list(self) -> list:
        try:
            rows = self._conn.execute("SELECT document FROM credentials").fetchall()
        except sqlite3.Error as exc:
            raise StorageError(f"could not list credentials: {type(exc).__name__}") from exc
        return [self._decode(row["document"]) for row in rows]

    def delete(self, credential_id: int, issuer_id: str = None) -> None:
        row = _single(self._rows(credential_id, issuer_id))
        if row is None:
            return
        try:
            with self._conn:
                self._conn.execute(
                    "DELETE FROM credentials WHERE issuer_id = ? AND credential_id = ?",
                    (row["issuer_id"], self._key(credential_id)),
                )
        except sqlite3.Error as exc:
            raise StorageError(f"could not delete credential: {type(exc).__name__}") from exc

    @staticmethod
    def _decode(document: str) -> Credential:
        try:
            return Credential.from_dict(json.loads(document))
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise StorageError(f"corrupt stored credential: {type(exc).__name__}") from exc

    def close(self) -> None:
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False
