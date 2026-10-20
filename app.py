#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import stat
import sys
import tempfile
import time
import traceback
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

try:
    import fcntl
except ImportError:
    fcntl = None

try:
    import msvcrt
except ImportError:
    msvcrt = None


VERSION = "1.0.0"
ALGORITHM = "sha256"
MANIFEST_FORMAT = "log-integrity-baseline"
MANIFEST_VERSION = 1
DEFAULT_PORT = 8765
EXIT_OK = 0
EXIT_DISCREPANCY = 1
EXIT_ERROR = 2
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


class IntegrityError(Exception):
    status_code = 400


class InvalidInput(IntegrityError):
    status_code = 400


class BaselineExists(IntegrityError):
    status_code = 409


class BaselineNotFound(IntegrityError):
    status_code = 404


class StoreError(IntegrityError):
    status_code = 500


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def canonical_path(value: Any) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise InvalidInput("A file or directory path is required.")
    expanded = os.path.expanduser(value)
    absolute = os.path.abspath(expanded)
    return Path(os.path.realpath(absolute))


def normalize_path(value: Path) -> str:
    return os.path.normcase(os.path.normpath(str(value)))


def same_path(left: Path, right: Path) -> bool:
    return normalize_path(left) == normalize_path(right)


def is_within(child: Path, parent: Path) -> bool:
    child_value = normalize_path(child)
    parent_value = normalize_path(parent)
    try:
        return os.path.commonpath([child_value, parent_value]) == parent_value
    except ValueError:
        return False


def relative_key(path: Path, root: Path) -> str:
    try:
        relative = os.path.relpath(str(path), str(root))
    except ValueError as exc:
        raise InvalidInput("The selected path is on a different filesystem.") from exc
    if relative in (".", ""):
        return ""
    relative = relative.replace(os.sep, "/")
    if relative == ".." or relative.startswith("../") or os.path.isabs(relative):
        raise InvalidInput("The selected path is outside the baseline root.")
    return relative


def key_in_scope(key: str, scope: str) -> bool:
    if scope == "":
        return True
    return key == scope or key.startswith(scope + "/")


def default_store_dir() -> Path:
    configured = os.environ.get("INTEGRITY_CHECK_STORE")
    if configured:
        return canonical_path(configured)
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    elif os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
    else:
        base = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local" / "state")))
    return canonical_path(str(base / "log-integrity"))


def resolve_store(value: Optional[str]) -> Path:
    return canonical_path(value) if value else default_store_dir()


def ensure_store(store: Path) -> None:
    try:
        store.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        raise StoreError(f"Could not create the baseline store at {store}: {exc}") from exc
    if not store.is_dir():
        raise StoreError(f"The baseline store is not a directory: {store}")
    if os.name != "nt":
        try:
            os.chmod(store, 0o700)
        except OSError as exc:
            raise StoreError(f"Could not secure the baseline store at {store}: {exc}") from exc


def manifest_path(store: Path, target: Path) -> Path:
    name = hashlib.sha256(os.fsencode(str(target))).hexdigest() + ".json"
    return store / name


def validate_manifest(data: Any, path: Path) -> Dict[str, Any]:
    if not isinstance(data, dict):
        raise StoreError(f"Baseline manifest is not a JSON object: {path.name}")
    if data.get("format") != MANIFEST_FORMAT or data.get("version") != MANIFEST_VERSION:
        raise StoreError(f"Unsupported baseline manifest: {path.name}")
    if data.get("algorithm") != ALGORITHM:
        raise StoreError(f"Unsupported hash algorithm in baseline: {path.name}")
    target_value = data.get("target")
    target_type = data.get("target_type")
    if not isinstance(target_value, str) or not os.path.isabs(target_value):
        raise StoreError(f"Invalid target path in baseline: {path.name}")
    if target_type not in ("file", "directory"):
        raise StoreError(f"Invalid target type in baseline: {path.name}")
    files = data.get("files")
    if not isinstance(files, dict):
        raise StoreError(f"Invalid file list in baseline: {path.name}")
    for key, entry in files.items():
        if not isinstance(key, str):
            raise StoreError(f"Invalid file key in baseline: {path.name}")
        if key:
            parts = key.split("/")
            if key.startswith("/") or ".." in parts:
                raise StoreError(f"Unsafe file key in baseline: {path.name}")
        elif target_type != "file":
            raise StoreError(f"Empty file key in directory baseline: {path.name}")
        if not isinstance(entry, dict):
            raise StoreError(f"Invalid file entry in baseline: {path.name}")
        digest = entry.get("sha256")
        size = entry.get("size")
        if not isinstance(digest, str) or not DIGEST_RE.match(digest):
            raise StoreError(f"Invalid SHA-256 value in baseline: {path.name}")
        if not isinstance(size, int) or size < 0:
            raise StoreError(f"Invalid file size in baseline: {path.name}")
    if target_type == "file" and set(files) != {""}:
        raise StoreError(f"Invalid file baseline entries: {path.name}")
    return data


def load_manifest_file(path: Path) -> Dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except OSError as exc:
        raise StoreError(f"Could not read baseline manifest {path.name}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise StoreError(f"Baseline manifest is not valid JSON: {path.name}") from exc
    return validate_manifest(data, path)


def find_baseline(store: Path, target: Path) -> Optional[Dict[str, Any]]:
    exact_path = manifest_path(store, target)
    if exact_path.exists():
        manifest = load_manifest_file(exact_path)
        if same_path(Path(manifest["target"]), target):
            return manifest
    candidates: List[Tuple[int, Dict[str, Any]]] = []
    if not store.is_dir():
        return None
    for path in store.glob("*.json"):
        if path.name.startswith("."):
            continue
        try:
            manifest = load_manifest_file(path)
        except IntegrityError:
            continue
        root = Path(manifest["target"])
        if manifest["target_type"] == "directory" and is_within(target, root):
            candidates.append((len(normalize_path(root)), manifest))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][1]


def list_baselines(store: Path) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    if not store.is_dir():
        return items
    for path in store.glob("*.json"):
        if path.name.startswith("."):
            continue
        try:
            manifest = load_manifest_file(path)
        except IntegrityError as exc:
            items.append(
                {
                    "target": None,
                    "target_type": None,
                    "file_count": 0,
                    "created_at": None,
                    "updated_at": None,
                    "revision": None,
                    "error": str(exc),
                    "manifest": path.name,
                }
            )
            continue
        items.append(
            {
                "target": manifest["target"],
                "target_type": manifest["target_type"],
                "file_count": len(manifest["files"]),
                "created_at": manifest.get("created_at"),
                "updated_at": manifest.get("updated_at"),
                "revision": manifest.get("revision"),
                "error": None,
                "manifest": path.name,
            }
        )
    items.sort(key=lambda item: (item["target"] or "", item["manifest"]))
    return items


class StoreLock:
    def __init__(self, store: Path):
        self.path = store / ".lock"
        self.handle = None

    def __enter__(self) -> "StoreLock":
        try:
            self.handle = self.path.open("a+b")
            if fcntl is not None:
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX)
            elif msvcrt is not None:
                self.handle.seek(0, os.SEEK_END)
                if self.handle.tell() == 0:
                    self.handle.write(b"0")
                    self.handle.flush()
                self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_LOCK, 1)
            if os.name != "nt":
                os.chmod(self.path, 0o600)
            return self
        except OSError as exc:
            if self.handle is not None:
                self.handle.close()
                self.handle = None
            raise StoreError(f"Could not lock the baseline store: {exc}") from exc

    def __exit__(self, exc_type: Any, exc_value: Any, traceback_value: Any) -> None:
        if self.handle is None:
            return
        try:
            if fcntl is not None:
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            elif msvcrt is not None:
                self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
        finally:
            self.handle.close()
            self.handle = None


def write_manifest(store: Path, target: Path, manifest: Dict[str, Any]) -> Path:
    destination = manifest_path(store, target)
    payload = (json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )
    descriptor = None
    temporary = None
    try:
        descriptor, temporary = tempfile.mkstemp(
            prefix=".manifest-", suffix=".tmp", dir=str(store)
        )
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
        temporary = None
        if os.name != "nt":
            os.chmod(destination, 0o600)
            try:
                directory_fd = os.open(str(store), os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                pass
        return destination
    except OSError as exc:
        raise StoreError(f"Could not write the baseline manifest: {exc}") from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def hash_bytes(data: bytes) -> Dict[str, Any]:
    """Hash an in-memory byte buffer (used for browser uploads)."""
    digest = hashlib.sha256(data)
    return {
        "sha256": digest.hexdigest(),
        "size": len(data),
        "mtime_ns": 0,
    }


def parse_multipart(body: bytes, boundary: bytes) -> Dict[str, Any]:
    """Minimal multipart/form-data parser — returns {name: bytes} for each part."""
    parts: Dict[str, Any] = {}
    delimiter = b"--" + boundary
    segments = body.split(delimiter)
    for segment in segments[1:]:
        if segment.strip() in (b"", b"--", b"--\r\n"):
            continue
        if segment.startswith(b"--"):
            continue
        # Split headers from body on the first blank line
        if b"\r\n\r\n" in segment:
            header_block, _, part_body = segment.partition(b"\r\n\r\n")
        elif b"\n\n" in segment:
            header_block, _, part_body = segment.partition(b"\n\n")
        else:
            continue
        # Strip the trailing CRLF before the next boundary
        if part_body.endswith(b"\r\n"):
            part_body = part_body[:-2]
        # Parse Content-Disposition to get the field name
        name = None
        filename = None
        for line in header_block.split(b"\r\n"):
            line_str = line.decode("utf-8", errors="replace")
            if line_str.lower().startswith("content-disposition:"):
                for token in line_str.split(";"):
                    token = token.strip()
                    if token.startswith("name="):
                        name = token[5:].strip('"')
                    elif token.startswith("filename="):
                        filename = token[9:].strip('"')
        if name is not None:
            parts[name] = {"data": part_body, "filename": filename}
    return parts


def perform_upload(filename: str, data: bytes, store: Path) -> Dict[str, Any]:
    """Hash uploaded bytes and auto-init or auto-check against a named baseline."""
    if not filename or not filename.strip():
        raise InvalidInput("A filename is required.")
    # Sanitise: keep only the base name, forbid path separators
    safe_name = os.path.basename(filename.strip())
    if not safe_name or safe_name in (".", ".."):
        raise InvalidInput(f"Invalid filename: {filename!r}")

    ensure_store(store)
    # Use a virtual path rooted at a fixed upload namespace so we never collide
    # with real filesystem baselines.
    # Use an absolute virtual path so validate_manifest accepts it.
    # The path never exists on disk; it's just a stable key per filename.
    virtual_root = Path("/__uploads__")
    virtual_target = virtual_root / safe_name

    # We key the manifest by the virtual path string.
    manifest_key_path = virtual_target

    def _find_upload_baseline() -> Optional[Dict[str, Any]]:
        mpath = manifest_path(store, manifest_key_path)
        if not mpath.exists():
            return None
        try:
            m = load_manifest_file(mpath)
        except IntegrityError:
            return None
        if m.get("target") == str(virtual_target):
            return m
        return None

    current_entry = hash_bytes(data)
    timestamp = now_iso()

    with StoreLock(store):
        existing = _find_upload_baseline()
        if existing is None:
            # First upload of this filename — store baseline.
            files = {"": current_entry}
            new_manifest = {
                "format": MANIFEST_FORMAT,
                "version": MANIFEST_VERSION,
                "algorithm": ALGORITHM,
                "target": str(virtual_target),
                "target_type": "file",
                "created_at": timestamp,
                "updated_at": timestamp,
                "revision": 1,
                "files": files,
            }
            write_manifest(store, manifest_key_path, new_manifest)
            return {
                "ok": True,
                "action": "init",
                "status": "baseline_created",
                "filename": safe_name,
                "target": str(virtual_target),
                "baseline": str(virtual_target),
                "files_hashed": 1,
                "store": str(store),
                "sha256": current_entry["sha256"],
                "size": current_entry["size"],
                "created_at": timestamp,
                "updated_at": timestamp,
                "message": f"Baseline created for \"{safe_name}\". Upload the file again to check it.",
            }
        else:
            # Baseline exists — compare.
            stored_entry = existing["files"].get("")
            if stored_entry is None:
                raise StoreError("Stored baseline is malformed.")
            matched = hmac.compare_digest(stored_entry["sha256"], current_entry["sha256"])
            return {
                "ok": True,
                "action": "check",
                "status": "unmodified" if matched else "modified",
                "filename": safe_name,
                "target": str(virtual_target),
                "baseline": str(virtual_target),
                "files_checked": 1,
                "unmodified": 1 if matched else 0,
                "modified": 0 if matched else 1,
                "missing": 0,
                "new": 0,
                "errors": 0,
                "discrepancies": 0 if matched else 1,
                "possible_tampering": not matched,
                "stored_sha256": stored_entry["sha256"],
                "current_sha256": current_entry["sha256"],
                "size": current_entry["size"],
                "stored_size": stored_entry["size"],
                "checked_at": timestamp,
                "message": (
                    f"\"{safe_name}\" matches the baseline — file is unmodified."
                    if matched else
                    f"\"{safe_name}\" does not match the baseline — possible tampering detected."
                ),
            }


def hash_file(path: Path) -> Dict[str, Any]:
    for _ in range(2):
        try:
            with path.open("rb") as handle:
                before = os.fstat(handle.fileno())
                if not stat.S_ISREG(before.st_mode):
                    raise InvalidInput(f"Not a regular file: {path}")
                digest = hashlib.sha256()
                while True:
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                after = os.fstat(handle.fileno())
            current = os.stat(path)
        except FileNotFoundError:
            time.sleep(0.05)
            continue
        except OSError as exc:
            raise IntegrityError(f"Could not read {path}: {exc}") from exc
        unchanged = (
            before.st_size == after.st_size == current.st_size
            and before.st_mtime_ns == after.st_mtime_ns == current.st_mtime_ns
            and before.st_ino == current.st_ino
            and before.st_dev == current.st_dev
        )
        if unchanged:
            return {
                "sha256": digest.hexdigest(),
                "size": after.st_size,
                "mtime_ns": after.st_mtime_ns,
            }
        time.sleep(0.05)
    raise IntegrityError(f"File changed while it was being hashed: {path}")


def snapshot_path(
    target: Path, root: Path, store: Path
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    entries: Dict[str, Dict[str, Any]] = {}
    errors: Dict[str, str] = {}

    if target.is_file():
        key = relative_key(target, root)
        try:
            entries[key] = hash_file(target)
        except IntegrityError as exc:
            errors[key] = str(exc)
        return entries, errors

    if target.is_dir():
        def on_walk_error(error: OSError) -> None:
            filename = error.filename or str(target)
            try:
                key = relative_key(Path(filename), root)
            except IntegrityError:
                key = "."
            errors[key] = str(error)

        for directory, directory_names, file_names in os.walk(
            target, topdown=True, followlinks=False, onerror=on_walk_error
        ):
            directory_path = Path(directory)
            directory_names[:] = sorted(
                name
                for name in directory_names
                if not same_path(directory_path / name, store)
            )
            for name in sorted(file_names):
                full_path = directory_path / name
                try:
                    if full_path.is_symlink():
                        continue
                    file_stat = full_path.stat()
                    if not stat.S_ISREG(file_stat.st_mode):
                        continue
                    key = relative_key(full_path, root)
                    entries[key] = hash_file(full_path)
                except IntegrityError as exc:
                    try:
                        key = relative_key(full_path, root)
                    except IntegrityError:
                        key = "."
                    errors[key] = str(exc)
                except OSError as exc:
                    try:
                        key = relative_key(full_path, root)
                    except IntegrityError:
                        key = "."
                    errors[key] = str(exc)
        return entries, errors

    errors[relative_key(target, root)] = f"Path is not a regular file or directory: {target}"
    return entries, errors


def scope_for_target(target: Path, baseline_target: Path) -> str:
    if same_path(target, baseline_target):
        return ""
    if not is_within(target, baseline_target):
        raise InvalidInput("The selected path is outside the baseline.")
    return relative_key(target, baseline_target)


def manifest_for_target(
    target: Path,
    target_type: str,
    files: Dict[str, Dict[str, Any]],
    created_at: Optional[str] = None,
    revision: int = 1,
) -> Dict[str, Any]:
    timestamp = now_iso()
    return {
        "format": MANIFEST_FORMAT,
        "version": MANIFEST_VERSION,
        "algorithm": ALGORITHM,
        "target": str(target),
        "target_type": target_type,
        "created_at": created_at or timestamp,
        "updated_at": timestamp,
        "revision": revision,
        "files": files,
    }


def perform_init(target_value: Any, store: Path, force: bool = False) -> Dict[str, Any]:
    target = canonical_path(target_value)
    if not target.exists():
        raise InvalidInput(f"Path does not exist: {target}")
    if not (target.is_file() or target.is_dir()):
        raise InvalidInput(f"Path is not a regular file or directory: {target}")
    if is_within(target, store):
        raise InvalidInput("The target path cannot be inside the baseline store.")
    ensure_store(store)
    target_type = "file" if target.is_file() else "directory"
    with StoreLock(store):
        existing = manifest_path(store, target).exists()
        if existing and not force:
            raise BaselineExists(
                f"A baseline already exists for {target}. Use re-initialization to replace it."
            )
        entries, errors = snapshot_path(target, target, store)
        if errors:
            first = next(iter(errors.items()))
            raise IntegrityError(f"Could not hash {first[0] or target}: {first[1]}")
        manifest = manifest_for_target(target, target_type, entries)
        destination = write_manifest(store, target, manifest)
    return {
        "ok": True,
        "action": "init",
        "target": str(target),
        "target_type": target_type,
        "baseline": str(target),
        "files_hashed": len(entries),
        "store": str(store),
        "manifest": str(destination),
        "reinitialized": existing,
        "created_at": manifest["created_at"],
        "updated_at": manifest["updated_at"],
    }


def perform_check(target_value: Any, store: Path) -> Dict[str, Any]:
    target = canonical_path(target_value)
    ensure_store(store)
    manifest = find_baseline(store, target)
    if manifest is None:
        raise BaselineNotFound(
            f"No baseline found for {target}. Initialize a baseline before checking."
        )
    root = Path(manifest["target"])
    scope = scope_for_target(target, root)
    expected = {
        key: entry for key, entry in manifest["files"].items() if key_in_scope(key, scope)
    }
    if not target.exists() and not expected:
        raise InvalidInput(f"Path does not exist and is not recorded in the baseline: {target}")
    if target.exists():
        current, read_errors = snapshot_path(target, root, store)
        current = {key: entry for key, entry in current.items() if key_in_scope(key, scope)}
        read_errors = {
            key: message for key, message in read_errors.items() if key_in_scope(key, scope)
        }
    else:
        current = {}
        read_errors = {}

    results: List[Dict[str, Any]] = []
    keys = sorted(set(expected) | set(current) | set(read_errors))
    for key in keys:
        expected_entry = expected.get(key)
        current_entry = current.get(key)
        display_path = key if key else str(target)
        if key in read_errors:
            results.append(
                {
                    "path": display_path,
                    "status": "error",
                    "detail": read_errors[key],
                    "stored_sha256": expected_entry["sha256"] if expected_entry else None,
                    "current_sha256": None,
                    "size": expected_entry["size"] if expected_entry else None,
                }
            )
        elif expected_entry is not None and current_entry is None:
            results.append(
                {
                    "path": display_path,
                    "status": "missing",
                    "detail": "File was present in the baseline but is now missing.",
                    "stored_sha256": expected_entry["sha256"],
                    "current_sha256": None,
                    "size": expected_entry["size"],
                }
            )
        elif expected_entry is None and current_entry is not None:
            results.append(
                {
                    "path": display_path,
                    "status": "new",
                    "detail": "File is not present in the baseline.",
                    "stored_sha256": None,
                    "current_sha256": current_entry["sha256"],
                    "size": current_entry["size"],
                }
            )
        elif expected_entry is not None and current_entry is not None:
            if hmac.compare_digest(expected_entry["sha256"], current_entry["sha256"]):
                results.append(
                    {
                        "path": display_path,
                        "status": "unmodified",
                        "detail": "SHA-256 hash matches the baseline.",
                        "stored_sha256": expected_entry["sha256"],
                        "current_sha256": current_entry["sha256"],
                        "size": current_entry["size"],
                    }
                )
            else:
                results.append(
                    {
                        "path": display_path,
                        "status": "modified",
                        "detail": "SHA-256 hash does not match the baseline.",
                        "stored_sha256": expected_entry["sha256"],
                        "current_sha256": current_entry["sha256"],
                        "size": current_entry["size"],
                    }
                )

    modified = sum(1 for item in results if item["status"] == "modified")
    missing = sum(1 for item in results if item["status"] == "missing")
    new = sum(1 for item in results if item["status"] == "new")
    errors = sum(1 for item in results if item["status"] == "error")
    unmodified = sum(1 for item in results if item["status"] == "unmodified")
    discrepancies = modified + missing + new
    if discrepancies:
        status = "modified"
    elif errors:
        status = "error"
    else:
        status = "unmodified"
    return {
        "ok": True,
        "action": "check",
        "status": status,
        "target": str(target),
        "baseline": str(root),
        "store": str(store),
        "algorithm": "SHA-256",
        "files_checked": len(results),
        "unmodified": unmodified,
        "modified": modified,
        "missing": missing,
        "new": new,
        "errors": errors,
        "discrepancies": discrepancies,
        "possible_tampering": modified + missing > 0,
        "results": results,
        "checked_at": now_iso(),
    }


def perform_update(target_value: Any, store: Path) -> Dict[str, Any]:
    target = canonical_path(target_value)
    if not target.exists():
        raise InvalidInput(f"Path does not exist: {target}")
    if not (target.is_file() or target.is_dir()):
        raise InvalidInput(f"Path is not a regular file or directory: {target}")
    if is_within(target, store):
        raise InvalidInput("The target path cannot be inside the baseline store.")
    ensure_store(store)
    with StoreLock(store):
        manifest = find_baseline(store, target)
        if manifest is None:
            raise BaselineNotFound(
                f"No baseline found for {target}. Initialize a baseline before updating."
            )
        root = Path(manifest["target"])
        scope = scope_for_target(target, root)
        current, errors = snapshot_path(target, root, store)
        current = {key: entry for key, entry in current.items() if key_in_scope(key, scope)}
        errors = {key: message for key, message in errors.items() if key_in_scope(key, scope)}
        if errors:
            first = next(iter(errors.items()))
            raise IntegrityError(f"Could not hash {first[0] or target}: {first[1]}")
        files = {
            key: entry for key, entry in manifest["files"].items() if not key_in_scope(key, scope)
        }
        files.update(current)
        root_type = manifest["target_type"]
        if root.is_file():
            root_type = "file"
        elif root.is_dir():
            root_type = "directory"
        updated = manifest_for_target(
            root,
            root_type,
            files,
            created_at=manifest.get("created_at"),
            revision=int(manifest.get("revision", 1)) + 1,
        )
        destination = write_manifest(store, root, updated)
    return {
        "ok": True,
        "action": "update",
        "target": str(target),
        "baseline": str(root),
        "files_updated": len(current),
        "total_files": len(files),
        "store": str(store),
        "manifest": str(destination),
        "updated_at": updated["updated_at"],
        "revision": updated["revision"],
    }


def status_payload(store: Path) -> Dict[str, Any]:
    ensure_store(store)
    return {
        "ok": True,
        "action": "status",
        "store": str(store),
        "algorithm": "SHA-256",
        "version": VERSION,
        "baselines": list_baselines(store),
    }


def check_exit_code(report: Dict[str, Any]) -> int:
    if report["discrepancies"] > 0:
        return EXIT_DISCREPANCY
    if report["errors"] > 0:
        return EXIT_ERROR
    return EXIT_OK


def print_check_report(report: Dict[str, Any]) -> None:
    if report["status"] == "unmodified":
        print("Status: Unmodified")
    elif report["modified"] > 0:
        print("Status: Modified (Hash mismatch)")
    elif report["missing"] > 0:
        print("Status: Modified (File missing)")
    elif report["new"] > 0:
        print("Status: Modified (Unexpected file)")
    else:
        print("Status: Error (Unable to read one or more files)")
    print(f"Baseline: {report['baseline']}")
    print(f"Files checked: {report['files_checked']}")
    if report["discrepancies"] or report["errors"]:
        print(
            "Summary: "
            f"{report['modified']} modified, "
            f"{report['missing']} missing, "
            f"{report['new']} new, "
            f"{report['errors']} unreadable"
        )
    for item in report["results"]:
        if item["status"] == "unmodified":
            continue
        print(f"  {item['status'].upper():<9} {item['path']} - {item['detail']}")
    if report["possible_tampering"]:
        print("Warning: possible file tampering detected. Review the files listed above.")
    elif report["new"]:
        print("Notice: files not present in the baseline were found.")


_SUBCOMMANDS = {"init", "reinit", "check", "update", "serve"}


def _is_simple_path_invocation(argv: List[str]) -> Optional[str]:
    """Return the path argument if the user passed a bare path with no subcommand."""
    positionals = [a for a in argv if not a.startswith("-")]
    if not positionals:
        return None
    first = positionals[0]
    if first in _SUBCOMMANDS:
        return None
    return first


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="integrity-check",
        description=(
            "SHA-256 baseline tool for log files and directories.\n\n"
            "Simple usage: just pass a file or directory path.\n"
            "  If no baseline exists yet, one will be created automatically.\n"
            "  If a baseline already exists, it will be checked for changes."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument(
        "--store",
        metavar="DIR",
        default=None,
        help="Baseline store directory. Defaults to the user state directory.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the check report as JSON (only used when checking).",
    )
    subparsers = parser.add_subparsers(dest="command")

    def add_store(command_parser: argparse.ArgumentParser) -> None:
        command_parser.add_argument(
            "--store",
            metavar="DIR",
            default=argparse.SUPPRESS,
            help="Baseline store directory. Defaults to the user state directory.",
        )

    init_parser = subparsers.add_parser("init", help="Create a new baseline.")
    init_parser.add_argument("path", help="File or directory to baseline.")
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="Replace an existing baseline for this path.",
    )
    add_store(init_parser)

    reinit_parser = subparsers.add_parser(
        "reinit", help="Replace an existing baseline for a file or directory."
    )
    reinit_parser.add_argument("path", help="File or directory to re-initialize.")
    add_store(reinit_parser)

    check_parser = subparsers.add_parser("check", help="Compare files against the baseline.")
    check_parser.add_argument("path", help="File or directory to check.")
    check_parser.add_argument("--json", action="store_true", help="Print the report as JSON.")
    add_store(check_parser)

    update_parser = subparsers.add_parser(
        "update", help="Accept the current state of a path as the new baseline."
    )
    update_parser.add_argument("path", help="File or directory to update.")
    add_store(update_parser)

    serve_parser = subparsers.add_parser("serve", help="Run the local web interface.")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Bind address.")
    serve_parser.add_argument("--port", default=DEFAULT_PORT, type=int, help="Bind port.")
    add_store(serve_parser)

    return parser


def run_server(store: Path, host: str, port: int) -> int:
    ensure_store(store)
    token = secrets.token_urlsafe(32)
    handler_class = make_handler(store, token, host)
    server_class: Any = ThreadingHTTPServer
    if ":" in host:
        class IPv6ThreadingHTTPServer(ThreadingHTTPServer):
            address_family = socket.AF_INET6

        server_class = IPv6ThreadingHTTPServer
    try:
        server = server_class((host, port), handler_class)
    except (OSError, OverflowError, ValueError) as exc:
        print(f"Error: could not start the web server: {exc}", file=sys.stderr)
        return EXIT_ERROR
    server.daemon_threads = True
    actual_host, actual_port = server.server_address[:2]
    display_host = str(actual_host)
    if display_host in ("0.0.0.0", "::"):
        display_host = "127.0.0.1" if display_host == "0.0.0.0" else "::1"
    if ":" in display_host and not display_host.startswith("["):
        display_host = f"[{display_host}]"
    print(f"Log integrity checker: http://{display_host}:{actual_port}/")
    print(f"Baseline store: {store}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping web server.")
    finally:
        server.server_close()
    return EXIT_OK


def make_handler(store: Path, token: str, bind_host: str) -> Any:
    class IntegrityHandler(BaseHTTPRequestHandler):
        server_version = "LogIntegrity"
        sys_version = ""

        def log_message(self, format_string: str, *args: Any) -> None:
            sys.stderr.write(
                f"{self.address_string()} - {format_string % args}\n"
            )

        def _host_is_allowed(self) -> bool:
            if bind_host not in LOOPBACK_HOSTS:
                return True
            host_header = self.headers.get("Host", "")
            try:
                hostname = urlsplit("//" + host_header).hostname
            except ValueError:
                return False
            return bool(hostname) and hostname.lower() in LOOPBACK_HOSTS

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                "connect-src 'self'; img-src 'self' data:; font-src 'self'; "
                "base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
            )
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self._send(status, body, "application/json; charset=utf-8")

        def do_GET(self) -> None:
            if not self._host_is_allowed():
                self._send_json(400, {"ok": False, "error": "Invalid Host header."})
                return
            path = urlsplit(self.path).path
            if path == "/healthz":
                self._send_json(200, {"ok": True, "status": "ok", "version": VERSION})
                return
            if path in ("/", "/index.html"):
                page = HTML_PAGE.replace("__CSRF_TOKEN__", token).encode("utf-8")
                self._send(200, page, "text/html; charset=utf-8")
                return
            if path == "/favicon.ico":
                self._send(204, b"", "text/plain; charset=utf-8")
                return
            self._send(404, b"Not found.\n", "text/plain; charset=utf-8")

        def _handle_upload(self) -> None:
            """Handle multipart/form-data file upload for /api/upload."""
            provided = self.headers.get("X-Integrity-Token", "")
            if not hmac.compare_digest(provided, token):
                self._send_json(403, {"ok": False, "error": "Invalid request token."})
                return
            content_type = self.headers.get("Content-Type", "")
            # Extract boundary from Content-Type header
            boundary = None
            for part in content_type.split(";"):
                part = part.strip()
                if part.startswith("boundary="):
                    boundary = part[9:].strip('"').encode("latin-1")
                    break
            if not boundary:
                self._send_json(400, {"ok": False, "error": "Missing multipart boundary."})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._send_json(400, {"ok": False, "error": "Invalid Content-Length."})
                return
            # 200 MB upload limit
            if length < 0 or length > 200 * 1024 * 1024:
                self._send_json(413, {"ok": False, "error": "File is too large (limit: 200 MB)."})
                return
            raw = self.rfile.read(length) if length else b""
            parts = parse_multipart(raw, boundary)
            file_part = parts.get("file")
            if file_part is None:
                self._send_json(400, {"ok": False, "error": "No file field in upload."})
                return
            filename = file_part.get("filename") or ""
            file_data = file_part.get("data", b"")
            try:
                response = perform_upload(filename, file_data, store)
                self._send_json(200, response)
            except IntegrityError as exc:
                self._send_json(exc.status_code, {"ok": False, "error": str(exc)})
            except Exception:
                traceback.print_exc()
                self._send_json(500, {"ok": False, "error": "Internal server error."})

        def do_POST(self) -> None:
            if not self._host_is_allowed():
                self._send_json(400, {"ok": False, "error": "Invalid Host header."})
                return
            action = urlsplit(self.path).path
            # File upload uses multipart — handle before the JSON gate
            if action == "/api/upload":
                self._handle_upload()
                return
            provided = self.headers.get("X-Integrity-Token", "")
            if not hmac.compare_digest(provided, token):
                self._send_json(403, {"ok": False, "error": "Invalid request token."})
                return
            content_type = self.headers.get("Content-Type", "")
            if not content_type.lower().startswith("application/json"):
                self._send_json(415, {"ok": False, "error": "Expected a JSON request."})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._send_json(400, {"ok": False, "error": "Invalid Content-Length."})
                return
            if length < 0 or length > 65536:
                self._send_json(413, {"ok": False, "error": "Request body is too large."})
                return
            raw = self.rfile.read(length) if length else b"{}"
            try:
                data = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_json(400, {"ok": False, "error": "Request body is not valid JSON."})
                return
            if not isinstance(data, dict):
                self._send_json(400, {"ok": False, "error": "Request body must be a JSON object."})
                return
            try:
                if action == "/api/status":
                    response = status_payload(store)
                elif action == "/api/init":
                    response = perform_init(data.get("path"), store, force=False)
                    response["message"] = "Baseline created successfully."
                elif action == "/api/reinit":
                    response = perform_init(data.get("path"), store, force=True)
                    response["action"] = "reinit"
                    response["message"] = "Baseline re-initialized successfully."
                elif action == "/api/check":
                    response = perform_check(data.get("path"), store)
                    if response["status"] == "unmodified":
                        response["message"] = "All checked files match the baseline."
                    elif response["errors"] and response["discrepancies"] == 0:
                        response["message"] = "Check completed with unreadable files."
                    elif response["possible_tampering"]:
                        response["message"] = (
                            "Discrepancies found. Possible file tampering detected."
                        )
                    else:
                        response["message"] = "Files not present in the baseline were found."
                elif action == "/api/update":
                    response = perform_update(data.get("path"), store)
                    response["message"] = "Baseline updated successfully."
                else:
                    self._send_json(404, {"ok": False, "error": "API endpoint not found."})
                    return
                self._send_json(200, response)
            except IntegrityError as exc:
                self._send_json(exc.status_code, {"ok": False, "error": str(exc)})
            except Exception:
                traceback.print_exc()
                self._send_json(500, {"ok": False, "error": "Internal server error."})

        def do_HEAD(self) -> None:
            self._send(405, b"", "text/plain; charset=utf-8")

    return IntegrityHandler


def main(argv: Optional[List[str]] = None) -> int:
    effective_argv: List[str] = sys.argv[1:] if argv is None else list(argv)

    # Simple mode: detect a bare path argument (no subcommand) before argparse
    # sees it, because argparse cannot distinguish a path from a subcommand name.
    simple_path = _is_simple_path_invocation(effective_argv)
    if simple_path is not None:
        # Parse only the flags (store, json, version, help).
        flag_parser = argparse.ArgumentParser(add_help=False)
        flag_parser.add_argument("--store", metavar="DIR", default=None)
        flag_parser.add_argument("--json", action="store_true", default=False)
        flag_parser.add_argument("--version", action="version", version=f"integrity-check {VERSION}")
        flag_args, _ = flag_parser.parse_known_args(effective_argv)
        store = resolve_store(flag_args.store)
        try:
            ensure_store(store)
            target = canonical_path(simple_path)
            existing = find_baseline(store, target)
            if existing is None:
                result = perform_init(simple_path, store, force=False)
                print("No baseline found. Creating one now...")
                print("Baseline created.")
                print(f"Path:         {result['baseline']}")
                print(f"Files hashed: {result['files_hashed']}")
                print(f"Store:        {result['store']}")
                return EXIT_OK
            else:
                report = perform_check(simple_path, store)
                if flag_args.json:
                    print(json.dumps(report, indent=2, ensure_ascii=False))
                else:
                    print_check_report(report)
                return check_exit_code(report)
        except IntegrityError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return EXIT_ERROR
        except KeyboardInterrupt:
            print("\nCancelled.", file=sys.stderr)
            return EXIT_ERROR
        except Exception as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return EXIT_ERROR

    parser = build_parser()
    args = parser.parse_args(effective_argv)
    store = resolve_store(getattr(args, "store", None))
    try:
        if args.command is None:
            parser.print_help()
            return EXIT_OK

        if args.command == "serve":
            return run_server(store, args.host, args.port)
        ensure_store(store)
        if args.command == "init":
            result = perform_init(args.path, store, force=args.force)
            print("Hashes stored successfully.")
            print(f"Baseline: {result['baseline']}")
            print(f"Files hashed: {result['files_hashed']}")
            print(f"Store: {result['store']}")
            return EXIT_OK
        if args.command == "reinit":
            result = perform_init(args.path, store, force=True)
            print("Hashes stored successfully.")
            print(f"Baseline re-initialized: {result['baseline']}")
            print(f"Files hashed: {result['files_hashed']}")
            print(f"Store: {result['store']}")
            return EXIT_OK
        if args.command == "check":
            report = perform_check(args.path, store)
            if args.json:
                print(json.dumps(report, indent=2, ensure_ascii=False))
            else:
                print_check_report(report)
            return check_exit_code(report)
        if args.command == "update":
            result = perform_update(args.path, store)
            print("Hash updated successfully.")
            print(f"Baseline: {result['baseline']}")
            print(f"Files updated: {result['files_updated']}")
            print(f"Total files in baseline: {result['total_files']}")
            return EXIT_OK
    except IntegrityError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_ERROR


HTML_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>Log Integrity Checker</title>
<link rel="icon" href="data:,">
<style>
:root {
    --page: #f4f5f6;
    --panel: #ffffff;
    --ink: #1d2733;
    --muted: #596675;
    --faint: #7b8794;
    --line: #d8dee4;
    --line-strong: #b9c2cc;
    --navy: #1f4c78;
    --navy-dark: #173a5c;
    --navy-soft: #edf3f9;
    --danger: #9f2f2f;
    --danger-dark: #7f2323;
    --danger-soft: #fbf1f1;
    --ok: #21643c;
    --ok-soft: #eef6f0;
    --warn: #7a5714;
    --warn-soft: #fbf5e8;
}
* { box-sizing: border-box; }
html { background: var(--page); }
body {
    margin: 0;
    color: var(--ink);
    background: var(--page);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    font-size: 15px;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
}
a { color: var(--navy); }
[hidden] { display: none !important; }
.wrap { width: min(1120px, calc(100% - 40px)); margin: 0 auto; }
.site-header { background: var(--panel); border-bottom: 1px solid var(--line); }
.site-header .wrap { min-height: 58px; display: flex; align-items: center; justify-content: space-between; gap: 20px; }
.brand { display: flex; align-items: baseline; gap: 10px; }
.brand strong { font-size: 15px; letter-spacing: 0.08em; text-transform: uppercase; }
.brand span { color: var(--muted); font-size: 13px; }
.header-note { color: var(--muted); font-size: 12px; }
main { padding: 30px 0 46px; }
.page-head { max-width: 760px; margin-bottom: 24px; }
.page-head h1 { margin: 0 0 8px; font-size: 28px; line-height: 1.2; letter-spacing: -0.01em; }
.page-head p { margin: 0; color: var(--muted); max-width: 68ch; }
.layout { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1.25fr); gap: 18px; align-items: start; }
.layout > * { min-width: 0; }
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 4px; min-width: 0; }
.panel-body { padding: 18px; }
.panel-head { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 14px 18px; border-bottom: 1px solid var(--line); }
.panel-head h2 { margin: 0; font-size: 15px; letter-spacing: 0.01em; }
.panel-head p { margin: 2px 0 0; color: var(--muted); font-size: 12px; }
/* ── File drop zone ── */
.drop-zone {
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    gap: 10px; min-height: 130px; padding: 24px 18px;
    border: 2px dashed var(--line-strong); border-radius: 4px;
    background: var(--page); cursor: pointer; text-align: center;
}
.drop-zone:hover, .drop-zone.drag-over { border-color: var(--navy); background: var(--navy-soft); }
.drop-zone.has-file { border-style: solid; border-color: var(--navy); background: var(--navy-soft); }
.drop-zone svg { flex-shrink: 0; opacity: 0.45; }
.drop-zone.has-file svg { opacity: 0.7; }
.drop-label { font-size: 14px; font-weight: 600; color: var(--ink); }
.drop-sub { font-size: 12px; color: var(--muted); }
.drop-filename { font-size: 13px; font-weight: 600; color: var(--navy); word-break: break-all; max-width: 100%; }
.drop-filesize { font-size: 11px; color: var(--muted); }
#file-input { display: none; }
/* Advanced section */
.advanced-toggle {
    display: flex; align-items: center; gap: 6px; margin-top: 14px;
    padding: 0; border: none; background: none; color: var(--muted);
    font: inherit; font-size: 12px; font-weight: 600; cursor: pointer; min-height: unset;
}
.advanced-toggle:hover { color: var(--ink); background: none; border: none; }
.advanced-toggle svg { flex-shrink: 0; transition: transform 0.15s; }
.advanced-toggle[aria-expanded="true"] svg { transform: rotate(90deg); }
.advanced-section { margin-top: 12px; }
.field { margin-bottom: 14px; }
.field label { display: block; margin-bottom: 6px; font-size: 12px; font-weight: 650; letter-spacing: 0.04em; text-transform: uppercase; color: var(--muted); }
.field input[type="text"] { width: 100%; min-height: 40px; padding: 9px 11px; border: 1px solid var(--line-strong); border-radius: 3px; background: #fff; color: var(--ink); font: inherit; }
.field input[type="text"]:focus { outline: 2px solid var(--navy); outline-offset: 1px; border-color: var(--navy); }
.hint { margin: 7px 0 0; color: var(--faint); font-size: 12px; }
.button-group { display: flex; flex-wrap: wrap; gap: 8px; }
.button-group + .button-group { margin-top: 10px; }
button { min-height: 38px; padding: 8px 14px; border: 1px solid var(--line-strong); border-radius: 3px; background: #fff; color: var(--ink); font: inherit; font-weight: 600; cursor: pointer; }
button:hover { background: #f7f8f9; border-color: #98a4b1; }
button:focus-visible { outline: 2px solid var(--navy); outline-offset: 2px; }
button:disabled { cursor: wait; color: var(--faint); background: #f5f6f7; }
button.primary { background: var(--navy); border-color: var(--navy); color: #fff; }
button.primary:hover { background: var(--navy-dark); border-color: var(--navy-dark); }
button.danger { color: var(--danger); border-color: #cda7a7; }
button.danger:hover { background: var(--danger-soft); border-color: var(--danger); }
.notice { margin-top: 16px; padding: 10px 12px; border: 1px solid var(--line); border-left: 3px solid var(--navy); background: var(--navy-soft); font-size: 13px; }
.notice.error { border-left-color: var(--danger); background: var(--danger-soft); color: var(--danger-dark); }
.notice.success { border-left-color: var(--ok); background: var(--ok-soft); color: #184b2d; }
.notice.warning { border-left-color: var(--warn); background: var(--warn-soft); color: var(--warn); }
.store-line { margin-top: 16px; padding-top: 14px; border-top: 1px solid var(--line); color: var(--muted); font-size: 12px; }
.store-line code, code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; }
.store-line code { word-break: break-all; color: var(--ink); }
.status { display: inline-block; padding: 3px 7px; border: 1px solid var(--line-strong); border-radius: 3px; background: #f7f8f9; color: var(--muted); font-size: 11px; font-weight: 700; letter-spacing: 0.04em; text-transform: uppercase; white-space: nowrap; }
.status.ok { color: var(--ok); background: var(--ok-soft); border-color: #b9d6c3; }
.status.warn { color: var(--warn); background: var(--warn-soft); border-color: #dfce9e; }
.status.error { color: var(--danger); background: var(--danger-soft); border-color: #d7b4b4; }
.empty { padding: 30px 18px; color: var(--muted); text-align: center; font-size: 13px; }
.visually-hidden { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0; }
.summary { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0; margin: 0; border-bottom: 1px solid var(--line); }
.summary div { padding: 11px 18px; border-bottom: 1px solid var(--line); }
.summary div:nth-last-child(-n+2) { border-bottom: 0; }
.summary dt { color: var(--muted); font-size: 11px; font-weight: 650; letter-spacing: 0.04em; text-transform: uppercase; }
.summary dd { margin: 3px 0 0; font-size: 14px; word-break: break-word; }
.summary dd code { font-size: 12px; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { padding: 10px 14px; text-align: left; vertical-align: top; border-bottom: 1px solid var(--line); }
th { color: var(--muted); background: #fafbfb; font-size: 11px; font-weight: 650; letter-spacing: 0.04em; text-transform: uppercase; white-space: nowrap; }
tbody tr:last-child td { border-bottom: 0; }
td.path { min-width: 180px; word-break: break-all; }
td.detail { color: var(--muted); min-width: 220px; }
td.actions { width: 1%; white-space: nowrap; }
td .small-button { min-height: 30px; padding: 4px 9px; font-size: 12px; font-weight: 500; }
.baselines { margin-top: 18px; }
.baselines .panel-body { padding: 0; }
.baselines .empty { text-align: left; }
.footer { color: var(--muted); font-size: 12px; padding: 0 0 30px; }
.footer p { margin: 0; }
.footer code { color: var(--ink); }
@media (max-width: 860px) {
    .layout { grid-template-columns: 1fr; }
    .page-head h1 { font-size: 24px; }
    .summary { grid-template-columns: 1fr; }
    .summary div:nth-last-child(-n+2) { border-bottom: 1px solid var(--line); }
    .summary div:last-child { border-bottom: 0; }
}
@media (max-width: 560px) {
    .wrap { width: calc(100% - 28px); }
    .header-note { display: none; }
    .panel-body { padding: 15px; }
    .panel-head { padding: 12px 15px; }
    th, td { padding: 9px 11px; }
}
@media (max-width: 480px) {
    .button-group button { flex: 1 1 100%; }
}
</style>
</head>
<body>
<header class="site-header">
    <div class="wrap">
        <div class="brand"><strong>Log Integrity</strong><span>SHA-256 baseline tool</span></div>
        <div class="header-note">Local utility &middot; SHA-256</div>
    </div>
</header>
<main class="wrap">
    <section class="page-head">
        <h1>Log file integrity checker</h1>
        <p>Select a file to check its SHA-256 integrity. The first upload stores a baseline; every upload after that compares against it.</p>
    </section>
    <div class="layout">
        <section class="panel" aria-labelledby="run-title">
            <div class="panel-head">
                <div>
                    <h2 id="run-title">Select a file</h2>
                    <p>Click to browse or drag a file onto the zone.</p>
                </div>
            </div>
            <div class="panel-body">
                <input type="file" id="file-input" aria-label="Select file">
                <div id="drop-zone" class="drop-zone" role="button" tabindex="0" aria-label="Select or drop a file">
                    <svg id="dz-icon-idle" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                        <polyline points="17 8 12 3 7 8"/>
                        <line x1="12" y1="3" x2="12" y2="15"/>
                    </svg>
                    <svg id="dz-icon-file" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" hidden>
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                        <polyline points="14 2 14 8 20 8"/>
                    </svg>
                    <span id="dz-label" class="drop-label">Click to browse or drop a file here</span>
                    <span id="dz-filename" class="drop-filename" hidden></span>
                    <span id="dz-size" class="drop-filesize" hidden></span>
                    <span class="drop-sub" id="dz-sub">Supports any file type &middot; up to 200 MB</span>
                </div>
                <div class="button-group" style="margin-top:14px;">
                    <button class="primary" id="btn-check-upload" disabled>Check integrity</button>
                </div>
                <button type="button" class="advanced-toggle" id="adv-toggle" aria-expanded="false" aria-controls="adv-section">
                    <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <polyline points="4 2 8 6 4 10"/>
                    </svg>
                    Advanced: use a server-side directory path
                </button>
                <div id="adv-section" class="advanced-section" hidden>
                    <div class="field">
                        <label for="path">Directory or file path on this server</label>
                        <input id="path" name="path" type="text" autocomplete="off" spellcheck="false" placeholder="/var/log or /var/log/syslog">
                        <p class="hint">Enter a path readable by the server process.</p>
                    </div>
                    <div class="button-group">
                        <button type="button" data-action="check">Check path</button>
                        <button type="button" data-action="init">Initialize baseline</button>
                        <button type="button" data-action="update">Update baseline</button>
                        <button class="danger" type="button" data-action="reinit">Re-initialize</button>
                    </div>
                </div>
                <div id="notice" class="notice" role="status" hidden></div>
                <div class="store-line">Baseline store: <code id="store-path">Loading...</code></div>
            </div>
        </section>
        <section class="panel" aria-labelledby="result-title">
            <div class="panel-head">
                <div>
                    <h2 id="result-title">Result</h2>
                    <p id="result-subtitle">No file has been checked.</p>
                </div>
                <span id="result-status" class="status">Idle</span>
            </div>
            <div id="result-empty" class="empty">Select a file and click Check integrity to get started.</div>
            <div id="result-content" hidden>
                <dl id="summary" class="summary"></dl>
                <div id="results-table-wrap" class="table-wrap" hidden>
                    <table>
                        <thead>
                            <tr><th scope="col">File</th><th scope="col">Status</th><th scope="col">Detail</th></tr>
                        </thead>
                        <tbody id="results-table"></tbody>
                    </table>
                </div>
                <div id="results-empty" class="empty" hidden></div>
            </div>
        </section>
    </div>
    <section class="panel baselines" aria-labelledby="baselines-title">
        <div class="panel-head">
            <div>
                <h2 id="baselines-title">Saved baselines</h2>
                <p>Baselines recorded in the store for this user.</p>
            </div>
        </div>
        <div class="panel-body">
            <div id="baselines-empty" class="empty">No baselines have been created.</div>
            <div id="baselines-table-wrap" class="table-wrap" hidden>
                <table>
                    <thead>
                        <tr><th scope="col">Path</th><th scope="col">Type</th><th scope="col">Files</th><th scope="col">Last updated</th><th scope="col"><span class="visually-hidden">Use</span></th></tr>
                    </thead>
                    <tbody id="baselines-table"></tbody>
                </table>
            </div>
        </div>
    </section>
</main>
<footer class="wrap footer">
    <p>The web interface binds to localhost by default. Baselines are kept in the store shown above.</p>
</footer>
<script>
(function () {
    "use strict";
    var token = "__CSRF_TOKEN__";
    var fileInput      = document.getElementById("file-input");
    var dropZone       = document.getElementById("drop-zone");
    var dzIconIdle     = document.getElementById("dz-icon-idle");
    var dzIconFile     = document.getElementById("dz-icon-file");
    var dzLabel        = document.getElementById("dz-label");
    var dzFilename     = document.getElementById("dz-filename");
    var dzSize         = document.getElementById("dz-size");
    var dzSub          = document.getElementById("dz-sub");
    var btnCheck       = document.getElementById("btn-check-upload");
    var advToggle      = document.getElementById("adv-toggle");
    var advSection     = document.getElementById("adv-section");
    var pathInput      = document.getElementById("path");
    var notice         = document.getElementById("notice");
    var storePath      = document.getElementById("store-path");
    var resultStatus   = document.getElementById("result-status");
    var resultSubtitle = document.getElementById("result-subtitle");
    var resultEmpty    = document.getElementById("result-empty");
    var resultContent  = document.getElementById("result-content");
    var summary        = document.getElementById("summary");
    var resultsWrap    = document.getElementById("results-table-wrap");
    var resultsTable   = document.getElementById("results-table");
    var resultsEmpty   = document.getElementById("results-empty");
    var baselinesEmpty = document.getElementById("baselines-empty");
    var baselinesWrap  = document.getElementById("baselines-table-wrap");
    var baselinesTable = document.getElementById("baselines-table");
    var pathActionBtns = Array.prototype.slice.call(document.querySelectorAll("[data-action]"));
    var busy = false;
    var selectedFile = null;

    function fmtSize(bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
        return (bytes / 1048576).toFixed(1) + " MB";
    }

    function setFile(file) {
        selectedFile = file;
        dzIconIdle.hidden = true;
        dzIconFile.hidden = false;
        dzLabel.hidden = true;
        dzSub.hidden = true;
        dzFilename.textContent = file.name;
        dzFilename.hidden = false;
        dzSize.textContent = fmtSize(file.size);
        dzSize.hidden = false;
        dropZone.classList.add("has-file");
        btnCheck.disabled = false;
    }

    dropZone.addEventListener("click", function () { if (!busy) fileInput.click(); });
    dropZone.addEventListener("keydown", function (e) {
        if ((e.key === "Enter" || e.key === " ") && !busy) { e.preventDefault(); fileInput.click(); }
    });
    fileInput.addEventListener("change", function () {
        if (fileInput.files && fileInput.files[0]) setFile(fileInput.files[0]);
    });
    dropZone.addEventListener("dragover", function (e) { e.preventDefault(); dropZone.classList.add("drag-over"); });
    dropZone.addEventListener("dragleave", function () { dropZone.classList.remove("drag-over"); });
    dropZone.addEventListener("drop", function (e) {
        e.preventDefault();
        dropZone.classList.remove("drag-over");
        var files = e.dataTransfer && e.dataTransfer.files;
        if (files && files[0]) setFile(files[0]);
    });

    advToggle.addEventListener("click", function () {
        var expanded = advToggle.getAttribute("aria-expanded") === "true";
        advToggle.setAttribute("aria-expanded", expanded ? "false" : "true");
        advSection.hidden = expanded;
    });

    function setNotice(message, kind) {
        notice.textContent = message;
        notice.className = kind ? "notice " + kind : "notice";
        notice.setAttribute("role", kind === "error" ? "alert" : "status");
        notice.hidden = false;
    }
    function hideNotice() { notice.hidden = true; notice.textContent = ""; }

    function setBusy(value) {
        busy = value;
        btnCheck.disabled = value || !selectedFile;
        pathActionBtns.forEach(function (b) { b.disabled = value; });
        dropZone.style.cursor = value ? "wait" : "pointer";
    }

    function setStatus(label, kind) {
        resultStatus.textContent = label;
        resultStatus.className = kind ? "status " + kind : "status";
    }

    function clearChildren(node) { while (node.firstChild) node.removeChild(node.firstChild); }

    function addSummary(term, value, isCode) {
        var g = document.createElement("div");
        var dt = document.createElement("dt");
        var dd = document.createElement("dd");
        dt.textContent = term;
        if (isCode) { var c = document.createElement("code"); c.textContent = value; dd.appendChild(c); }
        else { dd.textContent = value; }
        g.appendChild(dt); g.appendChild(dd); summary.appendChild(g);
    }

    function statusLabel(s) {
        return {unmodified:"Unmodified",modified:"Modified",missing:"Missing","new":"New",error:"Unreadable"}[s] || s;
    }
    function statusClass(s) {
        if (s === "unmodified") return "status ok";
        if (s === "new" || s === "missing" || s === "modified") return "status warn";
        return "status error";
    }
    function formatDate(v) {
        if (!v) return "Not recorded";
        var d = new Date(v);
        return isNaN(d.getTime()) ? v : d.toLocaleString();
    }

    function renderResult(r) {
        clearChildren(summary); clearChildren(resultsTable);
        resultEmpty.hidden = true; resultContent.hidden = false;
        resultsWrap.hidden = true; resultsEmpty.hidden = true;

        // Upload: first time (baseline created)
        if (r.action === "init" && r.status === "baseline_created") {
            setStatus("Baseline stored", "ok");
            resultSubtitle.textContent = "First upload \u2014 a new baseline was recorded.";
            addSummary("File", r.filename);
            addSummary("SHA-256", r.sha256.slice(0, 16) + "\u2026", true);
            addSummary("Size", fmtSize(r.size));
            addSummary("Stored", formatDate(r.created_at));
            resultsEmpty.hidden = false;
            resultsEmpty.textContent = "Upload this file again to check it for changes.";
            return;
        }

        // Path-based init / reinit
        if (r.action === "init" || r.action === "reinit") {
            setStatus(r.action === "reinit" ? "Re-initialized" : "Baseline stored", "ok");
            resultSubtitle.textContent = r.action === "reinit" ? "The baseline was replaced." : "A new baseline was written.";
            addSummary("Target", r.target, true);
            addSummary("Files hashed", String(r.files_hashed));
            addSummary("Store", r.store, true);
            addSummary("Created", formatDate(r.created_at));
            return;
        }

        if (r.action === "update") {
            setStatus("Baseline updated", "ok");
            resultSubtitle.textContent = "The selected path was accepted as the new baseline.";
            addSummary("Target", r.target, true);
            addSummary("Files updated", String(r.files_updated));
            addSummary("Total files in baseline", String(r.total_files));
            addSummary("Updated", formatDate(r.updated_at));
            return;
        }

        // Upload: subsequent check
        if (r.filename) {
            if (r.status === "unmodified") {
                setStatus("Unmodified", "ok");
                resultSubtitle.textContent = "File matches the stored SHA-256 baseline.";
            } else {
                setStatus("Modified", "warn");
                resultSubtitle.textContent = "File does not match the baseline \u2014 possible tampering.";
            }
            addSummary("File", r.filename);
            addSummary("Status", r.status === "unmodified" ? "Match" : "Mismatch");
            addSummary("Current SHA-256", r.current_sha256.slice(0, 16) + "\u2026", true);
            addSummary("Stored SHA-256",  r.stored_sha256.slice(0, 16)  + "\u2026", true);
            addSummary("Size", fmtSize(r.size));
            addSummary("Checked", formatDate(r.checked_at));
            if (r.status !== "unmodified") {
                resultsEmpty.hidden = false;
                resultsEmpty.textContent = "Stored: " + r.stored_sha256 + "\nCurrent: " + r.current_sha256;
            }
            return;
        }

        // Path-based check
        if (r.status === "unmodified") {
            setStatus("Unmodified", "ok");
            resultSubtitle.textContent = "Every checked file matches the stored SHA-256 hash.";
        } else if (r.status === "modified") {
            setStatus("Modified", "warn");
            resultSubtitle.textContent = "The current state differs from the baseline.";
        } else {
            setStatus("Error", "error");
            resultSubtitle.textContent = "One or more files could not be read.";
        }
        addSummary("Target", r.target, true);
        addSummary("Baseline", r.baseline, true);
        addSummary("Files checked", String(r.files_checked));
        addSummary("Discrepancies", String(r.discrepancies));
        addSummary("Modified", String(r.modified));
        addSummary("Missing", String(r.missing));
        addSummary("New", String(r.new));
        addSummary("Unreadable", String(r.errors));

        var visible = (r.results || []).filter(function (i) { return i.status !== "unmodified"; });
        if (visible.length === 0) {
            resultsEmpty.hidden = false;
            resultsEmpty.textContent = r.errors > 0
                ? "No hash discrepancies were found, but some files could not be read."
                : "All " + r.files_checked + " checked file(s) match the baseline.";
            return;
        }
        resultsWrap.hidden = false;
        visible.forEach(function (item) {
            var row = document.createElement("tr");
            var pC = document.createElement("td"); pC.className = "path mono"; pC.textContent = item.path;
            var sC = document.createElement("td");
            var dC = document.createElement("td"); dC.className = "detail";
            var badge = document.createElement("span"); badge.className = statusClass(item.status); badge.textContent = statusLabel(item.status);
            sC.appendChild(badge);
            dC.textContent = item.detail;
            if (item.status === "modified" && item.stored_sha256 && item.current_sha256)
                dC.textContent = item.detail + " Stored " + item.stored_sha256.slice(0,12) + "... current " + item.current_sha256.slice(0,12) + "...";
            row.appendChild(pC); row.appendChild(sC); row.appendChild(dC);
            resultsTable.appendChild(row);
        });
    }

    function renderBaselines(resp) {
        clearChildren(baselinesTable);
        var bs = resp.baselines || [];
        if (bs.length === 0) { baselinesEmpty.hidden = false; baselinesWrap.hidden = true; return; }
        baselinesEmpty.hidden = true; baselinesWrap.hidden = false;
        bs.forEach(function (item) {
            var row = document.createElement("tr");
            var pC = document.createElement("td"); pC.className = "path mono";
            var tC = document.createElement("td");
            var nC = document.createElement("td");
            var dC = document.createElement("td");
            var aC = document.createElement("td"); aC.className = "actions";
            if (item.error) {
                pC.textContent = "Unreadable manifest"; tC.textContent = "-"; nC.textContent = "-"; dC.textContent = item.error;
            } else {
                pC.textContent = item.target; tC.textContent = item.target_type;
                nC.textContent = String(item.file_count); dC.textContent = formatDate(item.updated_at);
                if (!item.target.startsWith("/__uploads__")) {
                    var btn = document.createElement("button");
                    btn.type = "button"; btn.className = "small-button"; btn.textContent = "Use path";
                    btn.addEventListener("click", function () {
                        advToggle.setAttribute("aria-expanded", "true"); advSection.hidden = false;
                        pathInput.value = item.target; pathInput.focus();
                    });
                    aC.appendChild(btn);
                }
            }
            row.appendChild(pC); row.appendChild(tC); row.appendChild(nC); row.appendChild(dC); row.appendChild(aC);
            baselinesTable.appendChild(row);
        });
    }

    async function api(action, payload) {
        var resp = await fetch("/api/" + action, {
            method: "POST",
            headers: {"Content-Type": "application/json", "X-Integrity-Token": token},
            body: JSON.stringify(payload || {})
        });
        var body; try { body = await resp.json(); } catch (e) { throw new Error("Invalid server response."); }
        if (!resp.ok || !body.ok) throw new Error(body.error || "Request failed.");
        return body;
    }

    async function uploadFile(file) {
        var fd = new FormData(); fd.append("file", file, file.name);
        var resp = await fetch("/api/upload", {method:"POST", headers:{"X-Integrity-Token": token}, body: fd});
        var body; try { body = await resp.json(); } catch (e) { throw new Error("Invalid server response."); }
        if (!resp.ok || !body.ok) throw new Error(body.error || "Upload failed.");
        return body;
    }

    async function refreshStatus() {
        try { var r = await api("status", {}); storePath.textContent = r.store; renderBaselines(r); }
        catch (e) { storePath.textContent = "Unavailable"; }
    }

    btnCheck.addEventListener("click", async function () {
        if (busy || !selectedFile) return;
        setBusy(true); hideNotice();
        try {
            var r = await uploadFile(selectedFile);
            renderResult(r);
            var kind = "success";
            if (r.status === "modified") kind = r.possible_tampering ? "error" : "warning";
            setNotice(r.message || "Done.", kind);
            await refreshStatus();
        } catch (e) { setNotice(e.message, "error"); }
        finally { setBusy(false); }
    });

    async function runAction(action) {
        if (busy) return;
        var path = pathInput.value.trim();
        if (!path) { setNotice("Enter a file or directory path.", "error"); pathInput.focus(); return; }
        if (action === "reinit" && !window.confirm("Re-initialize the baseline for " + path + "? Existing hashes will be replaced.")) return;
        setBusy(true); hideNotice();
        try {
            var r = await api(action, {path: path});
            renderResult(r);
            var kind = "success";
            if (r.action === "check" && r.status === "modified") kind = r.possible_tampering ? "error" : "warning";
            else if (r.action === "check" && r.status === "error") kind = "error";
            setNotice(r.message || "Command completed.", kind);
            await refreshStatus();
        } catch (e) { setNotice(e.message, "error"); }
        finally { setBusy(false); }
    }

    pathActionBtns.forEach(function (b) {
        b.addEventListener("click", function () { runAction(b.getAttribute("data-action")); });
    });

    refreshStatus();
})();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    sys.exit(main())
