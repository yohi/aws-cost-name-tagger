from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Final, TypeAlias

from name_tag_ledger_errors import LedgerError

JsonPrimitive: TypeAlias = str | int | float | bool | None


@dataclass(frozen=True, slots=True)
class _AnchorDocument:
    schema_version: int
    ledger_path: str
    host_binding: str
    ledger_instance_id: str
    ledger_device: int
    ledger_inode: int


@dataclass(frozen=True, slots=True)
class LedgerAnchorIdentity:
    ledger_instance_id: str
    ledger_device: int
    ledger_inode: int


JsonHookValue: TypeAlias = JsonPrimitive | list["JsonHookValue"] | _AnchorDocument

LEDGER_ANCHOR_DIRECTORY: Final[Path] = Path(
    "/etc/aws-cost-name-tagger/ledger-anchors"
)
_ANCHOR_OWNER_UID: Final[int] = 0
_ANCHOR_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "ledger_path",
        "host_binding",
        "ledger_instance_id",
        "ledger_device",
        "ledger_inode",
    }
)


def ledger_anchor_path(path: Path, host_binding: str) -> Path:
    canonical_path = path.resolve(strict=False)
    if not host_binding.endswith(f":{canonical_path}"):
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
    digest = hashlib.sha256(host_binding.encode("utf-8")).hexdigest()
    return LEDGER_ANCHOR_DIRECTORY / f"{digest}.json"


def validate_anchor_directory() -> None:
    for directory in (LEDGER_ANCHOR_DIRECTORY.parent, LEDGER_ANCHOR_DIRECTORY):
        try:
            info = directory.stat(follow_symlinks=False)
        except OSError as exc:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from exc
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != _ANCHOR_OWNER_UID
            or info.st_mode & 0o022
            or not os.access(directory, os.R_OK | os.X_OK, effective_ids=True)
        ):
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")


def _validate_anchor_file(path: Path) -> None:
    try:
        info = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != _ANCHOR_OWNER_UID
        or info.st_mode & 0o022
        or not os.access(path, os.R_OK, effective_ids=True)
    ):
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")


def require_root() -> None:
    if os.geteuid() != _ANCHOR_OWNER_UID:
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")


def _unique_json_object(
    pairs: list[tuple[str, JsonHookValue]],
) -> _AnchorDocument:
    values: dict[str, JsonHookValue] = {}
    for key, value in pairs:
        if key in values:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        values[key] = value
    if frozenset(values) != _ANCHOR_FIELDS:
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
    schema_version = values["schema_version"]
    ledger_path = values["ledger_path"]
    host_binding = values["host_binding"]
    instance_id = values["ledger_instance_id"]
    device = values["ledger_device"]
    inode = values["ledger_inode"]
    if (
        type(schema_version) is not int
        or not isinstance(ledger_path, str)
        or not isinstance(host_binding, str)
        or not isinstance(instance_id, str)
        or type(device) is not int
        or device < 0
        or type(inode) is not int
        or inode < 0
    ):
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
    return _AnchorDocument(
        schema_version, ledger_path, host_binding, instance_id, device, inode
    )


def _parse_anchor(
    raw: bytes, path: Path, host_binding: str
) -> LedgerAnchorIdentity:
    decoded_documents: list[_AnchorDocument] = []

    def parse_object(pairs: list[tuple[str, JsonHookValue]]) -> _AnchorDocument:
        document = _unique_json_object(pairs)
        decoded_documents.append(document)
        return document

    try:
        json_text = raw.decode("utf-8")
        if not json_text.lstrip().startswith("{"):
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        _ = json.loads(json_text, object_pairs_hook=parse_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from exc
    if len(decoded_documents) != 1:
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
    decoded = decoded_documents[0]
    if (
        decoded.schema_version != 1
        or decoded.ledger_path != str(path.resolve(strict=False))
        or decoded.host_binding != host_binding
        or re.fullmatch(r"[0-9a-f]{32}", decoded.ledger_instance_id) is None
    ):
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
    return LedgerAnchorIdentity(
        decoded.ledger_instance_id, decoded.ledger_device, decoded.ledger_inode
    )


def read_ledger_anchor(path: Path, host_binding: str) -> LedgerAnchorIdentity:
    anchor_path = ledger_anchor_path(path, host_binding)
    validate_anchor_directory()
    _validate_anchor_file(anchor_path)
    try:
        raw = anchor_path.read_bytes()
    except OSError as exc:
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from exc
    return _parse_anchor(raw, path, host_binding)


def write_ledger_anchor(
    path: Path, host_binding: str, ledger_instance_id: str, runtime_gid: int
) -> Path:
    require_root()
    if (
        type(runtime_gid) is not int
        or runtime_gid < 0
        or re.fullmatch(r"[0-9a-f]{32}", ledger_instance_id) is None
    ):
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
    anchor_path = ledger_anchor_path(path, host_binding)
    validate_anchor_directory()
    try:
        ledger_info = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from exc
    if not stat.S_ISREG(ledger_info.st_mode) or ledger_info.st_mode & 0o077:
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
    document = {
        "schema_version": 1,
        "ledger_path": str(path.resolve(strict=False)),
        "host_binding": host_binding,
        "ledger_instance_id": ledger_instance_id,
        "ledger_device": ledger_info.st_dev,
        "ledger_inode": ledger_info.st_ino,
    }
    payload = json.dumps(document, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    directory_fd = os.open(
        str(LEDGER_ANCHOR_DIRECTORY),
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        fd = os.open(
            anchor_path.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o640,
            dir_fd=directory_fd,
        )
        os.fchown(fd, _ANCHOR_OWNER_UID, runtime_gid)
        os.fchmod(fd, 0o640)
        with os.fdopen(fd, "wb") as stream:
            _ = stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(directory_fd)
    except OSError as exc:
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from exc
    finally:
        os.close(directory_fd)
    return anchor_path
