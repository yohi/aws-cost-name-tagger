from __future__ import annotations

import os
import pwd
import sqlite3
import stat
import uuid
from contextlib import contextmanager
from collections.abc import Generator
from pathlib import Path

from name_tag_ledger_anchor import (
    ledger_anchor_path,
    read_ledger_anchor,
    validate_anchor_directory,
    write_ledger_anchor,
)
from name_tag_ledger_errors import LedgerError


def _require_root() -> None:
    if os.geteuid() != 0:
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")


def _validate_provision_path(path: Path, runtime_uid: int) -> None:
    parent = path.parent
    try:
        parent_info = parent.stat(follow_symlinks=False)
    except OSError as exc:
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from exc
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != runtime_uid
        or parent_info.st_mode & 0o022
        or parent_info.st_mode & 0o300 != 0o300
        or parent.is_symlink()
    ):
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
    try:
        _ = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from exc
    raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")


@contextmanager
def _runtime_identity(
    runtime_uid: int, runtime_gid: int
) -> Generator[None, None, None]:
    current_uid = os.geteuid()
    current_gid = os.getegid()
    if current_uid == runtime_uid:
        yield
        return
    if current_uid != 0:
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
    try:
        os.setegid(runtime_gid)
        os.seteuid(runtime_uid)
        yield
    finally:
        if os.geteuid() != 0:
            os.seteuid(0)
        os.setegid(current_gid)


def _validate_provisioned_pair(
    path: Path, runtime_uid: int, runtime_gid: int, host_binding: str
) -> None:
    from name_tag_ledger import open_ledger

    with _runtime_identity(runtime_uid, runtime_gid):
        _ = read_ledger_anchor(path, host_binding)
        ledger = open_ledger(path, trusted_host=True, trust=None)
        ledger.close()


def initialize_ledger(path: Path | str, *, runtime_uid: int) -> None:
    """Provision a new ledger/anchor pair; never adopt existing state."""
    _require_root()
    if type(runtime_uid) is not int or runtime_uid < 0:
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
    try:
        runtime_gid = pwd.getpwuid(runtime_uid).pw_gid
    except KeyError as exc:
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from exc
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    if candidate.is_symlink():
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
    try:
        requested_parent = Path(os.path.abspath(candidate.parent))
        resolved_parent = requested_parent.resolve(strict=True)
    except OSError as exc:
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from exc
    if resolved_parent != requested_parent or not candidate.name:
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
    canonical_path = resolved_parent / candidate.name
    try:
        _validate_provision_path(canonical_path, runtime_uid)
        validate_anchor_directory()
        from name_tag_ledger import create_ledger_database, ledger_host_binding

        host_binding = ledger_host_binding(canonical_path)
        anchor_path = ledger_anchor_path(canonical_path, host_binding)
        if os.path.lexists(anchor_path):
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        ledger_instance_id = uuid.uuid4().hex
        with _runtime_identity(runtime_uid, runtime_gid):
            validate_anchor_directory()
            create_ledger_database(
                canonical_path, host_binding, ledger_instance_id
            )
        _ = write_ledger_anchor(
            canonical_path, host_binding, ledger_instance_id, runtime_gid
        )
        _validate_provisioned_pair(
            canonical_path, runtime_uid, runtime_gid, host_binding
        )
    except LedgerError:
        raise
    except (OSError, sqlite3.Error, RuntimeError) as exc:
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from exc
