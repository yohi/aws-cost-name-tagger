from __future__ import annotations

import argparse
from pathlib import Path

from name_tag_ledger_errors import LedgerError
from name_tag_ledger_provision import initialize_ledger


def _emit(code: str, *, success: bool = False) -> int:
    print(code)
    return 0 if success else 2


def initialize_ledger_cli(args: argparse.Namespace) -> int:
    path = getattr(args, "path", None)
    runtime_uid = getattr(args, "runtime_uid", None)
    if not isinstance(path, Path) or type(runtime_uid) is not int:
        return _emit("BLOCKED_INPUT_INVALID")
    try:
        initialize_ledger(path, runtime_uid=runtime_uid)
    except LedgerError as exc:
        return _emit(exc.code)
    except (OSError, ValueError):
        return _emit("BLOCKED_SCOPE_STATE_UNKNOWN")
    return _emit("LEDGER_INITIALIZED", success=True)
