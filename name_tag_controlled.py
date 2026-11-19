"""Offline CLI for preparing/verifying Owner envelopes while AWS writes stay held."""

# noqa: SIZE_OK — Task 7 requires all CLI handlers and shared protected-trust/private-output boundaries here.

# noqa: SIZE_OK — Task 7 requires all six CLI handlers and their shared secure I/O/trust boundary in one file.

# noqa: SIZE_OK — The CLI handlers share private I/O, trust-loading, and envelope-validation boundaries.

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Final, TypeAlias

from name_tag_approval import (
    ApprovalRejected,
    EnrolledOwner,
    Kind,
    NAMESPACES,
    OwnerTrust,
    VerifiedEnvelope,
    approval_digest,
    canonical_payload,
    verify_envelope,
)
from name_tag_execution import FakeNameTagAdapter, OfflineRuntimeContext, execute_once
from name_tag_ledger import IntentLedger
from name_tag_ledger_cli import initialize_ledger_cli
from name_tag_review import prepare_name_payload
from name_tag_scope import ScopeEvidence, SideEffectEvidence

TRUST_DIRECTORY: Final = Path("/etc/aws-cost-name-tagger")
TRUST_CONFIG_PATH: Final = TRUST_DIRECTORY / "owner-trust.json"
ALLOWED_SIGNERS_PATH: Final = TRUST_DIRECTORY / "allowed_signers"
EC2_CREATE_TAGS_OPERATION: Final = "ec2:CreateTags:2016-11-15"
JsonValue = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
MAX_CLI_INPUT_BYTES: Final = 64 * 1024 * 1024
CLIHandler: TypeAlias = Callable[[argparse.Namespace], int]


class ControlledCLIError(Exception):
    def __init__(self, code: str):
        self.code: str = code
        super().__init__(code)


def _pairs_no_duplicates(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            raise ControlledCLIError("BLOCKED_INPUT_INVALID")
        result[key] = value
    return result


def _read_private_input(path_text: str) -> bytes:
    path = Path(path_text)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    try:
        file_fd = os.open(path, flags)
    except OSError as exc:
        raise ControlledCLIError("BLOCKED_INPUT_INVALID") from exc
    try:
        info = os.fstat(file_fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
        ):
            raise ControlledCLIError("BLOCKED_INPUT_INVALID")
        data = bytearray()
        while True:
            chunk = os.read(file_fd, 64 * 1024)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > MAX_CLI_INPUT_BYTES:
                raise ControlledCLIError("BLOCKED_INPUT_INVALID")
        return bytes(data)
    finally:
        os.close(file_fd)


def _json_document(raw: bytes) -> JsonValue:
    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs_no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ControlledCLIError("BLOCKED_INPUT_INVALID") from exc


@contextmanager
def _private_directory_fd(path: Path) -> Generator[int, None, None]:
    if os.name != "posix" or not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise ControlledCLIError("BLOCKED_OUTPUT_UNSAFE")
    if ".." in path.parts:
        raise ControlledCLIError("BLOCKED_OUTPUT_UNSAFE")
    absolute = Path(os.path.abspath(path))
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    directory_fd = os.open("/", flags)
    try:
        for component in absolute.parts[1:]:
            try:
                next_fd = os.open(component, flags, dir_fd=directory_fd)
            except FileNotFoundError:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=directory_fd)
                except FileExistsError:
                    pass
                next_fd = os.open(component, flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        info = os.fstat(directory_fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ControlledCLIError("BLOCKED_OUTPUT_UNSAFE")
        yield directory_fd
    except OSError as exc:
        raise ControlledCLIError("BLOCKED_OUTPUT_UNSAFE") from exc
    finally:
        os.close(directory_fd)


def _write_private_new(path_text: str, data: bytes) -> None:
    path = Path(path_text)
    if not path.name or path.name in (".", ".."):
        raise ControlledCLIError("BLOCKED_OUTPUT_UNSAFE")
    with _private_directory_fd(path.parent) as directory_fd:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            file_fd = os.open(path.name, flags, 0o600, dir_fd=directory_fd)
        except FileExistsError as exc:
            raise ControlledCLIError("BLOCKED_OUTPUT_EXISTS") from exc
        try:
            if not stat.S_ISREG(os.fstat(file_fd).st_mode):
                raise ControlledCLIError("BLOCKED_OUTPUT_UNSAFE")
            pending = data
            while pending:
                written = os.write(file_fd, pending)
                if written <= 0:
                    raise OSError("short write")
                pending = pending[written:]
            os.fsync(file_fd)
            os.fsync(directory_fd)
        except OSError as exc:
            try:
                os.unlink(path.name, dir_fd=directory_fd)
            except OSError:
                pass
            raise ControlledCLIError("BLOCKED_OUTPUT_UNSAFE") from exc
        finally:
            os.close(file_fd)


def _argument(args: argparse.Namespace, name: str) -> str:
    value = getattr(args, name, None)
    if not isinstance(value, str) or not value:
        raise ControlledCLIError("BLOCKED_INPUT_INVALID")
    return value


def _string_list_argument(args: argparse.Namespace, name: str) -> list[str]:
    values = getattr(args, name, None)
    if not isinstance(values, list):
        raise ControlledCLIError("BLOCKED_INPUT_INVALID")
    result: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value:
            raise ControlledCLIError("BLOCKED_INPUT_INVALID")
        result.append(value)
    return result


def _optional_string_argument(args: argparse.Namespace, name: str) -> str:
    value = getattr(args, name, "")
    if not isinstance(value, str):
        raise ControlledCLIError("BLOCKED_INPUT_INVALID")
    return value


def _protected_file(path: Path, *, uid: int) -> bytes:
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
        raise ControlledCLIError("BLOCKED_OWNER_AUTHN")
    return path.read_bytes()


def _load_owner_trust() -> OwnerTrust | None:
    try:
        raw = _protected_file(TRUST_CONFIG_PATH, uid=0)
        config = _json_document(raw)
        if not isinstance(config, dict) or set(config) != {"schema_version", "allowed_signers_sha256", "owners"}:
            return None
        if type(config.get("schema_version")) is not int or config["schema_version"] != 1:
            return None
        pinned = config.get("allowed_signers_sha256")
        owner_rows = config.get("owners")
        if not isinstance(pinned, str) or re.fullmatch(r"[0-9a-f]{64}", pinned) is None:
            return None
        if not isinstance(owner_rows, dict):
            return None
        enrolled: dict[str, dict[str, EnrolledOwner]] = {}
        for owner_id, keys in owner_rows.items():
            if not isinstance(owner_id, str) or not isinstance(keys, dict):
                return None
            enrolled_keys: dict[str, EnrolledOwner] = {}
            for fingerprint, entry in keys.items():
                if not isinstance(fingerprint, str) or not isinstance(entry, dict):
                    return None
                role = entry.get("role")
                revoked = entry.get("revoked", False)
                if not isinstance(role, str) or type(revoked) is not bool:
                    return None
                enrolled_keys[fingerprint] = EnrolledOwner(fingerprint, role, revoked)
            enrolled[owner_id] = enrolled_keys
        return OwnerTrust.from_allowed_signers(
            ALLOWED_SIGNERS_PATH,
            pinned_sha256=pinned,
            enrolled=enrolled,
            expected_uid=0,
        )
    except (OSError, ControlledCLIError, ApprovalRejected):
        return None


def _verify_file(path_text: str, kind: Kind, trust: OwnerTrust) -> VerifiedEnvelope:
    raw = _read_private_input(path_text)
    try:
        return verify_envelope(raw, kind=kind, trust=trust, now_utc=datetime.now(timezone.utc))
    except ApprovalRejected as exc:
        raise ControlledCLIError("BLOCKED_OWNER_AUTHN") from exc


def _emit(code: str, detail: str | None = None, *, success: bool = False) -> int:
    print(code if detail is None else f"{code} {detail}")
    return 0 if success else 2


def prepare_name(args: argparse.Namespace) -> int:
    try:
        plan_bytes = _read_private_input(_argument(args, "plan"))
        document = _json_document(plan_bytes)
        if not isinstance(document, dict) or document.get("schema_version") != 2:
            raise ControlledCLIError("BLOCKED_INPUT_INVALID")
        account = document.get("account")
        records = document.get("records")
        proposal_id = _argument(args, "proposal_id")
        if not isinstance(account, str) or not isinstance(records, list):
            raise ControlledCLIError("BLOCKED_INPUT_INVALID")
        matches = [row for row in records if isinstance(row, dict) and row.get("proposal_id") == proposal_id]
        if len(matches) != 1:
            raise ControlledCLIError("BLOCKED_INPUT_INVALID")
        record: dict[str, JsonValue] = dict(matches[0])
        if "account" in record and record["account"] != account:
            raise ControlledCLIError("BLOCKED_INPUT_INVALID")
        evidence = record.get("evidence")
        if not isinstance(evidence, str):
            raise ControlledCLIError("BLOCKED_INPUT_INVALID")
        record["account"] = account
        record["plan_sha256"] = hashlib.sha256(plan_bytes).hexdigest()
        record["evidence_digest"] = hashlib.sha256(evidence.encode("utf-8")).hexdigest()
        payload = prepare_name_payload(
            plan_bytes,
            record,
            approved_name=_argument(args, "approved_name"),
            edit_reason=_optional_string_argument(args, "edit_reason"),
            owner_principal_id=_argument(args, "owner_principal_id"),
            owner_key_fingerprint=_argument(args, "owner_key_fingerprint"),
            issued_at_utc=_argument(args, "issued_at_utc"),
            expires_at_utc=_argument(args, "expires_at_utc"),
            decision_nonce=_argument(args, "decision_nonce"),
        )
        canonical = canonical_payload(payload, kind="name")
        _write_private_new(_argument(args, "output"), canonical)
    except (ControlledCLIError, ApprovalRejected, OSError, ValueError) as exc:
        code = exc.code if isinstance(exc, (ControlledCLIError, ApprovalRejected)) else "BLOCKED_INPUT_INVALID"
        return _emit(code)
    return _emit("PREPARED_NAME", approval_digest(canonical), success=True)


def verify_name(args: argparse.Namespace) -> int:
    trust = _load_owner_trust()
    if trust is None:
        return _emit("BLOCKED_OWNER_AUTHN")
    try:
        verified = _verify_file(_argument(args, "envelope"), "name", trust)
    except (ControlledCLIError, OSError) as exc:
        return _emit(exc.code if isinstance(exc, ControlledCLIError) else "BLOCKED_INPUT_INVALID")
    return _emit("VERIFIED_NAME", verified.content_id, success=True)


def prepare_execution(args: argparse.Namespace) -> int:
    trust = _load_owner_trust()
    if trust is None:
        return _emit("BLOCKED_OWNER_AUTHN")
    try:
        name = _verify_file(_argument(args, "name_envelope"), "name", trust)
        operation = _argument(args, "aws_operation")
        if operation != EC2_CREATE_TAGS_OPERATION:
            return _emit("WRITE_UNSUPPORTED")
        resource_arn = name.payload.get("resource_arn")
        approved_name = name.payload.get("approved_name")
        account = name.payload.get("account")
        partition = name.payload.get("partition")
        region = name.payload.get("region")
        if (
            not isinstance(resource_arn, str)
            or not resource_arn
            or not isinstance(approved_name, str)
            or not approved_name
            or not isinstance(account, str)
            or not account
            or not isinstance(partition, str)
            or not partition
            or not isinstance(region, str)
            or not region
        ):
            raise ControlledCLIError("BLOCKED_OWNER_AUTHN")
        payload = {
            "schema_version": 1,
            "authorization_namespace": NAMESPACES["execution"],
            "name_approval_id": name.content_id,
            "resource_arn": resource_arn,
            "approved_name": approved_name,
            "aws_operation": operation,
            "account": account,
            "partition": partition,
            "region": region,
            "identity": _argument(args, "identity"),
            "code_version": _argument(args, "code_version"),
            "code_hash": _argument(args, "code_hash"),
            "writer_control_scope_id": _argument(args, "scope_id"),
            "risk_acknowledgement": _argument(args, "risk_acknowledgement"),
            "writer_control_evidence_refs": _string_list_argument(args, "writer_evidence_ref"),
            "side_effect_evidence_refs": _string_list_argument(args, "side_effect_evidence_ref"),
            "owner_principal_id": _argument(args, "owner_principal_id"),
            "owner_key_fingerprint": _argument(args, "owner_key_fingerprint"),
            "allowed_role": _argument(args, "allowed_role"),
            "issued_at_utc": _argument(args, "issued_at_utc"),
            "expires_at_utc": _argument(args, "expires_at_utc"),
            "execution_nonce": _argument(args, "execution_nonce"),
        }
        canonical = canonical_payload(payload, kind="execution")
        _write_private_new(_argument(args, "output"), canonical)
    except (ControlledCLIError, ApprovalRejected, OSError, ValueError, KeyError) as exc:
        code = exc.code if isinstance(exc, (ControlledCLIError, ApprovalRejected)) else "BLOCKED_INPUT_INVALID"
        return _emit(code)
    return _emit("PREPARED_EXECUTION", approval_digest(canonical), success=True)


def verify_execution(args: argparse.Namespace) -> int:
    trust = _load_owner_trust()
    if trust is None:
        return _emit("BLOCKED_OWNER_AUTHN")
    try:
        verified = _verify_file(_argument(args, "envelope"), "execution", trust)
    except (ControlledCLIError, OSError) as exc:
        return _emit(exc.code if isinstance(exc, ControlledCLIError) else "BLOCKED_INPUT_INVALID")
    return _emit("VERIFIED_EXECUTION", verified.content_id, success=True)


def simulate(args: argparse.Namespace) -> int:
    harness = getattr(args, "_test_harness", None)
    if type(harness) is not OfflineSimulationHarness:
        return _emit("AWS_WRITE_BLOCKED")
    result = execute_once(
        harness.name_approval,
        harness.authorization,
        scope=harness.scope,
        side_effects=harness.side_effects,
        ledger=harness.ledger,
        adapter=harness.adapter,
        runtime=harness.runtime,
    )
    return _emit(result.code, success=result.code == "APPLIED_VERIFIED")


def execute_approved(args: argparse.Namespace) -> int:
    _ = args
    return _emit("AWS_WRITE_BLOCKED")


@dataclass(frozen=True, slots=True)
class OfflineSimulationHarness:
    name_approval: VerifiedEnvelope
    authorization: VerifiedEnvelope
    scope: ScopeEvidence
    side_effects: SideEffectEvidence
    ledger: IntentLedger
    adapter: FakeNameTagAdapter
    runtime: OfflineRuntimeContext


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare-name")
    prepare.add_argument("--plan", required=True)
    prepare.add_argument("--proposal-id", required=True)
    prepare.add_argument("--approved-name", required=True)
    prepare.add_argument("--edit-reason", default="")
    prepare.add_argument("--owner-principal-id", required=True)
    prepare.add_argument("--owner-key-fingerprint", required=True)
    prepare.add_argument("--issued-at-utc", required=True)
    prepare.add_argument("--expires-at-utc", required=True)
    prepare.add_argument("--decision-nonce", required=True)
    prepare.add_argument("--output", required=True)
    verify = subparsers.add_parser("verify-name")
    verify.add_argument("--envelope", required=True)

    execution = subparsers.add_parser("prepare-execution")
    execution.add_argument("--name-envelope", required=True)
    execution.add_argument("--aws-operation", required=True)
    execution.add_argument("--scope-id", required=True)
    execution.add_argument("--identity", required=True)
    execution.add_argument("--code-version", required=True)
    execution.add_argument("--code-hash", required=True)
    execution.add_argument("--risk-acknowledgement", required=True)
    execution.add_argument("--writer-evidence-ref", action="append", required=True)
    execution.add_argument("--side-effect-evidence-ref", action="append", required=True)
    execution.add_argument("--owner-principal-id", required=True)
    execution.add_argument("--owner-key-fingerprint", required=True)
    execution.add_argument("--allowed-role", required=True)
    execution.add_argument("--issued-at-utc", required=True)
    execution.add_argument("--expires-at-utc", required=True)
    execution.add_argument("--execution-nonce", required=True)
    execution.add_argument("--output", required=True)
    verify_execution_parser = subparsers.add_parser("verify-execution")
    verify_execution_parser.add_argument("--envelope", required=True)

    initialize_ledger_parser = subparsers.add_parser("initialize-ledger")
    initialize_ledger_parser.add_argument("--path", required=True, type=Path)
    initialize_ledger_parser.add_argument("--runtime-uid", required=True, type=int)

    subparsers.add_parser("simulate")
    subparsers.add_parser("execute-approved")
    return parser


def parse_cli(argv: list[str] | None = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


CLI_HANDLERS: Final[dict[str, CLIHandler]] = {
    "prepare-name": prepare_name,
    "verify-name": verify_name,
    "prepare-execution": prepare_execution,
    "verify-execution": verify_execution,
    "initialize-ledger": initialize_ledger_cli,
    "simulate": simulate,
    "execute-approved": execute_approved,
}


def main(argv: list[str] | None = None) -> int:
    batch_commands = {"prepare-batch", "batch-dryrun", "verify-batch", "batch-simulate"}
    selected_argv = list(sys.argv[1:] if argv is None else argv)
    if selected_argv and selected_argv[0] in batch_commands:
        from name_tag_batch_cli import main as batch_cli_main

        return batch_cli_main(selected_argv)
    args = parse_cli(argv)
    command = getattr(args, "command", None)
    if not isinstance(command, str):
        return _emit("BLOCKED_INPUT_INVALID")
    handler = CLI_HANDLERS.get(command)
    if handler is None:
        return _emit("BLOCKED_INPUT_INVALID")
    return handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
