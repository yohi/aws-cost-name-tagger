"""Offline-only Batch draft CLI. No AWS/STS/host Ledger access or live writes.

verify-batch and batch-simulate are deliberately fail-closed until trusted
OwnerTrust and full project-ledger adapters are integrated and tested.
"""
from __future__ import annotations
import argparse,json,sys
from pathlib import Path
from name_tag_batch_approval import prepare_batch_approval, BatchAuthRejected
from name_tag_batch_state import BatchValidationError
from name_tag_batch_report import build_batch_dry_run, ReportBlocked


def _resolve_cli_path(value):
    """Resolve a CLI path and reject targets outside the invocation directory."""
    root = Path.cwd().resolve()
    path = Path(value).resolve()
    try:
        path.relative_to(root)
    except ValueError as error:
        raise ValueError(f'Path is outside allowed directory: {value}') from error
    return path


def _write_new(path,bytes0):
    if path.exists():raise ValueError('Refusing overwrite of existing output')
    with path.open('xb') as f:f.write(bytes0)


def _pretty(obj):return (json.dumps(obj,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode('utf-8')


def _build_parser():
    pa=argparse.ArgumentParser(prog='name_tag_batch_cli',description='Offline planning only; AWS/STS/write operations not available')
    subs=pa.add_subparsers(dest='command',required=True)
    for cmd in ('prepare-batch','batch-dryrun','verify-batch','batch-simulate'):
        p=subs.add_parser(cmd)
        p.add_argument('--plan',required=True);p.add_argument('--review',required=True)
        if cmd=='prepare-batch':
            for flag in ('--owner-id','--owner-fingerprint','--role-arn','--issued-at','--expires-at','--nonce','--payload-out','--manifest-out'):p.add_argument(flag,required=True)
        else:
            p.add_argument('--report-out',required=True)
            if cmd in ('verify-batch','batch-simulate'):p.add_argument('--envelope',required=True)
    return pa


def _resolve_arguments(args):
    args.plan = _resolve_cli_path(args.plan)
    args.review = _resolve_cli_path(args.review)
    if args.command == 'prepare-batch':
        args.payload_out = _resolve_cli_path(args.payload_out)
        args.manifest_out = _resolve_cli_path(args.manifest_out)
    else:
        args.report_out = _resolve_cli_path(args.report_out)
    return args


def _prepare_batch(args,plan,review):
    result=prepare_batch_approval(plan,review,
        owner_principal_id=args.owner_id,owner_key_fingerprint=args.owner_fingerprint,
        authorized_role_arn=args.role_arn,issued_at_utc=args.issued_at,
        expires_at_utc=args.expires_at,batch_nonce=args.nonce)
    # Validate both paths before any output; this does not atomically publish both.
    if args.payload_out.exists() or args.manifest_out.exists() or args.payload_out==args.manifest_out:
        raise ValueError('Output already exists or aliases')
    _write_new(args.payload_out,result.canonical_payload_bytes)
    _write_new(args.manifest_out,_pretty(result.manifest))


def _run_command(args):
    if args.command in ('verify-batch','batch-simulate'):
        # Must not accept a caller-chosen trust source or an unsigned input.
        raise BatchAuthRejected('BLOCKED_OWNER_AUTHN: protected trust/ledger integration unavailable')
    plan=args.plan.read_bytes()
    review=args.review.read_bytes()
    if args.command=='batch-dryrun':
        _write_new(args.report_out,_pretty(build_batch_dry_run(plan,review)))
    elif args.command=='prepare-batch':
        _prepare_batch(args,plan,review)
    return 0


def main(argv=None):
    args=_build_parser().parse_args(argv)
    try:
        return _run_command(_resolve_arguments(args))
    except (OSError,ValueError,BatchValidationError,ReportBlocked,BatchAuthRejected) as e:
        print('BLOCKED (offline): '+str(e),file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
