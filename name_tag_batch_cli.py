"""Offline Batch CLI. Simulation uses an isolated fixture Ledger and fake only.

``batch-live`` is only an *untrusted local client* of the protected Host service: it sends
the exact Plan/CSV/Owner envelope bytes over the Task 6 IPC v1 client (literal socket path)
once and records a bounded local summary of the reply. It holds no Host, Owner or AWS
authority and never verifies, executes, retries or reconnects by itself.
"""
from __future__ import annotations
import argparse,json,sys
import os
import secrets
import stat
from datetime import datetime,timezone
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
import name_tag_batch_ipc
from name_tag_batch_approval import prepare_batch_approval, BatchAuthRejected
from name_tag_batch_approval import BATCH_NAMESPACE, canonical_bytes
from name_tag_batch_approval import verify_batch_approval
from name_tag_batch_state import BatchValidationError
from name_tag_batch_state import _unique_object
from name_tag_batch_report import build_batch_dry_run, ReportBlocked
from name_tag_batch_report import make_authenticated_batch_report
from name_tag_batch_trust import load_current_protected_owner_trust
from name_tag_batch_fake import BatchOfflineRuntime,BatchRuntimeEvidence,FakeBatchSDKAdapter
from name_tag_batch_executor import simulate_on_fixture_ledger,validate_fixture_scope
from name_tag_batch_ledger import LedgerBlocked
from name_tag_batch_report import reconcile_batch_outcomes
from name_tag_scope import ScopeEvidence,SideEffectEvidence


def _resolve_cli_path(value):
    """Resolve a CLI path and reject targets outside the invocation directory."""
    root = Path.cwd().resolve()
    root_info=root.stat(follow_symlinks=False)
    if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid!=os.geteuid()
            or stat.S_IMODE(root_info.st_mode)&0o077):
        raise ValueError('Invocation directory must be private and owned by the current UID')
    candidate=Path(value)
    candidate=candidate if candidate.is_absolute() else root/candidate
    if candidate.is_symlink():
        raise ValueError(f'Path is outside allowed directory: {value}')
    path = candidate.resolve()
    try:
        path.relative_to(root)
    except ValueError as error:
        raise ValueError(f'Path is outside allowed directory: {value}') from error
    return path


def _write_new(path,bytes0):
    if path.exists() or path.is_symlink():raise ValueError('Refusing overwrite of existing output')
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|getattr(os,'O_CLOEXEC',0)
    fd=os.open(path,flags,0o600)
    try:
        with os.fdopen(fd,'wb') as stream:
            stream.write(bytes0)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _validate_simulation_outputs(report_out:Path,ledger_path:Path)->None:
    if report_out.exists() or report_out.is_symlink():
        raise ValueError('Simulation report output already exists')
    normalized_report=report_out.resolve(strict=False)
    normalized_ledger=ledger_path.resolve(strict=False)
    if normalized_report==normalized_ledger or normalized_report in normalized_ledger.parents:
        raise ValueError('Simulation report output aliases the fixture Ledger')


def _read_private(path):
    info=path.stat(follow_symlinks=False)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid()
            or stat.S_IMODE(info.st_mode)&0o077 or info.st_size>64*1024*1024):
        raise ValueError('Batch input must be a private, bounded regular file')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|getattr(os,'O_CLOEXEC',0))
    with os.fdopen(fd,'rb') as stream:
        opened=os.fstat(stream.fileno())
        if (opened.st_dev,opened.st_ino)!=(info.st_dev,info.st_ino):
            raise ValueError('Batch input changed before opening')
        data=stream.read(64*1024*1024+1)
    if len(data)>64*1024*1024:
        raise ValueError('Batch input exceeds size limit')
    return data


def _pretty(obj):return (json.dumps(obj,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode('utf-8')


def _mapping(value):
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise ValueError('Expected JSON object with string keys')
    return value


def _text(document,key):
    value=document.get(key)
    if type(value) is not str or not value:
        raise ValueError(f'Invalid runtime evidence field: {key}')
    return value


def _date(document,key):
    value=_text(document,key)
    try:
        result=datetime.fromisoformat(value.replace('Z','+00:00'))
    except ValueError as error:
        raise ValueError(f'Invalid runtime evidence timestamp: {key}') from error
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError(f'Invalid runtime evidence timestamp: {key}')
    return result


def _parse_scopes(scopes_value):
    if type(scopes_value) is not list or not scopes_value:
        raise ValueError('Invalid scope/side-effect evidence lists')
    scopes={}
    fields={'account','partition','region','writer_control_scope_id','controlled_arns',
            'not_before_utc','not_after_utc','writer_evidence_digest','responsible_owner'}
    for item in scopes_value:
        entry=_mapping(item)
        if set(entry)!=fields or type(entry['controlled_arns']) is not list:
            raise ValueError('Invalid runtime ScopeEvidence shape')
        scope_id=_text(entry,'writer_control_scope_id')
        if scope_id in scopes or any(type(arn) is not str or not arn for arn in entry['controlled_arns']):
            raise ValueError('Duplicate Scope ID or invalid controlled ARN')
        scopes[scope_id]=ScopeEvidence(
            account=_text(entry,'account'),partition=_text(entry,'partition'),
            region=_text(entry,'region'),writer_control_scope_id=scope_id,
            controlled_arns=frozenset(entry['controlled_arns']),
            not_before_utc=_date(entry,'not_before_utc'),not_after_utc=_date(entry,'not_after_utc'),
            writer_evidence_digest=_text(entry,'writer_evidence_digest'),
            responsible_owner=_text(entry,'responsible_owner'),
        )
    return scopes


def _parse_side_effects(effects_value,scopes):
    if type(effects_value) is not list:
        raise ValueError('Invalid scope/side-effect evidence lists')
    effects_by_scope={scope_id:[] for scope_id in scopes}
    fields={'scope_id','target_arn','iam_abac_resource_tag_assessment','iac_assessment',
            'event_automation_assessment','evidence_references','not_before_utc','not_after_utc'}
    for item in effects_value:
        entry=_mapping(item)
        if set(entry)!=fields or type(entry['evidence_references']) is not list:
            raise ValueError('Invalid SideEffectEvidence shape')
        scope_id=_text(entry,'scope_id')
        if scope_id not in effects_by_scope or any(type(ref) is not str for ref in entry['evidence_references']):
            raise ValueError('Unregistered runtime Scope evidence')
        effects_by_scope[scope_id].append(SideEffectEvidence(
            target_arn=_text(entry,'target_arn'),
            iam_abac_resource_tag_assessment=_text(entry,'iam_abac_resource_tag_assessment'),
            iac_assessment=_text(entry,'iac_assessment'),
            event_automation_assessment=_text(entry,'event_automation_assessment'),
            evidence_references=tuple(entry['evidence_references']),
            not_before_utc=_date(entry,'not_before_utc'),not_after_utc=_date(entry,'not_after_utc'),
        ))
    return effects_by_scope


def _parse_initial_tags(value):
    initial_value=_mapping(value)
    initial_tags={}
    for arn,tags_value in initial_value.items():
        tags=_mapping(tags_value)
        if any(type(key) is not str or type(tag) is not str for key,tag in tags.items()):
            raise ValueError('Fake tag map must contain string keys and values')
        initial_tags[arn]=tags
    return initial_tags


def parse_offline_runtime(raw:bytes)->BatchOfflineRuntime:
    """Parse explicit offline scope evidence and fake tags; never create SDK clients."""
    if type(raw) is not bytes or len(raw)>4*1024*1024:
        raise ValueError('Offline runtime evidence is missing or oversized')
    try:
        doc=_mapping(json.loads(raw.decode('utf-8'),object_pairs_hook=_unique_object))
    except (UnicodeDecodeError,json.JSONDecodeError,BatchValidationError) as error:
        raise ValueError('Invalid offline runtime evidence JSON') from error
    if set(doc)!={'scopes','side_effects','initial_tags','readback_failures'}:
        raise ValueError('Unexpected offline runtime evidence fields')
    scopes=_parse_scopes(doc['scopes'])
    effects_by_scope=_parse_side_effects(doc['side_effects'],scopes)
    evidence_by_scope={}
    for scope_id,scope in scopes.items():
        effects=tuple(effects_by_scope[scope_id])
        if ({effect.target_arn for effect in effects}!=set(scope.controlled_arns)
                or len(effects)!=len(scope.controlled_arns)):
            raise ValueError('Side-effect evidence must cover every controlled ARN once')
        evidence_by_scope[scope_id]=BatchRuntimeEvidence(scope,effects)
    initial_tags=_parse_initial_tags(doc['initial_tags'])
    failures=doc['readback_failures']
    if type(failures) is not list or any(type(arn) is not str or arn not in initial_tags for arn in failures):
        raise ValueError('Invalid fake readback failure targets')
    return BatchOfflineRuntime(
        MappingProxyType(evidence_by_scope),
        FakeBatchSDKAdapter(initial_tags,readback_failures=failures),
    )


def _build_parser():
    pa=argparse.ArgumentParser(prog='name_tag_batch_cli',description='Offline planning; batch-live is only an untrusted client of the protected Host service')
    subs=pa.add_subparsers(dest='command',required=True)
    for cmd in ('prepare-batch','batch-dryrun','verify-batch','batch-simulate'):
        p=subs.add_parser(cmd)
        p.add_argument('--plan',required=True);p.add_argument('--review',required=True)
        if cmd=='prepare-batch':
            for flag in ('--owner-id','--owner-fingerprint','--role-arn','--issued-at','--expires-at','--nonce','--payload-out','--manifest-out'):p.add_argument(flag,required=True)
        else:
            p.add_argument('--report-out',required=True)
            if cmd in ('verify-batch','batch-simulate'):p.add_argument('--envelope',required=True)
            if cmd=='batch-simulate':
                p.add_argument('--ledger-path',required=True)
                p.add_argument('--runtime-evidence',required=True)
    # No socket, Host runtime, grant, row/subset, policy or request-id option exists by design.
    live=subs.add_parser('batch-live',allow_abbrev=False)
    for flag in ('--plan','--review','--envelope','--report-out'):live.add_argument(flag,required=True)
    live.add_argument('--live-opt-in',action='store_true')
    return pa


def _resolve_arguments(args):
    args.plan = _resolve_cli_path(args.plan)
    args.review = _resolve_cli_path(args.review)
    if args.command == 'prepare-batch':
        args.payload_out = _resolve_cli_path(args.payload_out)
        args.manifest_out = _resolve_cli_path(args.manifest_out)
    else:
        args.report_out = _resolve_cli_path(args.report_out)
        if args.command in ('verify-batch','batch-simulate','batch-live'):
            args.envelope = _resolve_cli_path(args.envelope)
        if args.command=='batch-simulate':
            args.ledger_path=_resolve_cli_path(args.ledger_path)
            args.runtime_evidence=_resolve_cli_path(args.runtime_evidence)
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


_LIVE_EXIT={'COMPLETE':0,'BLOCKED':2,'UNKNOWN':3}
_LIVE_STATUS_MEANING={
    'COMPLETE':('The accepted command reached a verified durable Host report, not that every '
                'row was applied. Read the protected Host report for per-row outcomes.'),
    'BLOCKED':('The Host refused this command or could not continue it safely. Earlier rows '
               'of this Batch may already be durably APPLIED_VERIFIED; read the protected '
               'Host report. Do not resubmit automatically.'),
    'UNKNOWN':('The command outcome or its reply could not be established; Host writes may '
               'have happened. Do not resubmit; use the Owner-authenticated read-only report '
               'recovery.'),
}


def _local_live_shape_check(plan:bytes,review:bytes,envelope:bytes)->None:
    """Deny-only local pre-check. It is never authorization: the Host re-verifies everything."""
    try:
        doc=json.loads(envelope.decode('utf-8'),object_pairs_hook=_unique_object)
    except (UnicodeDecodeError,json.JSONDecodeError,BatchValidationError) as error:
        raise ValueError('Live envelope is not a Batch envelope JSON object') from error
    if (type(doc) is not dict or set(doc)!={'payload','batch_id','signature_ref'}
            or type(doc['payload']) is not dict):
        raise ValueError('Live envelope is not a Batch envelope JSON object')
    payload=doc['payload']
    if (payload.get('purpose')!=BATCH_NAMESPACE
            or payload.get('plan_sha256')!=sha256(plan).hexdigest()
            or payload.get('csv_sha256')!=sha256(review).hexdigest()
            or doc['batch_id']!=sha256(canonical_bytes(payload)).hexdigest()):
        raise ValueError('Live envelope does not bind these exact Plan/CSV bytes')


def _live_summary(response)->dict:
    """Bounded local summary of the six-field Host reply; never a Host report or grant."""
    return {
        'schema':'aws-cnt-batch-live-client-summary-v1',
        'summary_kind':'LOCAL_UNTRUSTED_HOST_REPLY_SUMMARY',
        'request_id':response.request_id,'status':response.status,'code':response.code,
        'batch_id':response.batch_id,'report_sha256':response.report_sha256,
        'status_meaning':_LIVE_STATUS_MEANING[response.status],
        'zero_writes_implied':False,'all_rows_applied_implied':False,
        'applied_verified_asserted':False,
        'authoritative_report':'HOST_PROTECTED_REPORT_ONLY','execution_allowed':False,
    }


def _batch_live(args):
    if args.live_opt_in is not True:
        raise ValueError('batch-live requires --live-opt-in (and the protected Host decides)')
    if args.report_out.exists() or args.report_out.is_symlink():
        raise ValueError('Refusing overwrite of existing output')
    plan=_read_private(args.plan)
    review=_read_private(args.review)
    envelope=_read_private(args.envelope)
    _local_live_shape_check(plan,review,envelope)
    client=name_tag_batch_ipc.UnixBatchHostClient()
    try:
        response=client.execute(plan_bytes=plan,csv_bytes=review,owner_envelope_bytes=envelope,
                                request_id=secrets.token_hex(16))
    except name_tag_batch_ipc.IPCError as error:  # local bounds: nothing was sent
        raise ValueError(f'Live inputs exceed IPC v1 bounds: {error.code}') from error
    summary=_live_summary(response)
    line=(f"batch-live: status={response.status} code={response.code} "
          f"batch_id={response.batch_id} report_sha256={response.report_sha256}")
    print(line)
    print(summary['status_meaning'])
    try:
        _write_new(args.report_out,_pretty(summary))
    except OSError as error:
        print(f'Local summary was NOT written ({error}); the Host reply above stands.',
              file=sys.stderr)
    return _LIVE_EXIT[response.status]


def _run_command(args):
    if args.command=='batch-live':
        return _batch_live(args)
    plan=_read_private(args.plan)
    review=_read_private(args.review)
    if args.command=='batch-dryrun':
        _write_new(args.report_out,_pretty(build_batch_dry_run(plan,review)))
    elif args.command=='prepare-batch':
        _prepare_batch(args,plan,review)
    elif args.command=='verify-batch':
        trust=load_current_protected_owner_trust()
        envelope=_read_private(args.envelope)
        now=datetime.now(timezone.utc)
        batch=verify_batch_approval(plan,review,envelope,trust=trust,now_utc=now)
        report=make_authenticated_batch_report(
            batch,plan_bytes=plan,csv_bytes=review,trust=trust,now_utc=now)
        _write_new(args.report_out,_pretty(report))
    elif args.command=='batch-simulate':
        trust=load_current_protected_owner_trust()
        now=datetime.now(timezone.utc)
        batch=verify_batch_approval(
            plan,review,_read_private(args.envelope),trust=trust,
            now_utc=now)
        runtime=parse_offline_runtime(_read_private(args.runtime_evidence))
        validate_fixture_scope(batch,runtime)
        _validate_simulation_outputs(args.report_out,args.ledger_path)
        result=simulate_on_fixture_ledger(
            batch.batch_id,batch.payload['batch_nonce'],batch.approved_rows,
            ledger_path=args.ledger_path,adapter=runtime.adapter,
            cap=json.loads(plan)['execution_limits']['max_send_attempts'])
        report=make_authenticated_batch_report(
            batch,plan_bytes=plan,csv_bytes=review,trust=trust,now_utc=now)
        report=reconcile_batch_outcomes(
            report,dict(zip(batch.approved_row_indexes,result['outcomes'],strict=True)))
        report['batch_state']=result['batch_state']
        report['stop_reason']=result['stop_reason']
        report['send_attempts_consumed']=result['send_attempts_consumed']
        report['max_send_attempts']=result['max_send_attempts']
        report['remaining_unattempted_cap']=result['remaining_unattempted_cap']
        report['writes_complete']=result['writes_complete']
        report['execution_allowed']=False
        report['execution_mode']='ISOLATED_FIXTURE_ONLY'
        _write_new(args.report_out,_pretty(report))
    return 0


def main(argv=None):
    args=_build_parser().parse_args(argv)
    try:
        return _run_command(_resolve_arguments(args))
    except (OSError,ValueError,BatchValidationError,ReportBlocked,BatchAuthRejected,LedgerBlocked) as e:
        print('BLOCKED (offline): '+str(e),file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
