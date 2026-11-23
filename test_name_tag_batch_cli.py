import unittest, tempfile, json, pathlib, os, io, contextlib
import stat
from types import SimpleNamespace
from unittest.mock import patch
from name_tag_batch_cli import main, parse_offline_runtime, _write_new, _validate_simulation_outputs
from name_tag_batch_state import build_batch_review_projection
from name_tag_batch_executor import InMemoryNameAdapter,simulate_on_fixture_ledger
from name_tag_batch_ledger import LedgerBlocked

class CliTests(unittest.TestCase):
    def test_output_write_failure_removes_only_new_partial_file(self):
        with tempfile.TemporaryDirectory() as directory:
            output=pathlib.Path(directory)/'report.json'
            with patch('name_tag_batch_cli.os.fsync',side_effect=OSError('fsync failed')):
                with self.assertRaisesRegex(OSError,'fsync failed'):
                    _write_new(output,b'partial')
            self.assertFalse(output.exists())

    def test_simulation_output_preflight_rejects_collision_before_ledger_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            for name in ('plan.json','review.csv','envelope.json','runtime.json'):
                (root/name).write_text('{}')
                (root/name).chmod(0o600)
            (root/'report.json').write_text('existing')
            (root/'report.json').chmod(0o600)
            prior=pathlib.Path.cwd()
            os.chdir(root)
            try:
                with (
                    patch('name_tag_batch_cli.load_current_protected_owner_trust',return_value=object()),
                    patch('name_tag_batch_cli.verify_batch_approval',return_value=SimpleNamespace(
                        batch_id='b',payload={'batch_nonce':'n'},approved_rows=[])),
                    patch('name_tag_batch_cli.parse_offline_runtime',return_value=SimpleNamespace(adapter=object())),
                    patch('name_tag_batch_cli.validate_fixture_scope'),
                    patch('name_tag_batch_cli.simulate_on_fixture_ledger') as simulate,
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    self.assertEqual(main(['batch-simulate','--plan','plan.json','--review','review.csv',
                        '--envelope','envelope.json','--runtime-evidence','runtime.json',
                        '--ledger-path','fixture.db','--report-out','report.json']),2)
                simulate.assert_not_called()
            finally:
                os.chdir(prior)
            with self.assertRaises(ValueError):
                _validate_simulation_outputs(root/'fixture.db',root/'fixture.db')

    def test_simulation_output_preflight_rejects_ledger_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            path=pathlib.Path(directory)/'fixture.db'
            with self.assertRaises(ValueError):
                _validate_simulation_outputs(path,path)

    def test_simulation_output_preflight_rejects_missing_ledger_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger_parent=pathlib.Path(directory)/'new-ledger-parent'
            with self.assertRaises(ValueError):
                _validate_simulation_outputs(ledger_parent,ledger_parent/'fixture.db')

    def test_simulation_refuses_existing_host_ledger_path(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger_path = pathlib.Path(directory) / 'host-ledger.db'
            ledger_path.write_bytes(b'host ledger contents')
            before = ledger_path.read_bytes()

            with self.assertRaises(LedgerBlocked):
                simulate_on_fixture_ledger(
                    'batch-fixture', 'nonce-fixture', [],
                    ledger_path=ledger_path,
                    adapter=InMemoryNameAdapter({}), cap=1,
                )

            self.assertEqual(ledger_path.read_bytes(), before)

    def test_simulation_creates_only_a_new_isolated_fixture_ledger(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger_path=pathlib.Path(directory)/'fixture-ledger.db'
            adapter=InMemoryNameAdapter({'fixture-volume':{}})
            row={'resource_arn':'fixture-volume','writer_control_scope_id':'scope-1',
                 'name_state':'ABSENT','name_key_present':False,'name_raw_value':None,
                 'approved_name':'Name-1','proposed_name':'Name-1','approved':'YES',
                 'status':'proposed','confidence':'high','kind':'volume',
                 'aws_operation':'ec2:CreateTags','evidence':'fixture evidence'}

            result=simulate_on_fixture_ledger(
                'batch-fixture','nonce-fixture',[row],ledger_path=ledger_path,
                adapter=adapter,cap=1)

            self.assertTrue(ledger_path.is_file())
            self.assertEqual(result['authentication_state'],'SYNTHETIC_TEST_ONLY')
            self.assertEqual(result['outcomes'],['APPLIED_VERIFIED'])
            self.assertEqual(adapter.write_calls,1)

    def test_offline_runtime_document_builds_scope_bound_fake(self):
        document={
            'scopes':[{'account':'123456789012','partition':'aws','region':'us-east-1',
                'writer_control_scope_id':'scope-1','controlled_arns':['arn:aws:ec2:us-east-1:123456789012:volume/vol-0123456789abcdef0'],
                'not_before_utc':'2026-11-01T00:00:00Z','not_after_utc':'2026-12-01T00:00:00Z',
                'writer_evidence_digest':'c'*64,'responsible_owner':'batch-owner'}],
            'side_effects':[{'scope_id':'scope-1','target_arn':'arn:aws:ec2:us-east-1:123456789012:volume/vol-0123456789abcdef0',
                'iam_abac_resource_tag_assessment':'PASS','iac_assessment':'PASS','event_automation_assessment':'PASS',
                'evidence_references':['evidence://iam'],'not_before_utc':'2026-11-01T00:00:00Z',
                'not_after_utc':'2026-12-01T00:00:00Z'}],
            'initial_tags':{'arn:aws:ec2:us-east-1:123456789012:volume/vol-0123456789abcdef0':{}},
            'readback_failures':[],
        }

        runtime=parse_offline_runtime(json.dumps(document).encode())

        self.assertEqual(runtime.evidence_by_scope['scope-1'].scope.account,'123456789012')
        self.assertEqual(runtime.evidence_by_scope['scope-1'].side_effects[0].target_arn,
                         'arn:aws:ec2:us-east-1:123456789012:volume/vol-0123456789abcdef0')
        self.assertEqual(runtime.adapter.write_calls,0)

    def test_offline_runtime_rejects_unknown_top_level_fields(self):
        with self.assertRaises(ValueError):
            parse_offline_runtime(b'{"scopes":[],"side_effects":[],"initial_tags":{},"readback_failures":[],"ledger":"other"}')

    def test_rejects_input_path_outside_current_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            outside = root.parent / (root.name + '-secret.json')
            outside.write_text('{}')
            previous = pathlib.Path.cwd()
            os.chdir(root)
            try:
                errors = io.StringIO()
                with contextlib.redirect_stderr(errors):
                    result = main(['batch-dryrun', '--plan', str(outside), '--review', 'review.csv', '--report-out', 'report.json'])
                self.assertEqual(result, 2)
                self.assertIn('outside allowed directory', errors.getvalue())
                self.assertFalse((root / 'report.json').exists())
            finally:
                os.chdir(previous)
                outside.unlink()

    def test_rejects_output_path_outside_current_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            previous = pathlib.Path.cwd()
            os.chdir(root)
            try:
                errors = io.StringIO()
                with contextlib.redirect_stderr(errors):
                    result = main(['batch-dryrun', '--plan', 'plan.json', '--review', 'review.csv', '--report-out', '../report.json'])
                self.assertEqual(result, 2)
                self.assertIn('outside allowed directory', errors.getvalue())
                self.assertFalse((root.parent / 'report.json').exists())
            finally:
                os.chdir(previous)
    def test_rejects_symlink_target_outside_current_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            outside = root.parent / (root.name + '-target')
            outside.write_text('{}')
            (root / 'plan.json').symlink_to(outside)
            previous = pathlib.Path.cwd()
            os.chdir(root)
            try:
                errors = io.StringIO()
                with contextlib.redirect_stderr(errors):
                    result = main(['batch-dryrun', '--plan', 'plan.json', '--review', 'review.csv', '--report-out', 'report.json'])
                self.assertEqual(result, 2)
                self.assertIn('outside allowed directory', errors.getvalue())
            finally:
                os.chdir(previous)
                outside.unlink()

    def test_rejects_prepare_payload_path_outside_current_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            previous = pathlib.Path.cwd()
            os.chdir(root)
            try:
                errors = io.StringIO()
                with contextlib.redirect_stderr(errors):
                    result = main(['prepare-batch', '--plan', 'plan.json', '--review', 'review.csv', '--owner-id', 'owner', '--owner-fingerprint', 'fingerprint', '--role-arn', 'role', '--issued-at', 'start', '--expires-at', 'end', '--nonce', 'nonce', '--payload-out', '../payload.json', '--manifest-out', 'manifest.json'])
                self.assertEqual(result, 2)
                self.assertIn('outside allowed directory', errors.getvalue())
            finally:
                os.chdir(previous)

    def test_rejects_prepare_manifest_path_outside_current_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            previous = pathlib.Path.cwd()
            os.chdir(root)
            try:
                errors = io.StringIO()
                with contextlib.redirect_stderr(errors):
                    result = main(['prepare-batch', '--plan', 'plan.json', '--review', 'review.csv', '--owner-id', 'owner', '--owner-fingerprint', 'fingerprint', '--role-arn', 'role', '--issued-at', 'start', '--expires-at', 'end', '--nonce', 'nonce', '--payload-out', 'payload.json', '--manifest-out', '../manifest.json'])
                self.assertEqual(result, 2)
                self.assertIn('outside allowed directory', errors.getvalue())
            finally:
                os.chdir(previous)

    def test_dryrun_writes_only_explicit_report(self):
        with tempfile.TemporaryDirectory() as d:
            d=pathlib.Path(d)
            row={'proposal_id':'p','kind':'volume','region':'ap-northeast-1','resource_arn':'arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-abcdef12345678901','locator':'vol-abcdef12345678901','aws_operation':'ec2:CreateTags','status':'proposed','confidence':'high','name_state':'ABSENT','name_key_present':False,'name_raw_value':None,'existing_name':'','proposed_name':'Name-1','effective_usage_cost_usd':'1','evidence':'from metadata'}
            p={'schema_version':3,'account':'123456789012','partition':'aws','count':1,'records':[row],'execution_limits':{'max_send_attempts':1},'scope_declarations':[{'writer_control_scope_id':'scope','account':'123456789012','partition':'aws','region':'ap-northeast-1','resource_arns':[row['resource_arn']]}], 'cur_population':{'schema_version':2,'accounting_complete':True,'cur_recognized':{'count':1,'cost_usd':'1'},'below_min_cost':{'count':0,'cost_usd':'0'},'above_min_cost':{'count':1,'cost_usd':'1'},'lookup_selected':{'count':1,'cost_usd':'1'},'max_resources_not_inspected':{'count':0,'cost_usd':'0'},'outside_requested_kinds':{'known':True,'billing_rows':0,'cost_usd':'0'},'unsupported_kind':{'known':True,'billing_rows':0,'cost_usd':'0'},'unattributable_cur':{'known':True,'billing_rows':0,'cost_usd':'0'}}}
            (d/'plan.json').write_text(json.dumps(p));(d/'plan.json').chmod(0o600)
            (d/'review.csv').write_bytes(build_batch_review_projection((d/'plan.json').read_bytes()))
            (d/'review.csv').chmod(0o600)
            previous = pathlib.Path.cwd()
            os.chdir(d)
            try:
                self.assertEqual(main(['batch-dryrun','--plan','plan.json','--review','review.csv','--report-out','out.json']),0)
                data=json.loads((d/'out.json').read_text())
                self.assertEqual(data['authentication_state'],'UNSIGNED_PREVIEW')
                self.assertFalse(data['execution_allowed'])
                self.assertEqual(stat.S_IMODE((d/'out.json').stat().st_mode),0o600)
                self.assertEqual(main(['verify-batch','--plan','plan.json','--review','review.csv','--envelope','none','--report-out','signed.json']),2)
                self.assertFalse((d/'signed.json').exists())
            finally:
                os.chdir(previous)

    def test_offline_commands_never_build_the_live_ipc_client(self):
        with tempfile.TemporaryDirectory() as d:
            d=pathlib.Path(d)
            for name in ('plan.json','review.csv','envelope.json'):
                (d/name).write_text('{}');(d/name).chmod(0o600)
            previous=pathlib.Path.cwd()
            os.chdir(d)
            try:
                with patch('name_tag_batch_ipc.UnixBatchHostClient',
                           side_effect=AssertionError('offline command reached IPC')), \
                        contextlib.redirect_stderr(io.StringIO()), \
                        contextlib.redirect_stdout(io.StringIO()):
                    for argv in (['batch-dryrun','--plan','plan.json','--review','review.csv','--report-out','a.json'],
                                 ['verify-batch','--plan','plan.json','--review','review.csv','--envelope','envelope.json','--report-out','b.json'],
                                 ['batch-live','--plan','plan.json','--review','review.csv','--envelope','envelope.json','--report-out','c.json']):
                        self.assertEqual(main(argv),2)  # batch-live without --live-opt-in
                self.assertEqual(sorted(p.name for p in d.iterdir()),['envelope.json','plan.json','review.csv'])
            finally:
                os.chdir(previous)

if __name__=='__main__':unittest.main()
