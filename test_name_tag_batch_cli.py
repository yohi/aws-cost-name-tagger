import unittest, tempfile, json, pathlib, os, io, contextlib
import stat
from name_tag_batch_cli import main, parse_offline_runtime
from name_tag_batch_state import build_batch_review_projection

class CliTests(unittest.TestCase):
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
            row={'proposal_id':'p','kind':'volume','region':'ap-northeast-1','resource_arn':'arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-abcdef1234567890','locator':'vol-abcdef1234567890','aws_operation':'ec2:CreateTags','status':'proposed','confidence':'high','name_state':'ABSENT','name_key_present':False,'name_raw_value':None,'existing_name':'','proposed_name':'Name-1','effective_usage_cost_usd':'1','evidence':'from metadata'}
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

if __name__=='__main__':unittest.main()
