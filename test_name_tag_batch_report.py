import unittest,json, tempfile
from types import MappingProxyType
from name_tag_batch_state import build_batch_review_projection
from name_tag_batch_report import build_batch_dry_run,make_authenticated_batch_report, ReportBlocked
from name_tag_batch_approval import VerifiedBatchApproval

class ReportTests(unittest.TestCase):
    def setUp(self):
        row={'proposal_id':'p','kind':'volume','region':'ap-northeast-1','resource_arn':'arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-abcdef1234567890','locator':'vol-abcdef1234567890','aws_operation':'ec2:CreateTags','status':'proposed','confidence':'high','name_state':'ABSENT','name_key_present':False,'name_raw_value':None,'existing_name':'','proposed_name':'Name-1','effective_usage_cost_usd':'1','evidence':'from metadata'}
        p={'schema_version':3,'account':'123456789012','partition':'aws','count':1,'records':[row],'execution_limits':{'max_send_attempts':1},'scope_declarations':[{'writer_control_scope_id':'scope','account':'123456789012','partition':'aws','region':'ap-northeast-1','resource_arns':[row['resource_arn']]}], 'cur_population':{'schema_version':2,'accounting_complete':True,'cur_recognized':{'count':1,'cost_usd':'1'},'below_min_cost':{'count':0,'cost_usd':'0'},'above_min_cost':{'count':1,'cost_usd':'1'},'lookup_selected':{'count':1,'cost_usd':'1'},'max_resources_not_inspected':{'count':0,'cost_usd':'0'},'outside_requested_kinds':{'known':True,'billing_rows':0,'cost_usd':'0'},'unsupported_kind':{'known':True,'billing_rows':0,'cost_usd':'0'},'unattributable_cur':{'known':True,'billing_rows':0,'cost_usd':'0'}}}
        self.pb=json.dumps(p).encode();self.cb=build_batch_review_projection(self.pb)
    def test_dryrun_is_unsigned_and_no_sdk_or_ledger(self):
        out=build_batch_dry_run(self.pb,self.cb)
        self.assertEqual(out['authentication_state'],'UNSIGNED_PREVIEW')
        self.assertFalse(out['execution_allowed'])
        self.assertTrue(out['coverage_complete'])
        self.assertFalse(out['writes_complete'])
        self.assertEqual(out['rows'][0]['resource_arn'],
                         'arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-abcdef1234567890')
        self.assertEqual(out['rows'][0]['proposed_name'],'Name-1')
        self.assertEqual(out['rows'][0]['outcome'],'NOT_ATTEMPTED_UNSIGNED_PREVIEW')
        self.assertFalse(out['rows'][0]['execution_allowed'])
    def test_signed_report_refuses_foreign_bytes(self):
        import hashlib
        b=VerifiedBatchApproval(b'fixture',b'p','a'*64,MappingProxyType({'plan_sha256':hashlib.sha256(self.pb).hexdigest(),'csv_sha256':hashlib.sha256(self.cb).hexdigest()}),self.pb,self.cb,(),(), 'owner','sig')
        with self.assertRaises(ReportBlocked):make_authenticated_batch_report(b,plan_bytes=self.pb+b' ',csv_bytes=self.cb)
        with self.assertRaises(ReportBlocked):make_authenticated_batch_report(b,plan_bytes=self.pb,csv_bytes=self.cb) # missing fresh protected trust

    def test_preview_extracts_rows_without_generatable_names(self):
        plan=json.loads(self.pb)
        unresolved=dict(plan['records'][0],proposal_id='unresolved',status='manual_review',
                        confidence='none',name_state='UNKNOWN',name_key_present=None,
                        name_raw_value=None,existing_name='',proposed_name='',
                        locator='vol-0123456789abcdef0',
                        resource_arn='arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-0123456789abcdef0',
                        effective_usage_cost_usd='1',evidence='insufficient lineage')
        plan['records'].append(unresolved)
        plan['count']=2
        population=plan['cur_population']
        population['cur_recognized']={'count':2,'cost_usd':'2'}
        population['above_min_cost']={'count':2,'cost_usd':'2'}
        population['lookup_selected']={'count':2,'cost_usd':'2'}
        population['below_min_cost']={'count':0,'cost_usd':'0'}
        plan_bytes=json.dumps(plan).encode()
        csv_bytes=build_batch_review_projection(plan_bytes)

        result=build_batch_dry_run(plan_bytes,csv_bytes)

        self.assertEqual(result['name_generation_unavailable'],[
            {'proposal_id':'unresolved','kind':'volume','locator':'vol-0123456789abcdef0',
             'resource_arn':'arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-0123456789abcdef0',
             'effective_usage_cost_usd':'1','reason':'insufficient lineage'}])

if __name__=='__main__':unittest.main()
