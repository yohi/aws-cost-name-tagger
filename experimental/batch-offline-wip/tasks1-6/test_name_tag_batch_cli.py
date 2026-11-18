import unittest, tempfile, json, pathlib
from name_tag_batch_cli import main
from name_tag_batch_state import build_batch_review_projection

class CliTests(unittest.TestCase):
    def test_dryrun_writes_only_explicit_report(self):
        with tempfile.TemporaryDirectory() as d:
            d=pathlib.Path(d)
            row={'proposal_id':'p','kind':'volume','region':'ap-northeast-1','resource_arn':'arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-abc','locator':'vol-abc','aws_operation':'ec2:CreateTags','status':'proposed','confidence':'high','name_state':'ABSENT','name_key_present':False,'name_raw_value':None,'existing_name':'','proposed_name':'Name-1','effective_usage_cost_usd':'1','evidence':'from metadata'}
            p={'schema_version':3,'account':'123456789012','partition':'aws','count':1,'records':[row],'execution_limits':{'max_send_attempts':1},'scope_declarations':[{'writer_control_scope_id':'scope','account':'123456789012','partition':'aws','region':'ap-northeast-1','resource_arns':[row['resource_arn']]}], 'cur_population':{'schema_version':2,'accounting_complete':True,'cur_recognized':{'count':1,'cost_usd':'1'},'below_min_cost':{'count':0,'cost_usd':'0'},'above_min_cost':{'count':1,'cost_usd':'1'},'lookup_selected':{'count':1,'cost_usd':'1'},'max_resources_not_inspected':{'count':0,'cost_usd':'0'},'outside_requested_kinds':{'known':True,'billing_rows':0,'cost_usd':'0'},'unsupported_kind':{'known':True,'billing_rows':0,'cost_usd':'0'},'unattributable_cur':{'known':True,'billing_rows':0,'cost_usd':'0'}}}
            (d/'plan.json').write_text(json.dumps(p));(d/'review.csv').write_bytes(build_batch_review_projection((d/'plan.json').read_bytes()))
            self.assertEqual(main(['batch-dryrun','--plan',str(d/'plan.json'),'--review',str(d/'review.csv'),'--report-out',str(d/'out.json')]),0)
            data=json.loads((d/'out.json').read_text())
            self.assertEqual(data['authentication_state'],'UNSIGNED_PREVIEW')
            self.assertFalse(data['execution_allowed'])
            self.assertEqual(main(['verify-batch','--plan',str(d/'plan.json'),'--review',str(d/'review.csv'),'--envelope',str(d/'none'),'--report-out',str(d/'signed.json')]),2)
            self.assertFalse((d/'signed.json').exists())

if __name__=='__main__':unittest.main()
