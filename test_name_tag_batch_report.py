import unittest,json, tempfile
from types import MappingProxyType
from name_tag_batch_state import build_batch_review_projection
from name_tag_batch_report import build_batch_dry_run,make_authenticated_batch_report, ReportBlocked
from name_tag_batch_report import reconcile_batch_outcomes
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
        self.assertEqual(out['rows'][0]['outcome'],'UNAPPROVED')
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

        self.assertEqual(result['name_generation_unavailable'],[])
        self.assertEqual(result['rows'][1]['name_generation_state'],'NOT_EVALUATED')

    def test_s3_plan_reports_write_and_scope_limits_separately(self):
        plan=json.loads(self.pb)
        row=dict(plan['records'][0],kind='s3_bucket',locator='example-bucket',
                 region='global',resource_arn='arn:aws:s3:::example-bucket',
                 aws_operation=None)
        plan['records']=[row]
        plan['scope_declarations']=[]
        plan['count']=1
        plan['cur_population']['cur_recognized']={'count':1,'cost_usd':'1'}
        plan['cur_population']['above_min_cost']={'count':1,'cost_usd':'1'}
        plan['cur_population']['lookup_selected']={'count':1,'cost_usd':'1'}
        plan['cur_population']['below_min_cost']={'count':0,'cost_usd':'0'}
        plan['cur_population']['max_resources_not_inspected']={'count':0,'cost_usd':'0'}
        plan_bytes=json.dumps(plan).encode()
        csv_bytes=build_batch_review_projection(plan_bytes)

        result=build_batch_dry_run(plan_bytes,csv_bytes)

        self.assertEqual(result['rows'][0]['write_support'],'UNSUPPORTED_API')
        self.assertEqual(result['rows'][0]['scope_application'],'NOT_APPLIED')
        self.assertEqual(result['name_generation_unavailable'],[])

    def test_signed_row_and_ledger_outcomes_reconcile_disjoint_exact_costs(self):
        plan=json.loads(self.pb)
        original=plan['records'][0]
        outcomes=('NOT_ATTEMPTED_CAP','NOT_ATTEMPTED_BATCH_STOP',
                  'SKIPPED_NAME_CHANGED','APPLIED_VERIFIED','OUTCOME_UNKNOWN')
        records=[]
        scopes=[]
        approved_cells=[]
        for index,outcome in enumerate(outcomes):
            arn=f'arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-{index:017x}'
            row=dict(original,proposal_id=f'p{index}',locator=f'vol-{index:017x}',
                     resource_arn=arn,effective_usage_cost_usd=str(index+1))
            records.append(row)
            approved_cells.append(f'p{index}')
            scopes.append({'writer_control_scope_id':f'scope-{index}',
                           'account':'123456789012','partition':'aws',
                           'region':'ap-northeast-1','resource_arns':[arn]})

        unapproved=dict(original,proposal_id='p5',locator='vol-00000000000000005',
                        resource_arn='arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-00000000000000005',
                        effective_usage_cost_usd='6')
        unsupported=dict(original,proposal_id='p6',kind='s3_bucket',locator='bucket-6',
                         region='global',resource_arn='arn:aws:s3:::bucket-6',
                         aws_operation=None,effective_usage_cost_usd='7')
        no_name=dict(original,proposal_id='p7',locator='vol-7',
                     resource_arn='arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-7',
                     status='manual_review',confidence='none',proposed_name='',
                     name_state='ABSENT',name_key_present=False,name_raw_value=None,
                     evidence='Candidate lacks a structured Name namespace',
                     effective_usage_cost_usd='8')
        no_scope=dict(original,proposal_id='p8',locator='vol-00000000000000008',
                      resource_arn='arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-00000000000000008',
                      effective_usage_cost_usd='9')
        records.extend((unapproved,unsupported,no_name,no_scope))
        plan['records']=records
        plan['count']=len(records)
        plan['scope_declarations']=scopes+[{
            'writer_control_scope_id':'scope-5','account':'123456789012',
            'partition':'aws','region':'ap-northeast-1',
            'resource_arns':[unapproved['resource_arn']],
        }]
        population=plan['cur_population']
        for field in ('cur_recognized','above_min_cost','lookup_selected'):
            population[field]={'count':9,'cost_usd':'45'}
        population['below_min_cost']={'count':0,'cost_usd':'0'}
        population['max_resources_not_inspected']={'count':0,'cost_usd':'0'}
        plan_bytes=json.dumps(plan).encode()
        review=build_batch_review_projection(plan_bytes)
        for proposal_id in approved_cells:
            review=review.replace(f'\r\n,{proposal_id},'.encode(),f'\r\nYES,{proposal_id},'.encode())
        draft_report=build_batch_dry_run(plan_bytes,review)

        report=reconcile_batch_outcomes(
            draft_report,{index:outcome for index,outcome in enumerate(outcomes)})

        self.assertEqual(report['outcome_reconciliation'],{
            'NOT_ATTEMPTED_CAP':{'count':1,'cost_usd':'1'},
            'NOT_ATTEMPTED_BATCH_STOP':{'count':1,'cost_usd':'2'},
            'SKIPPED_NAME_CHANGED':{'count':1,'cost_usd':'3'},
            'APPLIED_VERIFIED':{'count':1,'cost_usd':'4'},
            'OUTCOME_UNKNOWN':{'count':1,'cost_usd':'5'},
            'UNAPPROVED':{'count':1,'cost_usd':'6'},
            'WRITE_UNSUPPORTED':{'count':1,'cost_usd':'7'},
            'NAME_GENERATION_UNAVAILABLE':{'count':1,'cost_usd':'8'},
            'SCOPE_NOT_APPLIED':{'count':1,'cost_usd':'9'},
        })
        self.assertEqual(report['outcome_reconciliation_total'],
                         {'count':9,'cost_usd':'45'})

if __name__=='__main__':unittest.main()
