from test_helpers import sample_population
import unittest, json, csv, io
from name_tag_batch_state import (
    classify_batch_name,batch_name_state,build_batch_review_projection,
    validate_batch_csv,validate_batch_draft,BatchValidationError,
)

class StateTests(unittest.TestCase):
    def test_exact_name_observations(self):
        for tags, expected, raw in [({},'ABSENT',None),({'Name':''},'EMPTY',''),({'Name':' \u3000\t'},'WHITESPACE_ONLY',' \u3000\t'),({'Name':'X'},'NONEMPTY','X'),({'name':'X'},'UNKNOWN',None),({'Name':None},'UNKNOWN',None)]:
            obs=classify_batch_name(tags)
            self.assertEqual(obs.state,expected)
            self.assertEqual(obs.name_raw_value,raw)
        self.assertEqual(batch_name_state({'Name':'\t'}),'WHITESPACE_ONLY')
    def test_csv_exact_and_approved_eligibility(self):
        plan={
            'schema_version':3,'account':'123456789012','partition':'aws',
            'execution_limits':{'max_send_attempts':2},
            'cur_population':sample_population(cost='1.2'),
            'scope_declarations':[{'writer_control_scope_id':'fixed-scope','account':'123456789012','partition':'aws','region':'ap-northeast-1','resource_arns':['arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-a']}],
            'records':[{'proposal_id':'proposal-1','kind':'volume','locator':'vol-a','region':'ap-northeast-1','resource_arn':'arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-a','status':'proposed','confidence':'high','name_state':'WHITESPACE_ONLY','name_key_present':True,'name_raw_value':' \t','existing_name':' \t','proposed_name':'Meaningful-Name','effective_usage_cost_usd':'1.2','evidence':'metadata evidence','aws_operation':'ec2:CreateTags'}],
            'count':1
        }
        pb=json.dumps(plan,ensure_ascii=False).encode()
        unsigned=build_batch_review_projection(pb)
        self.assertTrue(unsigned.startswith(b'\xef\xbb\xbf'))
        original=validate_batch_csv(pb,unsigned)
        self.assertEqual(original[0]['approved'],'')
        changed=unsigned.replace(b',proposal-1,',b',proposal-1,')
        text=changed.decode('utf-8-sig').replace(',proposal-1,', 'YES,proposal-1,')
        approved=b'\xef\xbb\xbf'+text.encode()
        draft=validate_batch_draft(pb,approved)
        self.assertEqual(len(draft.approved_rows),1)
        self.assertEqual(draft.approved_rows[0]['writer_control_scope_id'],'fixed-scope')
        altered_name=approved.replace(b'Meaningful-Name',b'Changed-Name')
        with self.assertRaises(BatchValidationError):validate_batch_draft(pb,altered_name)
        invalid_approval=approved.replace(b'YES,proposal-1',b'Y,proposal-1')
        with self.assertRaises(BatchValidationError):validate_batch_draft(pb,invalid_approval)

    def test_distinct_unconfirmed_targets_are_allowed_on_non_yes_rows(self):
        records=[]
        for proposal_id in ('first','second'):
            records.append({'proposal_id':proposal_id,'kind':'unknown','locator':'','region':'ap-northeast-1',
                'resource_arn':None,'aws_operation':None,'status':'unresolved','confidence':'low',
                'name_state':'UNKNOWN','name_key_present':None,'name_raw_value':None,'existing_name':'',
                'proposed_name':'','effective_usage_cost_usd':'1','evidence':'unresolved'})
        p={'schema_version':3,'account':'123456789012','partition':'aws','count':2,
           'execution_limits':{'max_send_attempts':1},'cur_population':sample_population(count=2,cost='2'),
           'scope_declarations':[{'writer_control_scope_id':'s','account':'123456789012','partition':'aws',
              'region':'ap-northeast-1','resource_arns':['arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-a']}],
           'records':records}
        plan_bytes=json.dumps(p).encode()
        rows=validate_batch_csv(plan_bytes,build_batch_review_projection(plan_bytes))
        self.assertEqual([row['approved'] for row in rows],['',''])

    def test_volume_locator_must_match_arn_resource_id(self):
        p={'schema_version':3,'account':'123456789012','partition':'aws','count':1,
           'execution_limits':{'max_send_attempts':1},'cur_population':sample_population(cost='1'),
           'scope_declarations':[{'writer_control_scope_id':'s','account':'123456789012','partition':'aws',
              'region':'ap-northeast-1','resource_arns':['arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-a']}],
           'records':[{'proposal_id':'p','kind':'volume','locator':'vol-b','region':'ap-northeast-1',
              'resource_arn':'arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-a',
              'aws_operation':'ec2:CreateTags','status':'proposed','confidence':'high','name_state':'ABSENT',
              'name_key_present':False,'name_raw_value':None,'existing_name':'','proposed_name':'Valid-Name',
              'effective_usage_cost_usd':'1','evidence':'metadata'}]}
        plan_bytes=json.dumps(p).encode()
        approved=build_batch_review_projection(plan_bytes).replace(b',p,',b'YES,p,')
        with self.assertRaises(BatchValidationError):
            validate_batch_draft(plan_bytes,approved)

    def test_proposed_name_accepts_256_unicode_chars_and_rejects_257(self):
        p={'schema_version':3,'account':'123456789012','partition':'aws','count':1,
           'execution_limits':{'max_send_attempts':1},'cur_population':sample_population(cost='1'),
           'scope_declarations':[{'writer_control_scope_id':'s','account':'123456789012','partition':'aws',
              'region':'ap-northeast-1','resource_arns':['arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-a']}],
           'records':[{'proposal_id':'p','kind':'volume','locator':'vol-a','region':'ap-northeast-1',
              'resource_arn':'arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-a',
              'aws_operation':'ec2:CreateTags','status':'proposed','confidence':'high','name_state':'ABSENT',
              'name_key_present':False,'name_raw_value':None,'existing_name':'','proposed_name':'名'*256,
              'effective_usage_cost_usd':'1','evidence':'metadata'}]}
        plan_bytes=json.dumps(p,ensure_ascii=False).encode()
        csv_bytes=build_batch_review_projection(plan_bytes).replace(b',p,',b'YES,p,')
        self.assertEqual(len(validate_batch_draft(plan_bytes,csv_bytes).approved_rows[0]['approved_name']),256)
        p['records'][0]['proposed_name']='名'*257
        plan_bytes=json.dumps(p,ensure_ascii=False).encode()
        csv_bytes=build_batch_review_projection(plan_bytes).replace(b',p,',b'YES,p,')
        with self.assertRaises(BatchValidationError):
            validate_batch_draft(plan_bytes,csv_bytes)

if __name__=='__main__':unittest.main()

class SecurityBoundaryTests(unittest.TestCase):
    def test_variant_name_unicode_casefold_is_unknown(self):
        self.assertEqual(classify_batch_name({'nAmE':'Value'}).state,'UNKNOWN')
    def test_foreign_arn_cannot_be_approved_through_matching_declaration(self):
        p={'schema_version':3,'account':'123456789012','partition':'aws','count':1,'execution_limits':{'max_send_attempts':1},'cur_population':sample_population(cost='1'),
        'scope_declarations':[{'writer_control_scope_id':'s','account':'123456789012','partition':'aws','region':'ap-northeast-1','resource_arns':['arn:aws:ec2:ap-northeast-1:999999999999:volume/vol-a']}],
        'records':[{'proposal_id':'a','kind':'volume','locator':'vol-a','region':'ap-northeast-1','resource_arn':'arn:aws:ec2:ap-northeast-1:999999999999:volume/vol-a','status':'proposed','confidence':'high','name_state':'ABSENT','name_key_present':False,'name_raw_value':None,'existing_name':'','proposed_name':'Name','effective_usage_cost_usd':'1','evidence':'E','aws_operation':'ec2:CreateTags'}]}
        pb=json.dumps(p).encode();csv0=build_batch_review_projection(pb)
        csv1=csv0.replace(b',a,',b'YES,a,')
        with self.assertRaises(BatchValidationError):validate_batch_draft(pb,csv1)
