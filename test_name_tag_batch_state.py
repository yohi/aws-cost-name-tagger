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
            'scope_declarations':[{'writer_control_scope_id':'fixed-scope','account':'123456789012','partition':'aws','region':'ap-northeast-1','resource_arns':['arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-abcdef12345678901']}],
            'records':[{'proposal_id':'proposal-1','kind':'volume','locator':'vol-abcdef12345678901','region':'ap-northeast-1','resource_arn':'arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-abcdef12345678901','status':'proposed','confidence':'high','name_state':'WHITESPACE_ONLY','name_key_present':True,'name_raw_value':' \t','existing_name':' \t','proposed_name':'app-prod-ebs-xvda-5678901','effective_usage_cost_usd':'1.2','evidence':'EBS vol-abcdef12345678901 -> attachment i-0123456789abcdef0 xvda -> EC2 i-0123456789abcdef0 Name=app-prod; Product(observed, not validated)=(unset)','aws_operation':'ec2:CreateTags'}],
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
        altered_name=approved.replace(b'app-prod-ebs-xvda-5678901',b'app-prod-ebs-xvda-0000000')
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
              'region':'ap-northeast-1','resource_arns':['arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-abcdef12345678901']}],
           'records':records}
        plan_bytes=json.dumps(p).encode()
        rows=validate_batch_csv(plan_bytes,build_batch_review_projection(plan_bytes))
        self.assertEqual([row['approved'] for row in rows],['',''])

    def test_volume_locator_must_match_arn_resource_id(self):
        p={'schema_version':3,'account':'123456789012','partition':'aws','count':1,
           'execution_limits':{'max_send_attempts':1},'cur_population':sample_population(cost='1'),
           'scope_declarations':[{'writer_control_scope_id':'s','account':'123456789012','partition':'aws',
              'region':'ap-northeast-1','resource_arns':['arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-abcdef12345678901']}],
           'records':[{'proposal_id':'p','kind':'volume','locator':'vol-0123456789abcdef0','region':'ap-northeast-1',
              'resource_arn':'arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-abcdef12345678901',
              'aws_operation':'ec2:CreateTags','status':'proposed','confidence':'high','name_state':'ABSENT',
              'name_key_present':False,'name_raw_value':None,'existing_name':'','proposed_name':'app-prod-ebs-xvda-abcdef0',
              'effective_usage_cost_usd':'1','evidence':'EBS vol-0123456789abcdef0 -> attachment i-0123456789abcdef0 xvda -> EC2 i-0123456789abcdef0 Name=app-prod; Product(observed, not validated)=(unset)'}]}
        plan_bytes=json.dumps(p).encode()
        approved=build_batch_review_projection(plan_bytes).replace(b',p,',b'YES,p,')
        with self.assertRaises(BatchValidationError):
            validate_batch_draft(plan_bytes,approved)

    def test_proposed_name_accepts_256_unicode_chars_and_rejects_257(self):
        p={'schema_version':3,'account':'123456789012','partition':'aws','count':1,
           'execution_limits':{'max_send_attempts':1},'cur_population':sample_population(cost='1'),
           'scope_declarations':[{'writer_control_scope_id':'s','account':'123456789012','partition':'aws',
              'region':'ap-northeast-1','resource_arns':['arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-abcdef12345678901']}],
           'records':[{'proposal_id':'p','kind':'volume','locator':'vol-abcdef12345678901','region':'ap-northeast-1',
              'resource_arn':'arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-abcdef12345678901',
              'aws_operation':'ec2:CreateTags','status':'proposed','confidence':'high','name_state':'ABSENT',
              'name_key_present':False,'name_raw_value':None,'existing_name':'','proposed_name':'app-prod-ebs-xvda-'+'x'*230+'-5678901',
              'effective_usage_cost_usd':'1','evidence':'EBS vol-abcdef12345678901 -> attachment i-0123456789abcdef0 xvda -> EC2 i-0123456789abcdef0 Name=app-prod; Product(observed, not validated)=(unset)'}]}
        plan_bytes=json.dumps(p,ensure_ascii=False).encode()
        csv_bytes=build_batch_review_projection(plan_bytes).replace(b',p,',b'YES,p,')
        self.assertEqual(len(validate_batch_draft(plan_bytes,csv_bytes).approved_rows[0]['approved_name']),256)
        p['records'][0]['proposed_name']='名'*257
        plan_bytes=json.dumps(p,ensure_ascii=False).encode()
        csv_bytes=build_batch_review_projection(plan_bytes).replace(b',p,',b'YES,p,')
        with self.assertRaises(BatchValidationError):
            validate_batch_draft(plan_bytes,csv_bytes)

    def test_review_projection_formula_escapes_match_validation_and_keeps_approval_editable(self):
        plan={
            'schema_version':3,'account':'123456789012','partition':'aws',
            'execution_limits':{'max_send_attempts':1},
            'cur_population':sample_population(cost='1'),
            'scope_declarations':[{'writer_control_scope_id':'s','account':'123456789012','partition':'aws',
                'region':'ap-northeast-1','resource_arns':['arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-abcdef12345678901']}],
            'records':[{'proposal_id':'proposal-1','kind':'volume','locator':'vol-abcdef12345678901','region':'ap-northeast-1',
                'resource_arn':'arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-abcdef12345678901',
                'aws_operation':'ec2:CreateTags','status':'proposed','confidence':'high','name_state':'WHITESPACE_ONLY',
                'name_key_present':True,'name_raw_value':'\t ','existing_name':'','proposed_name':'app-prod-ebs-xvda-5678901',
                'writer_control_scope_id':'s',
                'effective_usage_cost_usd':'1','evidence':'EBS vol-abcdef12345678901 -> attachment i-0123456789abcdef0 xvda -> EC2 i-0123456789abcdef0 Name=app-prod; Product(observed, not validated)=(unset)'}],
            'count':1,
        }
        plan_bytes=json.dumps(plan).encode()
        projection=build_batch_review_projection(plan_bytes)
        csv_rows=list(csv.reader(io.StringIO(projection.decode('utf-8-sig'))))
        self.assertEqual(csv_rows[1][9],"'\t ")
        csv_rows[1][0]='YES'
        edited=io.StringIO(newline='')
        writer=csv.writer(edited,lineterminator='\r\n')
        writer.writerows(csv_rows)
        draft=validate_batch_draft(plan_bytes,b'\xef\xbb\xbf'+edited.getvalue().encode())
        self.assertEqual(draft.rows[0]['approved'],'YES')

    def test_empty_scope_declaration_list_is_valid_for_unapprovable_plan(self):
        plan={'schema_version':3,'account':'123456789012','partition':'aws','count':0,
              'execution_limits':{'max_send_attempts':1},'cur_population':sample_population(count=0,cost='0'),
              'scope_declarations':[],'records':[]}
        plan_bytes=json.dumps(plan).encode()
        self.assertEqual(validate_batch_draft(plan_bytes,build_batch_review_projection(plan_bytes)).rows,())

    def test_non_string_proposal_id_is_rejected_as_batch_validation_error(self):
        plan={'schema_version':3,'account':'123456789012','partition':'aws','count':1,
              'execution_limits':{'max_send_attempts':1},'cur_population':sample_population(cost='1'),
              'scope_declarations':[], 'records':[{'proposal_id':[], 'kind':'unknown','locator':'',
              'region':'','resource_arn':None,'aws_operation':None,'status':'unresolved','confidence':'low',
              'name_state':'UNKNOWN','name_key_present':None,'name_raw_value':None,'existing_name':'',
              'proposed_name':'','effective_usage_cost_usd':'1','evidence':'x'}]}
        plan_bytes=json.dumps(plan).encode()
        with self.assertRaises(BatchValidationError):
            validate_batch_csv(plan_bytes,build_batch_review_projection(plan_bytes))

class SecurityBoundaryTests(unittest.TestCase):
    def test_variant_name_unicode_casefold_is_unknown(self):
        self.assertEqual(classify_batch_name({'nAmE':'Value'}).state,'UNKNOWN')
    def test_foreign_arn_cannot_be_approved_through_matching_declaration(self):
        p={'schema_version':3,'account':'123456789012','partition':'aws','count':1,'execution_limits':{'max_send_attempts':1},'cur_population':sample_population(cost='1'),
        'scope_declarations':[{'writer_control_scope_id':'s','account':'999999999999','partition':'aws','region':'ap-northeast-1','resource_arns':['arn:aws:ec2:ap-northeast-1:999999999999:volume/vol-abcdef12345678901']}],
        'records':[{'proposal_id':'a','kind':'volume','locator':'vol-abcdef12345678901','region':'ap-northeast-1','resource_arn':'arn:aws:ec2:ap-northeast-1:999999999999:volume/vol-abcdef12345678901','status':'proposed','confidence':'high','name_state':'ABSENT','name_key_present':False,'name_raw_value':None,'existing_name':'','proposed_name':'app-prod-ebs-xvda-5678901','effective_usage_cost_usd':'1','evidence':'EBS vol-abcdef12345678901 -> attachment i-0123456789abcdef0 xvda -> EC2 i-0123456789abcdef0 Name=app-prod; Product(observed, not validated)=(unset)','aws_operation':'ec2:CreateTags'}]}
        pb=json.dumps(p).encode()
        csv0=build_batch_review_projection(pb)
        with self.assertRaises(BatchValidationError):
            validate_batch_draft(pb,csv0.replace(b',a,',b'YES,a,'))

    def test_malformed_ec2_volume_arn_cannot_be_declared(self):
        p={'schema_version':3,'account':'123456789012','partition':'aws','count':1,
           'execution_limits':{'max_send_attempts':1},'cur_population':sample_population(cost='1'),
           'scope_declarations':[{'writer_control_scope_id':'s','account':'123456789012','partition':'aws',
              'region':'ap-northeast-1','resource_arns':['arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-a']}],
           'records':[{'proposal_id':'a','kind':'volume','locator':'vol-a','region':'ap-northeast-1',
              'resource_arn':'arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-a',
              'aws_operation':'ec2:CreateTags','status':'proposed','confidence':'high',
              'name_state':'ABSENT','name_key_present':False,'name_raw_value':None,
              'existing_name':'','proposed_name':'app-prod-ebs-xvda-vol-a','effective_usage_cost_usd':'1','evidence':'EBS vol-a -> attachment i-0123456789abcdef0 xvda -> EC2 i-0123456789abcdef0 Name=app-prod; Product(observed, not validated)=(unset)'}]}
        plan_bytes=json.dumps(p).encode()

        with self.assertRaises(BatchValidationError):
            validate_batch_draft(plan_bytes,build_batch_review_projection(plan_bytes))


def _single_row_plan(locator='vol-abcdef12345678901',name='app-prod-ebs-xvda-5678901',evidence=None,arn_id=None):
    arn_id=arn_id or locator
    arn=f'arn:aws:ec2:ap-northeast-1:123456789012:volume/{arn_id}'
    if evidence is None:
        evidence=f'EBS {locator} -> attachment i-0123456789abcdef0 xvda -> EC2 i-0123456789abcdef0 Name=app-prod; Product(observed, not validated)=(unset)'
    return json.dumps({'schema_version':3,'account':'123456789012','partition':'aws','count':1,
        'execution_limits':{'max_send_attempts':1},'cur_population':sample_population(cost='1'),
        'scope_declarations':[{'writer_control_scope_id':'s','account':'123456789012','partition':'aws',
            'region':'ap-northeast-1','resource_arns':[arn]}],
        'records':[{'proposal_id':'p','kind':'volume','locator':locator,'region':'ap-northeast-1',
            'resource_arn':arn,'aws_operation':'ec2:CreateTags','status':'proposed','confidence':'high',
            'name_state':'ABSENT','name_key_present':False,'name_raw_value':None,'existing_name':'',
            'proposed_name':name,'effective_usage_cost_usd':'1','evidence':evidence}]}).encode()


def _approve(plan_bytes):
    return validate_batch_draft(plan_bytes,build_batch_review_projection(plan_bytes).replace(b',p,',b'YES,p,'))


class ApprovedNameEligibilityTests(unittest.TestCase):
    """F-002: approval re-checks the v3 Name generation contract, not just non-empty evidence."""
    def test_generated_name_with_supporting_evidence_is_accepted(self):
        row=_approve(_single_row_plan()).approved_rows[0]
        self.assertEqual(row['approved_name'],'app-prod-ebs-xvda-5678901')

    def test_non_meaningful_or_non_generated_names_are_rejected(self):
        for name in ('Test-Name','app-prod-ebs-xvda-5678901 ','vol-abcdef12345678901','plainname','App-Prod-ebs-xvda-5678901'):
            with self.subTest(name=name),self.assertRaises(BatchValidationError):
                _approve(_single_row_plan(name=name))

    def test_nonempty_but_unrelated_evidence_is_rejected(self):
        bad=('evidence','manual note',
             'EBS vol-0123456789abcdef0 -> attachment i-0123456789abcdef0 xvda -> EC2 i-0123456789abcdef0 Name=app-prod; x',
             'EBS vol-abcdef12345678901 -> attachment i-0123456789abcdef0 xvda -> EC2 i-0123456789abcdef0 Name=other-prod; x')
        for evidence in bad:
            with self.subTest(evidence=evidence),self.assertRaises(BatchValidationError):
                _approve(_single_row_plan(evidence=evidence))

    def test_name_not_bound_to_volume_suffix_is_rejected(self):
        with self.assertRaises(BatchValidationError):
            _approve(_single_row_plan(name='app-prod-ebs-xvda-0000000'))

    def test_unapproved_rows_are_not_checked_for_eligibility(self):
        plan=_single_row_plan(name='Whatever',evidence='x')
        self.assertEqual(validate_batch_draft(plan,build_batch_review_projection(plan)).approved_rows,())


class VolumeIdSpecTests(unittest.TestCase):
    """F-003: State, IAM and the EC2 adapter share one canonical Volume ID rule."""
    GOOD=('vol-01234567','vol-0123456789abcdef0')
    BAD=('vol-a','vol-0123456','vol-012345678','vol-0123456789abcdef','vol-0123456789abcdef01',
         'vol-0123456G','vol-0123456789ABCDEF0','vol-0123456789abcdef0\n','vol-')

    def test_state_accepts_short_and_long_and_rejects_others(self):
        for vid in self.GOOD:
            with self.subTest(vid=vid):
                name=f'app-prod-ebs-xvda-{vid[-7:]}'
                self.assertEqual(len(_approve(_single_row_plan(locator=vid,name=name)).approved_rows),1)
        for vid in self.BAD:
            with self.subTest(vid=vid),self.assertRaises(BatchValidationError):
                _approve(_single_row_plan(locator=vid,name=f'app-prod-ebs-xvda-{vid[-7:]}'))

    def test_iam_and_adapter_agree_with_state(self):
        from name_tag_batch_iam import _validate_policy_row,IAMPolicyBlocked,KindPolicy
        from name_tag_adapters import build_volume_name_request,AdapterError
        kind={'volume':KindPolicy('ec2:CreateTags','ec2:DescribeVolumes')}
        class B:payload={'account':'123456789012','partition':'aws'}
        for vid in self.GOOD+self.BAD:
            arn=f'arn:aws:ec2:ap-northeast-1:123456789012:volume/{vid}'
            row={'kind':'volume','region':'ap-northeast-1','resource_arn':arn,'aws_operation':'ec2:CreateTags','approved_name':'n'}
            try:_validate_policy_row(B,row,kind);iam=True
            except IAMPolicyBlocked:iam=False
            try:build_volume_name_request(arn,'n',account='123456789012',region='ap-northeast-1');adapter=True
            except AdapterError:adapter=False
            with self.subTest(vid=vid):
                self.assertEqual(iam,vid in self.GOOD)
                self.assertEqual(adapter,vid in self.GOOD)


if __name__=='__main__':unittest.main()
