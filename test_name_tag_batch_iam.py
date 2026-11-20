import gc,hashlib,json,unittest,weakref
from types import MappingProxyType
from name_tag_batch_iam import build_subset_session_policy, KindPolicy, IAMPolicyBlocked, SessionPolicySpec
from name_tag_batch_credentials import OfflineFakeIssuer, CredentialBlocked
from name_tag_batch_credentials import IssuedBatchSession, validate_issued_batch_session
from name_tag_batch_approval import VerifiedBatchApproval, prepare_batch_approval
from name_tag_batch_state import build_batch_review_projection, validate_batch_draft
from test_helpers import sample_population

class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.plan=json.dumps({
            'schema_version':3,'account':'123456789012','partition':'aws',
            'execution_limits':{'max_send_attempts':1},'cur_population':sample_population(count=2,cost='1.5'),'count':2,
            'scope_declarations':[{'writer_control_scope_id':'s1','account':'123456789012','partition':'aws','region':'ap-northeast-1','resource_arns':['arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-abcdef1234567890']}],
            'records':[
                {'proposal_id':'p0','kind':'volume','locator':'vol-0123456789abcdef0','region':'ap-northeast-1','resource_arn':'arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-0123456789abcdef0','aws_operation':'ec2:CreateTags','status':'proposed','confidence':'high','name_state':'ABSENT','name_key_present':False,'name_raw_value':None,'existing_name':'','proposed_name':'Unused-Name','effective_usage_cost_usd':'0.75','evidence':'evidence-0'},
                {'proposal_id':'p1','kind':'volume','locator':'vol-abcdef1234567890','region':'ap-northeast-1','resource_arn':'arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-abcdef1234567890','aws_operation':'ec2:CreateTags','status':'proposed','confidence':'high','name_state':'ABSENT','name_key_present':False,'name_raw_value':None,'existing_name':'','proposed_name':'Test-Name','effective_usage_cost_usd':'0.75','evidence':'evidence-1'}]}
        ).encode()
        self.csv=build_batch_review_projection(self.plan).replace(b',p1,',b'YES,p1,')
        draft=validate_batch_draft(self.plan,self.csv)
        prepared=prepare_batch_approval(
            self.plan,self.csv,owner_principal_id='owner',owner_key_fingerprint='SHA256:key',
            authorized_role_arn='arn:aws:iam::123456789012:role/Batch',
            issued_at_utc='2026-11-19T00:00:00Z',expires_at_utc='2026-11-20T00:00:00Z',batch_nonce='ab'*16)
        self.row=draft.approved_rows[0]
        self.batch=VerifiedBatchApproval(
            b'fixture-envelope',prepared.canonical_payload_bytes,prepared.batch_id,
            MappingProxyType(dict(prepared.payload)),self.plan,self.csv,
            tuple(dict(row) for row in draft.approved_rows),(1,),'owner','fixture-signature')
        self.kind={'volume':KindPolicy('ec2:CreateTags','ec2:DescribeVolumes')}
    def test_volume_write_arn_exact_and_read_star_separate(self):
        spec=build_subset_session_policy(self.batch,(1,),kind_registry=self.kind)
        p=json.loads(spec.policy_bytes)
        self.assertEqual(len(p['Statement']),2)
        self.assertEqual(p['Statement'][0]['Resource'],['arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-abcdef1234567890'])
        self.assertEqual(p['Statement'][0]['Condition']['ForAllValues:StringEquals']['aws:TagKeys'],['Name'])
        self.assertEqual(p['Statement'][1]['Resource'],'*')
        self.assertEqual(p['Statement'][1]['Action'],['ec2:DescribeVolumes'])
        self.assertEqual(spec.write_arns,(self.row['resource_arn'],))
    def test_subset_index_uses_original_csv_row_position(self):
        spec=build_subset_session_policy(self.batch,(1,),kind_registry=self.kind)
        self.assertEqual(spec.row_indexes,(1,))
        self.assertEqual(spec.write_arns,(self.row['resource_arn'],))

    def test_short_noncanonical_volume_arn_is_rejected(self):
        from name_tag_batch_iam import _validate_policy_row

        malformed=dict(self.row)
        malformed['resource_arn']='arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-a'

        with self.assertRaises(IAMPolicyBlocked):
            _validate_policy_row(self.batch,malformed,self.kind)
    def test_unregistered_kind_duplicate_index_and_out_of_range_index_fail(self):
        with self.assertRaises(IAMPolicyBlocked):build_subset_session_policy(self.batch,(1,),kind_registry={})
        with self.assertRaises(IAMPolicyBlocked):build_subset_session_policy(self.batch,(1,1),kind_registry=self.kind)
        with self.assertRaises(IAMPolicyBlocked):build_subset_session_policy(self.batch,(10,),kind_registry=self.kind)
    def test_issuer_requires_offline_fake_and_exact_policy(self):
        spec=build_subset_session_policy(self.batch,(1,),kind_registry=self.kind)
        fake=OfflineFakeIssuer()
        sess=fake.issue(self.batch,spec,kind_registry=self.kind)
        self.assertEqual(sess.policy_sha256,spec.policy_sha256)
        self.assertEqual(sess.batch_id,self.batch.batch_id)
        self.assertEqual(sess.row_indexes,spec.row_indexes)
        self.assertEqual(sess.role_arn,self.batch.payload['authorized_role_arn'])
        self.assertEqual(sess.provenance,'OFFLINE_SYNTHETIC_NOT_STS')
        self.assertIn(b'aws:TagKeys',sess.policy_bytes)
        with self.assertRaises(CredentialBlocked):fake.issue(self.batch,build_subset_session_policy(self.batch,(1,),kind_registry=self.kind),kind_registry=self.kind,tamper_policy=True)

    def test_issued_session_claims_are_revalidated_before_use(self):
        spec=build_subset_session_policy(self.batch,(1,),kind_registry=self.kind)
        issuer=OfflineFakeIssuer()
        session=issuer.issue(self.batch,spec,kind_registry=self.kind)

        validate_issued_batch_session(self.batch,spec,session)

        counterfeit=IssuedBatchSession(
            batch_id='foreign-batch',policy_bytes=session.policy_bytes,
            policy_sha256=session.policy_sha256,row_indexes=session.row_indexes,
            role_arn=session.role_arn)
        with self.assertRaises(CredentialBlocked):
            validate_issued_batch_session(self.batch,spec,counterfeit)
    def test_offline_adapter_operations_require_issuer_minted_bound_session(self):
        from name_tag_batch_fake import FakeBatchSDKAdapter
        arn0=self.batch.approved_rows[0]['resource_arn']
        spec=build_subset_session_policy(self.batch,(1,),kind_registry=self.kind)
        session=OfflineFakeIssuer().issue(self.batch,spec,kind_registry=self.kind)
        adapter=FakeBatchSDKAdapter({arn0:{}},require_session=True)
        # Same session binds read, write and readback for its own subset.
        adapter.read_current(arn0,session=session)
        adapter.write_once(arn0,'Test-Name',session=session)
        self.assertEqual(adapter.readback(arn0,session=session)['Name'],'Test-Name')
        # Missing session, equal-valued external copy, tampered policy: all refused.
        with self.assertRaises(CredentialBlocked):adapter.read_current(arn0)
        copy=IssuedBatchSession(session.batch_id,session.policy_bytes,session.policy_sha256,session.row_indexes,session.role_arn)
        with self.assertRaises(CredentialBlocked):adapter.read_current(arn0,session=copy)
        tampered=IssuedBatchSession(session.batch_id,session.policy_bytes+b' ',session.policy_sha256,session.row_indexes,session.role_arn)
        with self.assertRaises(CredentialBlocked):adapter.write_once(arn0,'X',session=tampered)
        # A session for a different row subset cannot write a foreign ARN.
        other='arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-0123456789abcdef0'
        adapter2=FakeBatchSDKAdapter({other:{}},require_session=True)
        with self.assertRaises(CredentialBlocked):adapter2.write_once(other,'X',session=session)
        self.assertEqual(adapter2.write_calls,0)
        with self.assertRaises(CredentialBlocked):adapter2.readback(other)

    def test_issued_sessions_are_weakly_retained_until_caller_releases_them(self):
        import name_tag_batch_credentials as credentials
        session=OfflineFakeIssuer().issue(
            self.batch,build_subset_session_policy(self.batch,(1,),kind_registry=self.kind),
            kind_registry=self.kind)
        issued_id=id(session)
        reference=weakref.ref(session)
        self.assertIn(issued_id,credentials._ISSUED)
        del session
        gc.collect()
        self.assertIsNone(reference())
        self.assertNotIn(issued_id,credentials._ISSUED)

    def test_issuer_rejects_self_hashed_wildcard_policy(self):
        policy=b'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:CreateTags","Resource":"*"}]}'
        forged=SessionPolicySpec(self.batch.batch_id,(1,),policy,hashlib.sha256(policy).hexdigest(),('*',),('ec2:CreateTags',),('ec2:DescribeVolumes',))
        with self.assertRaises(CredentialBlocked):
            OfflineFakeIssuer().issue(self.batch,forged,kind_registry=self.kind)

if __name__=='__main__':unittest.main()
