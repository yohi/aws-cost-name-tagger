import json,unittest
from types import MappingProxyType
from name_tag_batch_iam import build_subset_session_policy, KindPolicy, IAMPolicyBlocked
from name_tag_batch_credentials import OfflineFakeIssuer, CredentialBlocked
from name_tag_batch_approval import VerifiedBatchApproval

class PolicyTests(unittest.TestCase):
    def setUp(self):
        import hashlib
        self.row={'proposal_id':'p1','kind':'volume','resource_arn':'arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-abc','aws_operation':'ec2:CreateTags','writer_control_scope_id':'s1','approved_name':'Test-Name','region':'ap-northeast-1'}
        self.batch=VerifiedBatchApproval(b'fixture',b'fixture','b'*64,MappingProxyType({'account':'123456789012','partition':'aws','authorized_role_arn':'arn:aws:iam::123456789012:role/Batch'}),b'plan',b'csv',(self.row,),'owner','signed')
        self.kind={'volume':KindPolicy('ec2:CreateTags','ec2:DescribeVolumes')}
    def test_volume_write_arn_exact_and_read_star_separate(self):
        spec=build_subset_session_policy(self.batch,(0,),kind_registry=self.kind)
        p=json.loads(spec.policy_bytes)
        self.assertEqual(len(p['Statement']),2)
        self.assertEqual(p['Statement'][0]['Resource'],['arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-abc'])
        self.assertEqual(p['Statement'][0]['Condition']['ForAllValues:StringEquals']['aws:TagKeys'],['Name'])
        self.assertEqual(p['Statement'][1]['Resource'],'*')
        self.assertEqual(p['Statement'][1]['Action'],['ec2:DescribeVolumes'])
        self.assertEqual(spec.write_arns,(self.row['resource_arn'],))
    def test_unsupported_or_overlong_scope_fails(self):
        with self.assertRaises(IAMPolicyBlocked):build_subset_session_policy(self.batch,(0,),kind_registry={})
        with self.assertRaises(IAMPolicyBlocked):build_subset_session_policy(self.batch,(0,0),kind_registry=self.kind)
        with self.assertRaises(IAMPolicyBlocked):build_subset_session_policy(self.batch,(10,),kind_registry=self.kind)
    def test_issuer_requires_offline_fake_and_exact_policy(self):
        spec=build_subset_session_policy(self.batch,(0,),kind_registry=self.kind)
        fake=OfflineFakeIssuer()
        sess=fake.issue(self.batch,spec)
        self.assertEqual(sess.policy_sha256,spec.policy_sha256)
        self.assertEqual(sess.batch_id,self.batch.batch_id)
        self.assertIn(b'aws:TagKeys',sess.policy_bytes)
        with self.assertRaises(CredentialBlocked):fake.issue(self.batch,build_subset_session_policy(self.batch,(0,),kind_registry=self.kind),tamper_policy=True)

if __name__=='__main__':unittest.main()
