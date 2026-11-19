from test_helpers import sample_population
import unittest, json, hashlib
from datetime import datetime, timezone
from name_tag_batch_approval import (prepare_batch_approval, verify_batch_approval, derive_batch_row_authority, VerifiedBatchApproval, BatchAuthRejected, BATCH_NAMESPACE)
from name_tag_batch_state import build_batch_review_projection
from types import MappingProxyType

class BatchApprovalTests(unittest.TestCase):
    def setUp(self):
        p={'schema_version':3,'account':'123456789012','partition':'aws', 'execution_limits':{'max_send_attempts':1},'cur_population':sample_population(cost='1.5'),'count':1,
          'scope_declarations':[{'writer_control_scope_id':'scope-1','account':'123456789012','partition':'aws','region':'ap-northeast-1','resource_arns':['arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-a']}],
          'records':[{'proposal_id':'pid','kind':'volume','locator':'vol-a','region':'ap-northeast-1','resource_arn':'arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-a','aws_operation':'ec2:CreateTags','status':'proposed','confidence':'high','name_state':'ABSENT','name_key_present':False,'name_raw_value':None,'existing_name':'','proposed_name':'Test-Name','effective_usage_cost_usd':'1.5','evidence':'evidence'}]}
        self.plan=json.dumps(p).encode();self.csv=build_batch_review_projection(self.plan).replace(b',pid,',b'YES,pid,')
        self.kw={'owner_principal_id':'owner','owner_key_fingerprint':'SHA256:key','authorized_role_arn':'arn:aws:iam::123456789012:role/batch','issued_at_utc':'2026-11-19T00:00:00Z','expires_at_utc':'2026-11-20T00:00:00Z','batch_nonce':'ab'*16}
    def test_prep_is_unsigned_and_canonical(self):
        p=prepare_batch_approval(self.plan,self.csv,**self.kw)
        self.assertEqual(p.payload['purpose'],BATCH_NAMESPACE)
        self.assertEqual(p.payload['allowed_role'],'batch-approver')
        self.assertEqual(p.batch_id,hashlib.sha256(p.canonical_payload_bytes).hexdigest())
        self.assertEqual(len(p.manifest['approved_rows']),1)
        self.assertEqual(p.manifest['approved_rows'][0]['writer_control_scope_id'],'scope-1')
        self.assertFalse(p.execution_allowed)
    def test_self_attested_claim_is_not_auth(self):
        p=prepare_batch_approval(self.plan,self.csv,**self.kw)
        envelope=json.dumps({'payload':p.payload,'batch_id':p.batch_id,'signature_ref':'not-a-signature'}).encode()
        with self.assertRaises(BatchAuthRejected):verify_batch_approval(self.plan,self.csv,envelope,trust=None,now_utc=None)
        with self.assertRaises(BatchAuthRejected):verify_batch_approval(self.plan,self.csv,envelope,trust=object(),now_utc=None)
    def test_forged_verified_batch_cannot_mint_row_authority(self):
        forged=VerifiedBatchApproval(b'not-signed',b'not-canonical','fake-batch',MappingProxyType({'account':'123456789012','partition':'aws'}),self.plan,self.csv,({'fake':'row'},),(0,),'owner','fake-signature')
        with self.assertRaises(BatchAuthRejected):
            derive_batch_row_authority(forged,0,trust=None,now_utc=datetime(2026,11,19,tzinfo=timezone.utc))

if __name__=='__main__': unittest.main()
