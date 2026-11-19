from test_helpers import sample_population
import unittest, json, hashlib, base64, os, subprocess, tempfile
from datetime import datetime, timezone
from pathlib import Path
from name_tag_batch_approval import (prepare_batch_approval, verify_batch_approval, derive_batch_row_authority, VerifiedBatchApproval, BatchAuthRejected, BATCH_NAMESPACE)
from name_tag_batch_iam import build_subset_session_policy, KindPolicy, IAMPolicyBlocked
from name_tag_batch_state import build_batch_review_projection
from types import MappingProxyType
from name_tag_approval import EnrolledOwner, OwnerTrust

class BatchApprovalTests(unittest.TestCase):
    def setUp(self):
        p={'schema_version':3,'account':'123456789012','partition':'aws', 'execution_limits':{'max_send_attempts':1},'cur_population':sample_population(cost='1.5'),'count':1,
          'scope_declarations':[{'writer_control_scope_id':'scope-1','account':'123456789012','partition':'aws','region':'ap-northeast-1','resource_arns':['arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-a']}],
          'records':[{'proposal_id':'pid','kind':'volume','locator':'vol-a','region':'ap-northeast-1','resource_arn':'arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-a','aws_operation':'ec2:CreateTags','status':'proposed','confidence':'high','name_state':'ABSENT','name_key_present':False,'name_raw_value':None,'existing_name':'','proposed_name':'Test-Name','effective_usage_cost_usd':'1.5','evidence':'evidence'}]}
        self.plan=json.dumps(p).encode();self.csv=build_batch_review_projection(self.plan).replace(b',pid,',b'YES,pid,')
        self.kw={'owner_principal_id':'owner','owner_key_fingerprint':'SHA256:key','authorized_role_arn':'arn:aws:iam::123456789012:role/batch','issued_at_utc':'2026-11-19T00:00:00Z','expires_at_utc':'2026-11-20T00:00:00Z','batch_nonce':'ab'*16}
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.key=self.root/'owner-key';self.allowed=self.root/'allowed_signers'
        subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(self.key)],check=True)
        public=self.key.with_suffix('.pub').read_text().split()
        self.allowed.write_text(f'owner namespaces="{BATCH_NAMESPACE}" {public[0]} {public[1]}\n')
        self.allowed.chmod(0o600)
        self.fingerprint=subprocess.check_output(['ssh-keygen','-lf',str(self.key.with_suffix('.pub')),'-E','sha256'],text=True).split()[1]
        self.kw['owner_key_fingerprint']=self.fingerprint
        self.trust=OwnerTrust.from_allowed_signers(
            self.allowed,pinned_sha256=hashlib.sha256(self.allowed.read_bytes()).hexdigest(),
            enrolled={'owner':{self.fingerprint:EnrolledOwner(self.fingerprint,'batch-approver')}},
            expected_uid=os.getuid())

    def _signed_envelope(self):
        prepared=prepare_batch_approval(self.plan,self.csv,**self.kw)
        message=self.root/'payload'
        message.write_bytes(prepared.canonical_payload_bytes)
        subprocess.run(['ssh-keygen','-Y','sign','-f',str(self.key),'-n',BATCH_NAMESPACE,str(message)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        signature=message.with_suffix('.sig').read_bytes()
        envelope=json.dumps({'payload':prepared.payload,'batch_id':prepared.batch_id,'signature_ref':base64.b64encode(signature).decode()},separators=(',',':')).encode()
        return envelope
    def test_prep_is_unsigned_and_canonical(self):
        p=prepare_batch_approval(self.plan,self.csv,**self.kw)
        self.assertEqual(p.payload['purpose'],BATCH_NAMESPACE)
        self.assertEqual(p.payload['allowed_role'],'batch-approver')
        self.assertEqual(p.batch_id,hashlib.sha256(p.canonical_payload_bytes).hexdigest())
        self.assertEqual(len(p.manifest['approved_rows']),1)
        self.assertEqual(p.manifest['cur_population'],json.loads(self.plan)['cur_population'])
        self.assertEqual(p.manifest['approved_rows'][0]['writer_control_scope_id'],'scope-1')
        self.assertFalse(p.execution_allowed)
    def test_self_attested_claim_is_not_auth(self):
        p=prepare_batch_approval(self.plan,self.csv,**self.kw)
        envelope=json.dumps({'payload':p.payload,'batch_id':p.batch_id,'signature_ref':'not-a-signature'}).encode()
        with self.assertRaises(BatchAuthRejected):verify_batch_approval(self.plan,self.csv,envelope,trust=None,now_utc=None)
        with self.assertRaises(BatchAuthRejected):verify_batch_approval(self.plan,self.csv,envelope,trust=object(),now_utc=None)
    def test_real_owner_signature_is_accepted(self):
        envelope=self._signed_envelope()
        now=datetime(2026,11,19,12,tzinfo=timezone.utc)
        verified=verify_batch_approval(self.plan,self.csv,envelope,trust=self.trust,now_utc=now)
        self.assertEqual(verified.approved_row_indexes,(0,))

    def test_csv_change_after_signature_is_rejected(self):
        envelope=self._signed_envelope()
        now=datetime(2026,11,19,12,tzinfo=timezone.utc)
        changed_csv=self.csv.replace(b'Test-Name',b'Other-Name')
        with self.assertRaises(BatchAuthRejected):
            verify_batch_approval(self.plan,changed_csv,envelope,trust=self.trust,now_utc=now)

    def test_invalid_signature_is_rejected(self):
        envelope=self._signed_envelope()
        now=datetime(2026,11,19,12,tzinfo=timezone.utc)
        data=json.loads(envelope)
        data['signature_ref']=base64.b64encode(b'invalid signature').decode()
        with self.assertRaises(BatchAuthRejected):
            verify_batch_approval(self.plan,self.csv,json.dumps(data).encode(),trust=self.trust,now_utc=now)
    def test_forged_verified_batch_cannot_mint_row_authority(self):
        forged=VerifiedBatchApproval(b'not-signed',b'not-canonical','fake-batch',MappingProxyType({'account':'123456789012','partition':'aws'}),self.plan,self.csv,({'fake':'row'},),(0,),'owner','fake-signature')
        with self.assertRaises(BatchAuthRejected):
            derive_batch_row_authority(forged,0,trust=None,now_utc=datetime(2026,11,19,tzinfo=timezone.utc))

    def test_session_policy_rejects_row_changed_after_owner_verification(self):
        from dataclasses import replace

        envelope=self._signed_envelope()
        now=datetime(2026,11,19,12,tzinfo=timezone.utc)
        verified=verify_batch_approval(self.plan,self.csv,envelope,trust=self.trust,now_utc=now)
        changed_row=dict(verified.approved_rows[0])
        changed_row['resource_arn']='arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-other'
        changed=replace(verified,approved_rows=(changed_row,))

        with self.assertRaises(IAMPolicyBlocked):
            build_subset_session_policy(
                changed,(0,),kind_registry={'volume':KindPolicy('ec2:CreateTags','ec2:DescribeVolumes')})

if __name__=='__main__': unittest.main()
