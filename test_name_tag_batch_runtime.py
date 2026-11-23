import unittest
from types import SimpleNamespace
from unittest.mock import patch

from name_tag_batch_approval import BatchAuthRejected
from name_tag_batch_runtime import _advance_batch_row, _record_cap_for_unclaimed
from name_tag_ledger_errors import LedgerError


class _Ledger:
    def __init__(self):
        self.stop_reasons=[]
        self.disposition_error=None

    def stop_batch(self,batch,*,reason_code):
        self.stop_reasons.append(reason_code)

    def record_batch_presend_disposition(self,*args,**kwargs):
        if self.disposition_error is not None:
            raise self.disposition_error


class RuntimeCapTests(unittest.TestCase):
    def setUp(self):
        self.batch=SimpleNamespace(approved_row_indexes=(0,))
        self.state=SimpleNamespace(
            send_attempts_consumed=1,max_send_attempts=1,outcomes=('UNCLAIMED',),state='ACTIVE')
        self.ledger=_Ledger()
        self.runtime=SimpleNamespace()
        self.report={}

    def test_scope_state_failure_does_not_revoke_owner_authentication(self):
        with patch('name_tag_batch_runtime._current_authority',return_value=SimpleNamespace(row={})), \
                patch('name_tag_batch_runtime._evidence_for',side_effect=LedgerError('BLOCKED_SCOPE_STATE_UNKNOWN')):
            stopped=_advance_batch_row(self.batch,0,0,self.state,self.ledger,self.runtime,self.report)
        self.assertTrue(stopped)
        self.assertEqual(self.ledger.stop_reasons,['BLOCKED_SCOPE_STATE_UNKNOWN'])
        self.assertNotIn('authentication_state',self.report)

    def test_owner_authentication_failure_is_reported_as_revoked(self):
        with patch('name_tag_batch_runtime._current_authority',side_effect=BatchAuthRejected()):
            stopped=_advance_batch_row(self.batch,0,0,self.state,self.ledger,self.runtime,self.report)
        self.assertTrue(stopped)
        self.assertEqual(self.ledger.stop_reasons,['BLOCKED_OWNER_AUTHN'])
        self.assertEqual(self.report['authentication_state'],'OWNER_AUTHN_REVOKED')

    def test_cap_disposition_ledger_error_stops_batch(self):
        authority=SimpleNamespace(row={})
        evidence=SimpleNamespace(scope=None,side_effects=())
        self.ledger.disposition_error=LedgerError('BLOCKED_SCOPE_STATE_UNKNOWN')
        with patch('name_tag_batch_runtime._current_authority',return_value=authority), \
                patch('name_tag_batch_runtime._evidence_for',return_value=evidence):
            stopped=_record_cap_for_unclaimed(self.batch,self.ledger,self.runtime,self.state)
        self.assertEqual(stopped,'BLOCKED_SCOPE_STATE_UNKNOWN')
        self.assertEqual(self.ledger.stop_reasons,['BLOCKED_SCOPE_STATE_UNKNOWN'])



class OfflineApiPreservedTests(unittest.TestCase):
    """RG-PRC-004: execute_batch_offline keeps its exact API; execute_batch_live is separate."""

    def test_offline_signature_unchanged_and_live_is_distinct(self):
        import inspect
        import name_tag_batch_runtime as runtime
        offline = inspect.signature(runtime.execute_batch_offline)
        self.assertEqual(
            [(p.name, p.kind) for p in offline.parameters.values()],
            [('batch', inspect.Parameter.POSITIONAL_OR_KEYWORD),
             ('plan_bytes', inspect.Parameter.KEYWORD_ONLY),
             ('csv_bytes', inspect.Parameter.KEYWORD_ONLY),
             ('ledger', inspect.Parameter.KEYWORD_ONLY),
             ('runtime', inspect.Parameter.KEYWORD_ONLY)])
        self.assertEqual(list(inspect.signature(runtime.execute_batch_live).parameters),
                         ['batch', 'ledger', 'runtime'])
        source = inspect.getsource(runtime.execute_batch_offline)
        self.assertIn('type(runtime.adapter) is not FakeBatchSDKAdapter', source)
        self.assertNotIn('execute_batch_live', source)

    def test_offline_runtime_never_accepted_by_live_api(self):
        from name_tag_batch_host_runtime import HostRuntimeBlocked
        import name_tag_batch_runtime as runtime
        with self.assertRaises(HostRuntimeBlocked) as caught:
            runtime.execute_batch_live(SimpleNamespace(), SimpleNamespace(), SimpleNamespace())
        self.assertEqual(caught.exception.code, "AWS_RUNTIME_NOT_AUTHORIZED")


if __name__=='__main__':
    unittest.main()
