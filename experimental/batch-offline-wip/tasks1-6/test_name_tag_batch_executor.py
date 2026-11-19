import tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from name_tag_batch_executor import InMemoryNameAdapter,simulate_untrusted_fixture
from name_tag_batch_ledger import OfflineFixtureBatchLedger
from name_tag_batch_ledger import LedgerBlocked

class ExecutorFixtureTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup)
        self.ledger=OfflineFixtureBatchLedger.create_fixture(Path(self.t.name)/'fixture.sqlite')
        self.addCleanup(self.ledger.close)
        self.rows=[{'resource_arn':'volume-1','writer_control_scope_id':'scope-a','name_state':'ABSENT','name_raw_value':None,'approved_name':'Name-1'},
                   {'resource_arn':'volume-2','writer_control_scope_id':'scope-b','name_state':'ABSENT','name_raw_value':None,'approved_name':'Name-2'}]
    def test_two_rows_with_cap_one(self):
        a=InMemoryNameAdapter({'volume-1':{},'volume-2':{}})
        result=simulate_untrusted_fixture('batch-1','nonce-1',self.rows,ledger=self.ledger,adapter=a,cap=1)
        self.assertEqual(a.write_calls,1)
        self.assertEqual(self.ledger.dispositions('batch-1'),[(1,'NOT_ATTEMPTED_CAP')])
        self.assertEqual(result['batch_state'],'COMPLETED')
        self.assertEqual(result['authentication_state'],'SYNTHETIC_TEST_ONLY')
        self.assertFalse(result['writes_complete'])
    def test_readback_unknown_prevents_second_row(self):
        a=InMemoryNameAdapter({'volume-1':{},'volume-2':{}},unreadable_after_write={'volume-1'})
        result=simulate_untrusted_fixture('batch-2','nonce-2',self.rows,ledger=self.ledger,adapter=a,cap=2)
        self.assertEqual(a.write_calls,1)
        self.assertEqual(self.ledger.state('batch-2'),'STOPPED')
        self.assertEqual(result['outcomes'],['OUTCOME_UNKNOWN','NOT_ATTEMPTED_BATCH_STOP'])
    def test_inactive_batch_classifies_current_and_remaining_rows(self):
        a=InMemoryNameAdapter({'volume-1':{},'volume-2':{}})
        register=self.ledger.register
        def register_and_stop(*args,**kwargs):
            register(*args,**kwargs)
            self.ledger.stop('batch-stop','fixture stop')
        with patch.object(self.ledger,'register',side_effect=register_and_stop):
            result=simulate_untrusted_fixture('batch-stop','nonce-stop',self.rows,ledger=self.ledger,adapter=a,cap=2)
        self.assertEqual(result['outcomes'],['NOT_ATTEMPTED_BATCH_STOP','NOT_ATTEMPTED_BATCH_STOP'])
        self.assertEqual(a.write_calls,0)
    def test_readback_ledger_failure_after_send_is_outcome_unknown(self):
        a=InMemoryNameAdapter({'volume-1':{},'volume-2':{}})
        with patch.object(self.ledger,'readback',side_effect=LedgerBlocked('fixture readback persistence failed')):
            result=simulate_untrusted_fixture('batch-readback-failure','nonce-readback-failure',self.rows,ledger=self.ledger,adapter=a,cap=2)
        self.assertEqual(a.write_calls,1)
        self.assertEqual(result['outcomes'],['OUTCOME_UNKNOWN','NOT_ATTEMPTED_BATCH_STOP'])
        self.assertEqual(result['batch_state'],'STOPPED')
    def test_presend_name_change_skips_not_consume(self):
        a=InMemoryNameAdapter({'volume-1':{'Name':'existing'},'volume-2':{}})
        result=simulate_untrusted_fixture('batch-3','nonce-3',self.rows,ledger=self.ledger,adapter=a,cap=2)
        self.assertEqual(a.write_calls,1)
        self.assertEqual(self.ledger.counter('batch-3'),1)
        self.assertEqual(self.ledger.state('batch-3'),'COMPLETED')
        self.assertFalse(result['writes_complete'])

if __name__=='__main__':unittest.main()
