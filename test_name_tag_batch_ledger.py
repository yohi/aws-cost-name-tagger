import sqlite3,tempfile,unittest
from contextlib import closing
from unittest.mock import patch
from pathlib import Path
import name_tag_batch_ledger
from name_tag_batch_ledger import OfflineFixtureBatchLedger, LedgerBlocked

class DurableFixtureTests(unittest.TestCase):
    def setUp(self):
        self.d=tempfile.TemporaryDirectory();self.addCleanup(self.d.cleanup)
        self.path=Path(self.d.name)/'batch_fixture.sqlite'
        self.ledger=OfflineFixtureBatchLedger.create_fixture(self.path)
        self.ledger.register('batch-a','nonce-a',max_send_attempts=1,row_count=2,scope_ids=['scope-a','scope-b'])
    def tearDown(self):
        self.ledger.close()
    def test_counter_atomic_and_cap_skip(self):
        self.ledger.admit('batch-a',0,'scope-a','row-0')
        self.ledger.consume('batch-a',0)
        self.assertEqual(self.ledger.counter('batch-a'),1)
        self.ledger.readback('batch-a',0,'APPLIED_VERIFIED')
        self.ledger.classify_cap('batch-a')
        self.assertEqual(self.ledger.dispositions('batch-a'),[(1,'NOT_ATTEMPTED_CAP')])
        self.assertEqual(self.ledger.state('batch-a'),'COMPLETED')
        with self.assertRaises(LedgerBlocked):self.ledger.admit('batch-a',1,'scope-b','row-1')
    def test_presend_skip_does_not_count_and_survives_restart(self):
        self.ledger.presend_skip('batch-a',0,'scope-a','row-0','SKIPPED_NAME_CHANGED')
        self.assertEqual(self.ledger.counter('batch-a'),0)
        self.ledger.close();self.ledger=OfflineFixtureBatchLedger.open_fixture(self.path)
        self.ledger.admit('batch-a',1,'scope-b','row-1')
        self.ledger.consume('batch-a',1)
        self.ledger.readback('batch-a',1,'APPLIED_VERIFIED')
        self.ledger.complete('batch-a')
        self.assertEqual(self.ledger.state('batch-a'),'COMPLETED')
        with self.assertRaises(LedgerBlocked):self.ledger.presend_skip('batch-a',0,'scope-a','row-0','SKIPPED_NAME_CHANGED')
    def test_cross_scope_unknown_stops_durably(self):
        self.ledger.admit('batch-a',0,'scope-a','row-0')
        self.ledger.consume('batch-a',0)
        self.ledger.readback('batch-a',0,'OUTCOME_UNKNOWN')
        self.ledger.close();self.ledger=OfflineFixtureBatchLedger.open_fixture(self.path)
        self.assertEqual(self.ledger.state('batch-a'),'STOPPED')
        self.ledger.release_scope('scope-a')
        with self.assertRaises(LedgerBlocked):self.ledger.admit('batch-a',1,'scope-b','row-1')
    def test_crash_after_consumed_stops_and_counter_preserved(self):
        self.ledger.admit('batch-a',0,'scope-a','row-0')
        self.ledger.consume('batch-a',0)
        self.ledger.close();self.ledger=OfflineFixtureBatchLedger.open_fixture(self.path)
        self.assertEqual(self.ledger.counter('batch-a'),1)
        self.assertEqual(self.ledger.state('batch-a'),'STOPPED')
        with self.assertRaises(LedgerBlocked):self.ledger.admit('batch-a',1,'scope-b','row-1')
    def test_crash_after_consumed_holds_scope_for_later_batches(self):
        self.ledger.admit('batch-a',0,'scope-a','row-0')
        self.ledger.consume('batch-a',0)
        self.ledger.close();self.ledger=OfflineFixtureBatchLedger.open_fixture(self.path)
        self.ledger.register('batch-b','nonce-b',max_send_attempts=1,row_count=1,scope_ids=['scope-a'])

        with self.assertRaises(LedgerBlocked):
            self.ledger.admit('batch-b',0,'scope-a','row-b')
        self.assertEqual(self.ledger.conn.execute("SELECT state FROM scopes WHERE scope_id='scope-a'").fetchone(),('HOLD',))
    def test_history_tamper_counter_rejected(self):
        self.ledger.admit('batch-a',0,'scope-a','row-0')
        self.ledger.consume('batch-a',0)
        self.ledger.close()
        con=sqlite3.connect(self.path);con.execute('UPDATE batch_registry SET send_attempts_consumed=0');con.commit();con.close()
        with self.assertRaises(LedgerBlocked):OfflineFixtureBatchLedger.open_fixture(self.path)
        # TearDown should not close an already closed connection
        self.ledger=OfflineFixtureBatchLedger.open_read_only_for_fixture(self.path)

    def test_create_fixture_rolls_back_partial_schema(self):
        path = Path(self.d.name) / 'partial_fixture.sqlite'
        ddl = 'CREATE TABLE should_rollback (id INTEGER); CREATE TABL invalid;'
        with patch.object(name_tag_batch_ledger, 'DDL', ddl):
            with self.assertRaises(sqlite3.OperationalError):
                OfflineFixtureBatchLedger.create_fixture(path)
        with closing(sqlite3.connect(path)) as connection:
            tables = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        self.assertEqual(tables, [])

    def test_admission_rejects_after_cap_without_creating_intent(self):
        self.ledger.admit('batch-a',0,'scope-a','row-0')
        self.ledger.consume('batch-a',0)
        self.ledger.readback('batch-a',0,'APPLIED_VERIFIED')
        with self.assertRaises(LedgerBlocked):
            self.ledger.admit('batch-a',1,'scope-b','row-1')
        self.assertIsNone(self.ledger.conn.execute(
            'SELECT 1 FROM intents WHERE batch_id=? AND row_index=?',('batch-a',1)).fetchone())

    def test_presend_skip_rejects_after_cap(self):
        self.ledger.admit('batch-a',0,'scope-a','row-0')
        self.ledger.consume('batch-a',0)
        self.ledger.readback('batch-a',0,'APPLIED_VERIFIED')
        with self.assertRaises(LedgerBlocked):
            self.ledger.presend_skip('batch-a',1,'scope-b','row-1','SKIPPED_NAME_CHANGED')

    def test_consume_rejects_unresolved_intent_in_another_batch_same_scope(self):
        self.ledger.register('batch-b','nonce-b',max_send_attempts=1,row_count=1,scope_ids=['scope-a'])
        self.ledger.admit('batch-b',0,'scope-a','row-b')
        self.ledger.conn.execute(
            "INSERT INTO intents VALUES(?,?,?,?,?)",
            ('batch-a',0,'row-a','scope-a','SEND_ATTEMPT_CONSUMED'),
        )
        with self.assertRaises(LedgerBlocked):
            self.ledger.consume('batch-b',0)

    def test_admit_rejects_another_batch_admitted_intent_in_same_scope(self):
        self.ledger.admit('batch-a',0,'scope-a','row-a')
        self.ledger.register('batch-b','nonce-b',max_send_attempts=1,row_count=1,scope_ids=['scope-a'])
        with self.assertRaises(LedgerBlocked):
            self.ledger.admit('batch-b',0,'scope-a','row-b')

    def test_reconcile_holds_all_scopes_before_stopping_related_batches(self):
        self.ledger.register('batch-b','nonce-b',max_send_attempts=1,row_count=1,scope_ids=['scope-b'])
        self.ledger.admit('batch-b',0,'scope-b','row-b')
        self.ledger.consume('batch-b',0)
        self.ledger.close()
        self.ledger=OfflineFixtureBatchLedger.open_fixture(self.path)
        self.assertEqual(self.ledger.state('batch-a'),'STOPPED')
        self.assertEqual(self.ledger.state('batch-b'),'STOPPED')
        self.assertEqual(self.ledger.conn.execute(
            "SELECT state FROM scopes WHERE scope_id='scope-b'"
        ).fetchone(),('HOLD',))

if __name__=='__main__':unittest.main()
