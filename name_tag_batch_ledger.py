"""ISOLATED OFFLINE FIXTURE ONLY. NOT A PRODUCTION/PHASE-A LEDGER MIGRATION.

Proves durable Batch stop/cap/skip invariants with a disposable SQLite DB.
Does not grant send permission; production integration MUST reauthenticate Owner,
ScopeEvidence, SideEffectEvidence and effective IAM at both admission and permit.
"""
from __future__ import annotations
import sqlite3
from pathlib import Path
from contextlib import contextmanager

class LedgerBlocked(RuntimeError):pass

DDL='''
CREATE TABLE batch_registry (
 batch_id TEXT PRIMARY KEY, batch_nonce TEXT NOT NULL UNIQUE,
 plan_sha256 TEXT NOT NULL DEFAULT '', csv_sha256 TEXT NOT NULL DEFAULT '',
 state TEXT NOT NULL CHECK(state IN ('ACTIVE','STOPPED','COMPLETED')),
 max_send_attempts INTEGER NOT NULL CHECK(max_send_attempts BETWEEN 1 AND 20),
 send_attempts_consumed INTEGER NOT NULL DEFAULT 0
     CHECK(send_attempts_consumed >= 0 AND send_attempts_consumed <= max_send_attempts),
 stop_reason TEXT, created_at_utc TEXT NOT NULL DEFAULT 'fixture',
 stopped_at_utc TEXT,completed_at_utc TEXT,
 row_count INTEGER NOT NULL CHECK(row_count >= 1)
);
CREATE TABLE scopes(scope_id TEXT PRIMARY KEY, state TEXT NOT NULL CHECK(state IN ('CLEARED','HOLD')));
CREATE TABLE batch_scopes(batch_id TEXT NOT NULL REFERENCES batch_registry(batch_id),scope_id TEXT NOT NULL REFERENCES scopes(scope_id),PRIMARY KEY(batch_id,scope_id));
CREATE TABLE intents(batch_id TEXT NOT NULL REFERENCES batch_registry(batch_id),row_index INTEGER NOT NULL,row_authority_id TEXT UNIQUE NOT NULL,scope_id TEXT NOT NULL REFERENCES scopes(scope_id),state TEXT NOT NULL CHECK(state IN ('ADMITTED','SEND_ATTEMPT_CONSUMED','APPLIED_VERIFIED','OUTCOME_UNKNOWN')),PRIMARY KEY(batch_id,row_index));
CREATE TABLE batch_row_dispositions(batch_id TEXT NOT NULL REFERENCES batch_registry(batch_id),row_index INTEGER NOT NULL,row_authority_id TEXT NOT NULL UNIQUE,decision TEXT NOT NULL CHECK(decision IN ('SKIPPED_NAME_CHANGED','SKIPPED_IAM_UNSUPPORTED','NOT_ATTEMPTED_CAP')),PRIMARY KEY(batch_id,row_index));
CREATE TABLE batch_events(event_id INTEGER PRIMARY KEY AUTOINCREMENT,batch_id TEXT NOT NULL REFERENCES batch_registry(batch_id),event TEXT NOT NULL,reason TEXT NOT NULL DEFAULT '');
'''

class OfflineFixtureBatchLedger:
    @classmethod
    def create_fixture(cls,path):
        path=Path(path)
        if path.exists():raise LedgerBlocked('Fixture path already exists; refusing existing Ledger')
        path.parent.mkdir(parents=True,exist_ok=True)
        path.touch(mode=0o600,exist_ok=False)
        l=cls(path)
        try:
            with l._tx():
                for statement in DDL.split(';'):
                    if statement.strip():
                        l.conn.execute(statement)
        except sqlite3.Error:
            l.close()
            raise
        return l
    @classmethod
    def open_fixture(cls,path):
        if not Path(path).is_file():raise LedgerBlocked('No fixture')
        l=cls(Path(path))
        try:l._reconcile()
        except Exception:
            l.close();raise
        return l
    @classmethod
    def open_read_only_for_fixture(cls,path):
        # Only for teardown in tests of a known-corrupt *disposable* fixture.
        l=object.__new__(cls);l.path=Path(path);l.conn=sqlite3.connect(f'file:{path}?mode=ro',uri=True,isolation_level=None)
        return l
    def __init__(self,path):
        self.path=Path(path)
        self.conn=sqlite3.connect(self.path,timeout=5,isolation_level=None)
        self.conn.execute('PRAGMA foreign_keys=ON')
        self.conn.execute('PRAGMA busy_timeout=5000')
        self.conn.execute('PRAGMA journal_mode=DELETE')
        self.conn.execute('PRAGMA synchronous=FULL')
    def close(self):self.conn.close()
    @contextmanager
    def _tx(self):
        try:
            self.conn.execute('BEGIN IMMEDIATE')
            yield
            if self.conn.in_transaction:self.conn.execute('COMMIT')
        except BaseException:
            if self.conn.in_transaction:self.conn.execute('ROLLBACK')
            raise
    def _meta(self,id):
        r=self.conn.execute('SELECT state,max_send_attempts,send_attempts_consumed,row_count FROM batch_registry WHERE batch_id=?',(id,)).fetchone()
        if r is None:raise LedgerBlocked('Unknown Batch')
        return r
    def _safe(self,id):
        state,cap,used,size=self._meta(id)
        if state!='ACTIVE':raise LedgerBlocked('Batch not ACTIVE')
        held=self.conn.execute('SELECT COUNT(*) FROM batch_scopes bs JOIN scopes s USING(scope_id) WHERE bs.batch_id=? AND s.state<>\'CLEARED\'',(id,)).fetchone()[0]
        if held:raise LedgerBlocked('Covered Scope HOLD')
        pending=self.conn.execute("SELECT COUNT(*) FROM intents WHERE batch_id=? AND state IN ('ADMITTED','SEND_ATTEMPT_CONSUMED')",(id,)).fetchone()[0]
        if pending:raise LedgerBlocked('Prior incomplete Intent')
        unresolved=self.conn.execute("SELECT COUNT(*) FROM intents WHERE scope_id IN (SELECT scope_id FROM batch_scopes WHERE batch_id=?) AND state='SEND_ATTEMPT_CONSUMED'",(id,)).fetchone()[0]
        if unresolved:raise LedgerBlocked('Covered Scope has an unresolved send attempt')
        return cap,used,size
    def _claimed(self,id,index,authority):
        r=self.conn.execute('SELECT 1 FROM intents WHERE (batch_id=? AND row_index=?) OR row_authority_id=?',(id,index,authority)).fetchone()
        r2=self.conn.execute('SELECT 1 FROM batch_row_dispositions WHERE (batch_id=? AND row_index=?) OR row_authority_id=?',(id,index,authority)).fetchone()
        if r or r2:raise LedgerBlocked('Row already used')
    def register(self,id,nonce,*,max_send_attempts,row_count,scope_ids):
        if not id or not nonce or not scope_ids or type(row_count) is not int or row_count<=0:
            raise LedgerBlocked('Invalid fixture registry')
        with self._tx():
            if self.conn.execute('SELECT 1 FROM batch_registry WHERE batch_nonce=? OR batch_id=?',(nonce,id)).fetchone():
                raise LedgerBlocked('Batch replay')
            self.conn.execute('INSERT INTO batch_registry(batch_id,batch_nonce,state,max_send_attempts,row_count) VALUES(?,?,?,?,?)',(id,nonce,'ACTIVE',max_send_attempts,row_count))
            for scope in sorted(set(scope_ids)):
                self.conn.execute('INSERT OR IGNORE INTO scopes(scope_id,state) VALUES(?,\'CLEARED\')',(scope,))
                self.conn.execute('INSERT INTO batch_scopes VALUES (?,?)',(id,scope))
    def admit(self,id,index,scope,authority):
        with self._tx():
            _,_,size=self._safe(id)
            if not 0<=index<size or not self.conn.execute('SELECT 1 FROM batch_scopes WHERE batch_id=? AND scope_id=?',(id,scope)).fetchone():raise LedgerBlocked('Invalid row/scope')
            self._claimed(id,index,authority)
            self.conn.execute('INSERT INTO intents VALUES(?,?,?,?,?)',(id,index,authority,scope,'ADMITTED'))
    def presend_skip(self,id,index,scope,authority,decision):
        if decision not in ('SKIPPED_NAME_CHANGED','SKIPPED_IAM_UNSUPPORTED'):
            raise LedgerBlocked('Invalid skip')
        with self._tx():
            _,_,size=self._safe(id)
            if not 0<=index<size or not self.conn.execute('SELECT 1 FROM batch_scopes WHERE batch_id=? AND scope_id=?',(id,scope)).fetchone():raise LedgerBlocked('Invalid row/scope')
            self._claimed(id,index,authority)
            self.conn.execute('INSERT INTO batch_row_dispositions VALUES (?,?,?,?)',(id,index,authority,decision))
    def consume(self,id,index):
        with self._tx():
            state,cap,used,_=self._meta(id)
            if state!='ACTIVE' or used>=cap:raise LedgerBlocked('Cap reached or STOP')
            if self.conn.execute("SELECT COUNT(*) FROM batch_scopes bs JOIN scopes s USING(scope_id) WHERE bs.batch_id=? AND s.state!='CLEARED'",(id,)).fetchone()[0]:raise LedgerBlocked('Scope HOLD')
            r=self.conn.execute('SELECT state FROM intents WHERE batch_id=? AND row_index=?',(id,index)).fetchone()
            if r!=('ADMITTED',):raise LedgerBlocked('No fresh admitted Intent')
            self.conn.execute("UPDATE intents SET state='SEND_ATTEMPT_CONSUMED' WHERE batch_id=? AND row_index=?",(id,index))
            self.conn.execute('UPDATE batch_registry SET send_attempts_consumed=send_attempts_consumed+1 WHERE batch_id=?',(id,))
            self.conn.execute('INSERT INTO batch_events(batch_id,event) VALUES (?,?)',(id,'SEND_ATTEMPT_CONSUMED'))
    def readback(self,id,index,outcome):
        if outcome not in ('APPLIED_VERIFIED','OUTCOME_UNKNOWN'):raise LedgerBlocked('Not a terminal outcome')
        with self._tx():
            r=self.conn.execute('SELECT state,scope_id FROM intents WHERE batch_id=? AND row_index=?',(id,index)).fetchone()
            if not r or r[0]!='SEND_ATTEMPT_CONSUMED':raise LedgerBlocked('No consumed permit')
            self.conn.execute('UPDATE intents SET state=? WHERE batch_id=? AND row_index=?',(outcome,id,index))
            if outcome=='OUTCOME_UNKNOWN':
                self.conn.execute("UPDATE scopes SET state='HOLD' WHERE scope_id=?",(r[1],))
                self.conn.execute("UPDATE batch_registry SET state='STOPPED',stop_reason='OUTCOME_UNKNOWN',stopped_at_utc='fixture' WHERE batch_id=?",(id,))
            self.conn.execute('INSERT INTO batch_events(batch_id,event,reason) VALUES(?,?,?)',(id,'READBACK',outcome))
    def outcome_unknown_after_readback_failure(self,id,index):
        """Atomically record uncertain post-send state, Batch STOP, and Scope HOLD."""
        with self._tx():
            batch_state=self.conn.execute('SELECT state FROM batch_registry WHERE batch_id=?',(id,)).fetchone()
            row=self.conn.execute('SELECT state,scope_id FROM intents WHERE batch_id=? AND row_index=?',(id,index)).fetchone()
            if batch_state!=('ACTIVE',) or not row or row[0]!='SEND_ATTEMPT_CONSUMED':
                raise LedgerBlocked('No active consumed Intent for unknown outcome')
            self.conn.execute("UPDATE intents SET state='OUTCOME_UNKNOWN' WHERE batch_id=? AND row_index=?",(id,index))
            self.conn.execute("UPDATE scopes SET state='HOLD' WHERE scope_id=?",(row[1],))
            self.conn.execute("UPDATE batch_registry SET state='STOPPED',stop_reason='OUTCOME_UNKNOWN',stopped_at_utc='fixture' WHERE batch_id=?",(id,))
            self.conn.execute("INSERT INTO batch_events(batch_id,event,reason) VALUES(?,?,?)",(id,'READBACK','OUTCOME_UNKNOWN'))
    def _complete_in_tx(self,id):
        _,_,_,size=self._meta(id)
        actual=self.conn.execute('SELECT COUNT(*) FROM intents WHERE batch_id=?',(id,)).fetchone()[0]+self.conn.execute('SELECT COUNT(*) FROM batch_row_dispositions WHERE batch_id=?',(id,)).fetchone()[0]
        bad=self.conn.execute("SELECT COUNT(*) FROM intents WHERE batch_id=? AND state != 'APPLIED_VERIFIED'",(id,)).fetchone()[0]
        if actual!=size or bad:raise LedgerBlocked('Incomplete/unverified Batch')
        self.conn.execute("UPDATE batch_registry SET state='COMPLETED',completed_at_utc='fixture' WHERE batch_id=? AND state='ACTIVE'",(id,))
        self.conn.execute('INSERT INTO batch_events(batch_id,event) VALUES(?,?)',(id,'COMPLETED'))
    def complete(self,id):
        with self._tx():
            self._safe(id)
            self._complete_in_tx(id)
    def classify_cap(self,id):
        with self._tx():
            cap,used,size=self._safe(id)
            if used<cap:raise LedgerBlocked('Send cap not reached')
            for i in range(size):
                n=self.conn.execute('SELECT 1 FROM intents WHERE batch_id=? AND row_index=?',(id,i)).fetchone()
                s=self.conn.execute('SELECT 1 FROM batch_row_dispositions WHERE batch_id=? AND row_index=?',(id,i)).fetchone()
                if not n and not s:
                    self.conn.execute('INSERT INTO batch_row_dispositions VALUES(?,?,?,?)',(id,i,f'cap:{id}:{i}','NOT_ATTEMPTED_CAP'))
            self._complete_in_tx(id)
    def stop(self,id,reason):
        with self._tx():
            if self._meta(id)[0]!='ACTIVE':raise LedgerBlocked('Batch already terminal')
            self.conn.execute("UPDATE batch_registry SET state='STOPPED',stop_reason=?,stopped_at_utc='fixture' WHERE batch_id=?",(reason,id))
            self.conn.execute('INSERT INTO batch_events(batch_id,event,reason) VALUES(?,?,?)',(id,'STOP',reason))
    def release_scope(self,scope):
        with self._tx():self.conn.execute("UPDATE scopes SET state='CLEARED' WHERE scope_id=?",(scope,))
    def _reconcile(self):
        with self._tx():
            if self.conn.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise LedgerBlocked('SQLite corrupt')
            for (id,stored,state) in self.conn.execute('SELECT batch_id,send_attempts_consumed,state FROM batch_registry'):
                counted=self.conn.execute("SELECT COUNT(*) FROM intents WHERE batch_id=? AND state IN ('SEND_ATTEMPT_CONSUMED','APPLIED_VERIFIED','OUTCOME_UNKNOWN')",(id,)).fetchone()[0]
                if counted!=stored:raise LedgerBlocked('Counter/history mismatch')
                dangling=self.conn.execute("SELECT COUNT(*) FROM intents WHERE batch_id=? AND state IN ('ADMITTED','SEND_ATTEMPT_CONSUMED')",(id,)).fetchone()[0]
                unresolved_scopes=self.conn.execute("SELECT DISTINCT scope_id FROM intents WHERE batch_id=? AND state='SEND_ATTEMPT_CONSUMED'",(id,)).fetchall()
                for (scope_id,) in unresolved_scopes:
                    self.conn.execute("UPDATE scopes SET state='HOLD' WHERE scope_id=?",(scope_id,))
                held=self.conn.execute("SELECT COUNT(*) FROM batch_scopes b JOIN scopes s USING(scope_id) WHERE b.batch_id=? AND s.state='HOLD'",(id,)).fetchone()[0]
                if state=='ACTIVE' and (dangling or held):
                    self.conn.execute("UPDATE batch_registry SET state='STOPPED',stop_reason='CRASH_OR_SCOPE_HOLD',stopped_at_utc='fixture' WHERE batch_id=?",(id,))
    def state(self,id):return self._meta(id)[0]
    def counter(self,id):return self._meta(id)[2]
    def dispositions(self,id):return self.conn.execute('SELECT row_index,decision FROM batch_row_dispositions WHERE batch_id=? ORDER BY row_index',(id,)).fetchall()
