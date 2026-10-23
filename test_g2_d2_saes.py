"""D2 offline SAES tests: deterministic race, isolation, unknown outcomes."""
import threading
import unittest

from g2_d2_saes import (
    Attempt, OfflineContractError, OfflineSAES, SyntheticTransport,
    SAES_RUNTIME_PROOF, AWS_WRITES,
)


def make_saes(max_sends=3):
    return OfflineSAES(
        grant_id="synthetic-grant", plan_sha256="synthetic-plan",
        context_id="P1", gateway_id="synthetic-gateway",
        expires_at_tick=100, max_sends=max_sends,
    )


def make_attempt(aid="a1", epoch=0, context="P1", plan="synthetic-plan"):
    return Attempt(aid, plan, context, "synthetic-request", epoch)


def _wait_requested(g):
    # Event.wait() is a deterministic signal, not a sleeping race loop.
    return g._cancel_requested.wait(timeout=3)


class OfflineSAESTests(unittest.TestCase):
    def test_cancellation_wins_and_queued_attempt_never_sends(self):
        g, transport = make_saes(), SyntheticTransport()
        a = make_attempt()
        self.assertEqual(g.queue_attempt(a, tick=1), "QUEUED")
        self.assertEqual(g.revoke(), "REVOKED")
        self.assertEqual(g.attempt_state("a1"), "CANCELLED_BEFORE_SEND")
        self.assertEqual(g.send_once(a, transport, gateway_id=g.gateway_id, tick=2), "STOP_GRANT")
        self.assertEqual(transport.physical_send_count, 0)
        events = [x["kind"] for x in g.ledger]
        self.assertLess(events.index("REVOKE_COMMITTED"), events.index("REVOKE_ACK_SUCCESS"))
        self.assertNotIn("SEND_STARTED", events)

    def test_send_start_wins_ack_waits_for_inflight_start(self):
        g, transport_started, release = make_saes(), threading.Event(), threading.Event()
        transport = SyntheticTransport(gate_entered=transport_started, gate_release=release)
        a = make_attempt()
        self.assertEqual(g.queue_attempt(a, tick=1), "QUEUED")
        results = {}
        worker = threading.Thread(
            target=lambda: results.setdefault(
                "send", g.send_once(a, transport, gateway_id=g.gateway_id, tick=2)))
        revoker = threading.Thread(
            target=lambda: results.setdefault("revoke", g.revoke()))
        worker.start()
        try:
            self.assertTrue(transport_started.wait(3), "synthetic start never reached")
            revoker.start()
            self.assertFalse(release.is_set())
            # While the Gateway holds its synthetic serialization lock, the
            # revoker cannot report a successful ACK.
            self.assertNotIn("revoke", results)
        finally:
            release.set()
            worker.join(4)
            if revoker.ident is not None:
                revoker.join(4)
        self.assertFalse(worker.is_alive())
        self.assertFalse(revoker.is_alive())
        self.assertEqual(results, {"send": "OK", "revoke": "REVOKED"})
        names = [x["kind"] for x in g.ledger]
        self.assertLess(names.index("SEND_STARTED"), names.index("REVOKE_COMMITTED"))
        self.assertLess(names.index("REVOKE_COMMITTED"), names.index("REVOKE_ACK_SUCCESS"))
        self.assertEqual(transport.physical_send_count, 1)

    def test_cancel_between_admission_and_first_byte_blocks_send(self):
        g, entered, release = make_saes(), threading.Event(), threading.Event()
        t = SyntheticTransport(pre_start_entered=entered, pre_start_release=release)
        a = make_attempt("admitted-pending")
        self.assertEqual(g.queue_attempt(a, tick=1), "QUEUED")
        results = {}
        worker = threading.Thread(
            target=lambda: results.setdefault(
                "send", g.send_once(a, t, gateway_id=g.gateway_id, tick=2)))
        revoker = threading.Thread(
            target=lambda: results.setdefault("revoke", g.revoke()))
        worker.start()
        try:
            self.assertTrue(entered.wait(3), "pre-start admission barrier not reached")
            revoker.start()
            # The request flag is outside the synthetic sequencer lock;
            # the durable commit/ACK must wait for send to leave the lock.
            self.assertTrue(_wait_requested(g), "Owner cancellation was not submitted")
            self.assertNotIn("revoke", results)
        finally:
            release.set()
            worker.join(4)
            if revoker.ident is not None:
                revoker.join(4)
        self.assertFalse(worker.is_alive())
        self.assertFalse(revoker.is_alive())
        self.assertEqual(results, {"send": "STOP_GRANT", "revoke": "REVOKED"})
        self.assertEqual(t.physical_send_count, 0)
        names = [x["kind"] for x in g.ledger]
        self.assertIn("SEND_ADMITTED", names)
        self.assertIn("CANCELLED_BEFORE_SEND", names)
        self.assertLess(names.index("REVOKE_REQUESTED"),
                        names.index("CANCELLED_BEFORE_SEND"))
        self.assertNotIn("SEND_STARTED", names)
        self.assertLess(names.index("CANCELLED_BEFORE_SEND"),
                        names.index("REVOKE_ACK_SUCCESS"))

    def test_retry_after_owner_revokes_is_zero(self):
        g = make_saes()
        first, second = make_attempt("initial"), make_attempt("retry")
        t1, t2 = SyntheticTransport("THROTTLED"), SyntheticTransport()
        self.assertEqual(g.queue_attempt(first, tick=1), "QUEUED")
        self.assertEqual(g.send_once(first, t1, gateway_id=g.gateway_id, tick=2), "THROTTLED")
        self.assertEqual(g.revoke(), "REVOKED")
        self.assertEqual(g.queue_attempt(second, tick=3), "STOP_GRANT")
        self.assertEqual(g.send_once(second, t2, gateway_id=g.gateway_id, tick=3), "STOP_GRANT")
        self.assertEqual(t1.physical_send_count, 1)
        self.assertEqual(t2.physical_send_count, 0)

    def test_unknown_before_record_never_replayed(self):
        for outcome, observed in (("CRASH_BEFORE_START", 0),
                                  ("CRASH_AFTER_START", 1)):
            with self.subTest(outcome=outcome):
                g, a = make_saes(), make_attempt()
                t = SyntheticTransport(outcome)
                self.assertEqual(g.queue_attempt(a, tick=1), "QUEUED")
                self.assertEqual(g.send_once(a, t, gateway_id=g.gateway_id, tick=2),
                                 "SEND_OUTCOME_UNKNOWN")
                self.assertEqual(t.physical_send_count, observed)
                self.assertEqual(g.attempt_state(a.attempt_id), "SEND_OUTCOME_UNKNOWN")
                self.assertEqual(g.simulate_recovery(), "SUSPENDED")
                self.assertEqual(g.send_once(a, SyntheticTransport(),
                                              gateway_id=g.gateway_id, tick=3), "STOP_GRANT")
                self.assertNotIn("REVOKE_ACK_SUCCESS",
                                 [x["kind"] for x in g.ledger])

    def test_unfenced_gateway_cannot_ack_or_restart(self):
        g, a = make_saes(), make_attempt()
        self.assertEqual(g.queue_attempt(a, tick=1), "QUEUED")
        self.assertEqual(g.revoke(gateway_fencing_proven=False), "CANCEL_PENDING")
        transport = SyntheticTransport()
        self.assertEqual(g.send_once(a, transport, gateway_id=g.gateway_id, tick=2), "STOP_GRANT")
        self.assertEqual(transport.physical_send_count, 0)
        self.assertNotIn("REVOKE_ACK_SUCCESS", [x["kind"] for x in g.ledger])
        self.assertEqual(g.simulate_recovery(), "SUSPENDED")

    def test_expired_grant_wrong_plan_gateway_and_epoch(self):
        for invalid in (make_attempt("a1", epoch=1), make_attempt("a1", plan="wrong"),
                        make_attempt("a1", context="P3")):
            with self.subTest(invalid=invalid):
                g = make_saes()
                self.assertEqual(g.queue_attempt(invalid, tick=2), "STOP_POLICY")
        g, a = make_saes(), make_attempt()
        self.assertEqual(g.queue_attempt(a, tick=100), "STOP_GRANT")
        self.assertEqual(g.queue_attempt(a, tick=1), "QUEUED")
        transport = SyntheticTransport()
        self.assertEqual(g.send_once(a, transport, gateway_id="old-gateway", tick=1),
                         "STOP_GRANT")
        self.assertEqual(transport.physical_send_count, 0)

    def test_budget_duplicate_and_attempt_replay(self):
        g, a = make_saes(max_sends=1), make_attempt()
        self.assertEqual(g.queue_attempt(a, tick=1), "QUEUED")
        self.assertEqual(g.queue_attempt(a, tick=1), "STOP_DUPLICATE")
        self.assertEqual(g.send_once(a, SyntheticTransport(),
                                      gateway_id=g.gateway_id, tick=2), "OK")
        self.assertEqual(g.send_once(a, SyntheticTransport(),
                                      gateway_id=g.gateway_id, tick=3), "STOP_UNQUEUED")
        b = make_attempt("a2")
        self.assertEqual(g.queue_attempt(b, tick=3), "QUEUED")
        t = SyntheticTransport()
        self.assertEqual(g.send_once(b, t, gateway_id=g.gateway_id, tick=3), "STOP_BUDGET")
        self.assertEqual(t.physical_send_count, 0)

    def test_reject_non_synthetic_transport_and_invalid_objects(self):
        g, a = make_saes(), make_attempt()
        self.assertEqual(g.queue_attempt(a, tick=1), "QUEUED")
        with self.assertRaises(OfflineContractError):
            g.send_once(a, object(), gateway_id=g.gateway_id, tick=2)
        with self.assertRaises(OfflineContractError):
            g.queue_attempt(object(), tick=2)
        with self.assertRaises(OfflineContractError):
            SyntheticTransport("NETWORK")

    def test_no_real_sdk_or_runtime_proof(self):
        self.assertEqual(SAES_RUNTIME_PROOF, "NOT_PROVEN")
        self.assertEqual(AWS_WRITES, "BLOCKED")
        self.assertEqual(make_saes().ledger, ())


if __name__ == "__main__":
    unittest.main()
