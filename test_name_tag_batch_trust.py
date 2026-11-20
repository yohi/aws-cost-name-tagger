import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import name_tag_controlled
from name_tag_batch_approval import BatchAuthRejected
from name_tag_batch_trust import load_current_protected_owner_trust
from name_tag_approval import OwnerTrust


class BatchTrustTests(unittest.TestCase):
    def test_each_load_uses_the_protected_phase_a_ownertrust_loader(self):
        with tempfile.TemporaryDirectory() as directory:
            allowed=Path(directory)/'allowed_signers'
            allowed.write_bytes(b'')
            allowed.chmod(0o600)
            trust=OwnerTrust.from_allowed_signers(
                allowed,pinned_sha256=hashlib.sha256(b'').hexdigest(),
                enrolled={},expected_uid=os.getuid())
            with patch.object(name_tag_controlled, "_load_owner_trust", side_effect=[trust,None]) as loader:
                self.assertIs(load_current_protected_owner_trust(),trust)
                with self.assertRaises(BatchAuthRejected):
                    load_current_protected_owner_trust()
        self.assertEqual(loader.call_count, 2)

    def test_missing_protected_ownertrust_fails_closed(self):
        with patch.object(name_tag_controlled, "_load_owner_trust", return_value=None):
            with self.assertRaises(BatchAuthRejected):
                load_current_protected_owner_trust()


if __name__ == "__main__":
    unittest.main()
