import unittest
from unittest.mock import patch

import name_tag_controlled
from name_tag_batch_approval import BatchAuthRejected
from name_tag_batch_trust import load_current_protected_owner_trust


class BatchTrustTests(unittest.TestCase):
    def test_each_load_uses_the_protected_phase_a_ownertrust_loader(self):
        with patch.object(name_tag_controlled, "_load_owner_trust", return_value=None) as loader:
            for _ in range(2):
                with self.assertRaises(BatchAuthRejected):
                    load_current_protected_owner_trust()
        self.assertEqual(loader.call_count, 2)

    def test_missing_protected_ownertrust_fails_closed(self):
        with patch.object(name_tag_controlled, "_load_owner_trust", return_value=None):
            with self.assertRaises(BatchAuthRejected):
                load_current_protected_owner_trust()


if __name__ == "__main__":
    unittest.main()
