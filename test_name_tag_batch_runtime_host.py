from __future__ import annotations

import unittest

from name_tag_batch_credentials import BatchCredentialIssuer, OfflineFakeIssuer


class BatchCredentialIssuerContractTests(unittest.TestCase):
    def test_offline_fake_issuer_implements_the_runtime_issuer_contract(self) -> None:
        issuer: BatchCredentialIssuer = OfflineFakeIssuer()

        self.assertTrue(callable(issuer.issue))


if __name__ == "__main__":
    unittest.main()
