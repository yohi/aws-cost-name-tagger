"""Fresh protected OwnerTrust access for purpose-separated Batch verification."""
from __future__ import annotations

from name_tag_approval import OwnerTrust
from name_tag_batch_approval import BatchAuthRejected


def load_current_protected_owner_trust() -> OwnerTrust:
    """Reload the root-managed Phase A trust source; never accept caller paths."""
    from name_tag_controlled import _load_owner_trust

    trust = _load_owner_trust()
    if not isinstance(trust, OwnerTrust):
        raise BatchAuthRejected()
    return trust
