"""Supply-chain image verification gate.

Fixes:
- Signatures are bound to the image digest (tags are mutable and never trusted).
- Attestation predicateType must match the expected type exactly (SBOM and
  provenance attestations are not interchangeable).
- Signer identity is matched on the exact email, not a prefix.
- TUF metadata past its expiry is rejected (offline rollback protection).
- Every child manifest of a multi-arch manifest list must verify.
"""


def verify_signature(image, signature, key):
    """A signature is valid only if it is bound to the image's digest and
    was made with the expected key. Tag-only references are rejected."""
    image_digest = image.get('digest')
    if not image_digest:
        return False
    if not signature:
        return False
    if signature.get('digest') != image_digest:
        return False
    if signature.get('key') != key:
        return False
    return True


def predicate_ok(attestation, expected_type):
    """The attestation's predicateType must exactly equal the expected type."""
    if not attestation:
        return False
    return attestation.get('predicateType') == expected_type


def identity_ok(identity, allowed_identities):
    """The signer's email must exactly match an allowed identity."""
    if not identity:
        return False
    return identity.get('email') in allowed_identities


def tuf_fresh(metadata, now):
    """TUF metadata must not be expired at `now`."""
    if not metadata:
        return False
    expires = metadata.get('expires')
    if expires is None:
        return False
    return expires > now


def verify_manifest_list(manifests, verify_fn):
    """Every child manifest in a multi-arch manifest list must verify;
    an empty list is rejected."""
    if not manifests:
        return False
    return all(verify_fn(m) for m in manifests)
