import pytest

from supplychain.image_verify import (
    verify_signature,
    predicate_ok,
    identity_ok,
    tuf_fresh,
    verify_manifest_list
)


def test_digest_match():
    assert verify_signature({'digest': 'sha256:a'}, {'digest': 'sha256:a', 'key': 'k1'}, 'k1') is True

def test_digest_mismatch():
    assert verify_signature({'digest': 'sha256:a'}, {'digest': 'sha256:b', 'key': 'k1'}, 'k1') is False

def test_tag_only():
    assert verify_signature({'tag': 'latest'}, {'digest': 'sha256:a', 'key': 'k1'}, 'k1') is False

def test_predicate_sbom():
    assert predicate_ok({'predicateType': 'https://spdx.dev/Document'}, 'https://spdx.dev/Document') is True

def test_predicate_mismatch():
    assert predicate_ok({'predicateType': 'https://slsa.dev/provenance'}, 'https://spdx.dev/Document') is False

def test_identity():
    assert identity_ok({'email': 'dev@example.com', 'issuer': 'oidc'}, {'dev@example.com'}) is True

def test_identity_prefix():
    assert identity_ok({'email': 'dev@example.com.evil', 'issuer': 'oidc'}, {'dev@example.com'}) is False

def test_tuf_fresh():
    assert tuf_fresh({'version': 1, 'expires': 200}, 100) is True

def test_tuf_expired():
    assert tuf_fresh({'version': 1, 'expires': 90}, 100) is False

def test_list_ok():
    assert verify_manifest_list([{'digest': 'a'}, {'digest': 'b'}], lambda m: True) is True

def test_list_bad():
    assert verify_manifest_list([{'digest': 'a'}, {'digest': 'b'}], lambda m: m['digest'] == 'a') is False

def test_list_empty():
    assert verify_manifest_list([], lambda m: True) is False

def test_missing_sig():
    assert verify_signature({'digest': 'sha256:a'}, {}, 'k1') is False

def test_wrong_key():
    assert verify_signature({'digest': 'sha256:a'}, {'digest': 'sha256:a', 'key': 'k2'}, 'k1') is False

def test_rotation():
    assert verify_signature({'digest': 'sha256:a'}, {'digest': 'sha256:a', 'key': 'k2'}, 'k2') is True
