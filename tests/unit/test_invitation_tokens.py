from jdlib.authz.access import (
    build_invitation_token,
    hash_invitation_secret,
    verify_invitation,
)


def _split(token: str) -> tuple[str, str]:
    _, token_id, secret = token.split("_")
    return token_id, secret


def test_token_roundtrip_and_tampering():
    token = build_invitation_token()
    token_id, secret = token.split("_")[1], token.rsplit("_", 1)[1]
    stored = hash_invitation_secret(secret)
    assert verify_invitation(token, token_id, stored) is True
    assert verify_invitation("inv_deadbeef_wrong", token_id, stored) is False


def test_tokens_are_unique_and_hashes_hide_the_secret():
    first = build_invitation_token()
    second = build_invitation_token()
    first_id, first_secret = _split(first)
    assert first != second
    assert first.startswith("inv_")
    assert second.startswith("inv_")
    assert first_id != _split(second)[0]
    stored = hash_invitation_secret(first_secret)
    assert stored.startswith("$argon2id$")
    assert first_secret not in stored


def test_verify_rejects_malformed_and_mismatched_tokens():
    token = build_invitation_token()
    token_id, secret = _split(token)
    stored = hash_invitation_secret(secret)
    assert verify_invitation("", token_id, stored) is False
    assert verify_invitation("inv_only", token_id, stored) is False
    assert verify_invitation(f"inv_{token_id}_{secret}_extra", token_id, stored) is False
    assert verify_invitation(f"pat_{token_id}_{secret}", token_id, stored) is False
    assert verify_invitation(f"inv_other_{secret}", token_id, stored) is False
    assert verify_invitation(token, "other", stored) is False


def test_verify_rejects_invalid_stored_hash():
    token = build_invitation_token()
    token_id, _ = _split(token)
    assert verify_invitation(token, token_id, "not-a-password-hash") is False
    assert verify_invitation(token, token_id, "") is False
