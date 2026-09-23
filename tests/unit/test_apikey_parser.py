import pytest

from jdlib.authn.apikey import hash_api_key_secret, parse_api_key, verify_api_key_secret
from jdlib.errors import InvalidToken


def test_parse_api_key_shape():
    parsed = parse_api_key("jd.keyid123.secret456")
    assert parsed.key_prefix == "jd.keyid123"
    assert parsed.secret == "secret456"


def test_parse_api_key_rejects_malformed():
    for token in ("", "jd.keyid", "jd..secret", "one.two.three.four"):
        with pytest.raises(InvalidToken):
            parse_api_key(token)


def test_hash_and_verify_roundtrip():
    stored = hash_api_key_secret("secret456")
    assert verify_api_key_secret("secret456", stored) is True
    assert verify_api_key_secret("wrong", stored) is False
    assert verify_api_key_secret("secret456", "not-a-hash") is False
