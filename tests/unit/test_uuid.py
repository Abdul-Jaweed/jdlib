import time
import uuid

from jdlib._uuid import uuid7


def test_uuid7_version_and_variant():
    value = uuid7()
    assert value.version == 7
    assert value.variant == uuid.RFC_4122
    assert (value.bytes[8] & 0xC0) == 0x80


def test_uuid7_is_unique_and_ordered_by_time():
    first = uuid7()
    time.sleep(0.002)
    second = uuid7()
    assert first != second
    assert first.hex < second.hex


def test_uuid7_returns_stdlib_uuid():
    assert isinstance(uuid7(), uuid.UUID)
