"""Tests for ledger.py — SHA-256 chain append + verify + tamper detection."""
from hermes_guard.ledger import GENESIS_PREV, Ledger


class TestLedger:
    def test_empty_head_is_genesis(self):
        led = Ledger()
        assert led.head_hash == GENESIS_PREV
        assert len(led) == 0

    def test_append_and_verify(self):
        led = Ledger()
        led.append("block", 100, {"L1": True}, preview="hello", session_id="s1")
        led.append("pass", 0, {}, preview="hi", session_id="s1")
        ok, bad = led.verify()
        assert ok is True
        assert bad is None

    def test_chain_links(self):
        led = Ledger()
        e1 = led.append("block", 100, {"L1": True}, preview="a")
        e2 = led.append("pass", 0, {}, preview="b")
        assert e1["prev"] == GENESIS_PREV
        assert e2["prev"] == e1["hash"]
        assert led.head_hash == e2["hash"]

    def test_tamper_detected(self):
        led = Ledger()
        led.append("block", 100, {"L1": True}, preview="a")
        led.append("pass", 0, {}, preview="b")
        # Tamper with the first entry's tier.
        led.entries[0]["tier"] = "pass"
        ok, bad = led.verify()
        assert ok is False
        assert bad == 0

    def test_tamper_hash_detected(self):
        led = Ledger()
        led.append("block", 100, {"L1": True}, preview="a")
        led.append("pass", 0, {}, preview="b")
        led.entries[1]["hash"] = "0" * 64
        ok, bad = led.verify()
        assert ok is False
        assert bad == 1

    def test_preview_truncated_to_160(self):
        led = Ledger()
        e = led.append("block", 100, {}, preview="X" * 500)
        assert len(e["preview"]) == 160

    def test_verify_empty(self):
        led = Ledger()
        ok, bad = led.verify()
        assert ok is True
        assert bad is None

    def test_reload_from_entries(self):
        led = Ledger()
        led.append("block", 100, {"L1": True}, preview="a")
        led.append("quarantine", 40, {"L2": True}, preview="b")
        led2 = Ledger(entries=led.entries)
        ok, bad = led2.verify()
        assert ok is True
        assert led2.head_hash == led.head_hash
