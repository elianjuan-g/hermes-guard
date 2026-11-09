"""Tests for taint.py — session taint + call-ID race guard."""
from hermes_guard.taint import TaintTracker


class FakeClock:
    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class TestTaint:
    def test_fresh_session_not_tainted(self):
        t = TaintTracker()
        assert t.is_tainted("s1") is False

    def test_taint_then_check(self):
        t = TaintTracker()
        t.taint_session("s1")
        assert t.is_tainted("s1") is True
        assert t.is_tainted("s2") is False

    def test_taint_expires(self):
        clock = FakeClock()
        t = TaintTracker(taint_ttl=60, clock=clock)
        t.taint_session("s1")
        assert t.is_tainted("s1") is True
        clock.advance(61)
        assert t.is_tainted("s1") is False

    def test_taint_none_session_safe(self):
        t = TaintTracker()
        t.taint_session(None)
        assert t.is_tainted(None) is False

    def test_tainted_sessions_lists_live_only(self):
        clock = FakeClock()
        t = TaintTracker(taint_ttl=60, clock=clock)
        t.taint_session("s1")
        t.taint_session("s2")
        assert set(t.tainted_sessions()) == {"s1", "s2"}
        clock.advance(61)
        assert t.tainted_sessions() == []


class TestCallIdRace:
    def test_first_call_not_race(self):
        t = TaintTracker()
        is_race, _ = t.check_call("s1", "read_file", {"path": "/tmp/a"})
        assert is_race is False

    def test_identical_call_in_window_is_race(self):
        clock = FakeClock()
        t = TaintTracker(race_window=10, clock=clock)
        t.check_call("s1", "read_file", {"path": "/tmp/a"})
        clock.advance(5)
        is_race, _ = t.check_call("s1", "read_file", {"path": "/tmp/a"})
        assert is_race is True

    def test_identical_call_after_window_not_race(self):
        clock = FakeClock()
        t = TaintTracker(race_window=10, clock=clock)
        t.check_call("s1", "read_file", {"path": "/tmp/a"})
        clock.advance(11)
        is_race, _ = t.check_call("s1", "read_file", {"path": "/tmp/a"})
        assert is_race is False

    def test_different_args_not_race(self):
        t = TaintTracker()
        t.check_call("s1", "read_file", {"path": "/tmp/a"})
        is_race, _ = t.check_call("s1", "read_file", {"path": "/tmp/b"})
        assert is_race is False

    def test_different_tool_not_race(self):
        t = TaintTracker()
        t.check_call("s1", "read_file", {"path": "/tmp/a"})
        is_race, _ = t.check_call("s1", "write_file", {"path": "/tmp/a"})
        assert is_race is False

    def test_different_session_not_race(self):
        t = TaintTracker()
        t.check_call("s1", "read_file", {"path": "/tmp/a"})
        is_race, _ = t.check_call("s2", "read_file", {"path": "/tmp/a"})
        assert is_race is False

    def test_fingerprint_stable(self):
        t = TaintTracker()
        _, fp1 = t.check_call("s1", "tool", {"b": 2, "a": 1})
        _, fp2 = t.check_call("s1", "tool", {"a": 1, "b": 2})
        assert fp1 == fp2
