"""Batching + retry behavior of LiveScoreSender (mocked HTTP transport)."""
import httpx

from nids_sensor.sender import LiveScoreSender


def make_sender(handler, batch_size=3):
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return LiveScoreSender("http://api.test", batch_size=batch_size, client=client)


def ok_handler(calls):
    def handler(request):
        calls.append(request)
        import json
        n = len(json.loads(request.content)["records"])
        return httpx.Response(200, json={"count": n, "attacks": 0, "results": []})
    return handler


def test_flushes_when_batch_full():
    calls = []
    s = make_sender(ok_handler(calls), batch_size=3)
    assert s.add({"a": 1}) is None
    assert s.add({"a": 2}) is None
    body = s.add({"a": 3})
    assert body == {"count": 3, "attacks": 0, "results": []}
    assert len(calls) == 1
    assert calls[0].url.path == "/score/live"
    assert s.pending == 0


def test_manual_flush_sends_partial_batch():
    calls = []
    s = make_sender(ok_handler(calls), batch_size=10)
    s.add({"a": 1})
    assert s.flush()["count"] == 1
    assert s.flush() is None  # empty buffer -> no request
    assert len(calls) == 1


def test_failure_keeps_records_for_retry():
    fail = {"on": True}

    def handler(request):
        if fail["on"]:
            raise httpx.ConnectError("backend down")
        import json
        n = len(json.loads(request.content)["records"])
        return httpx.Response(200, json={"count": n, "attacks": 0, "results": []})

    s = make_sender(handler, batch_size=2)
    s.add({"a": 1})
    assert s.add({"a": 2}) is None  # flush attempted, failed
    assert s.pending == 2
    fail["on"] = False
    assert s.flush()["count"] == 2
    assert s.pending == 0
