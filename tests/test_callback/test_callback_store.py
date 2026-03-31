# tests/test_callback/test_callback_store.py
import pytest


def test_register_callback():
    from workers.callback.callback_store import CallbackStore

    store = CallbackStore()
    cb_id = store.register(protocols=["http", "dns"])

    assert cb_id is not None
    cb = store.get(cb_id)
    assert cb["protocols"] == ["http", "dns"]
    assert cb["interactions"] == []


def test_record_interaction():
    from workers.callback.callback_store import CallbackStore

    store = CallbackStore()
    cb_id = store.register(protocols=["http"])

    store.record_interaction(cb_id, {
        "protocol": "http",
        "source_ip": "10.0.0.1",
        "data": "GET /callback/test HTTP/1.1",
    })

    cb = store.get(cb_id)
    assert len(cb["interactions"]) == 1
    assert cb["interactions"][0]["protocol"] == "http"


def test_cleanup_callback():
    from workers.callback.callback_store import CallbackStore

    store = CallbackStore()
    cb_id = store.register(protocols=["http"])
    assert store.cleanup(cb_id) is True
    assert store.get(cb_id) is None
    assert store.cleanup("nonexistent") is False
