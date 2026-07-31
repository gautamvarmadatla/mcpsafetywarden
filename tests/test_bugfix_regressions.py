"""Regression tests for fixed bugs that exercise LLM-dependent paths with mocks.

These cover code that CI otherwise skips (no API key), so the fixes for null LLM
verdicts, confidence coercion, and encryption plaintext fallback stay fixed.
"""

import asyncio

import pytest

from mcpsafetywarden.scan import args as argsmod


def _run(coro):
    return asyncio.run(coro)


def test_arg_llm_null_verdict_fails_closed(monkeypatch):
    monkeypatch.setattr(argsmod, "_call_llm_scanner", lambda *a, **k: '{"is_attack": null, "confidence": null}')
    result = _run(
        argsmod.scan_args_for_threats("run", {"cmd": "; rm -rf /"}, llm_provider="anthropic", llm_api_key="x")
    )
    assert result is not None


def test_arg_llm_string_confidence_does_not_crash(monkeypatch):
    monkeypatch.setattr(argsmod, "_call_llm_scanner", lambda *a, **k: '{"is_attack": true, "confidence": "0.9"}')
    result = _run(
        argsmod.scan_args_for_threats("run", {"cmd": "; rm -rf /"}, llm_provider="anthropic", llm_api_key="x")
    )
    assert result is not None


def test_arg_llm_clears_false_positive(monkeypatch):
    monkeypatch.setattr(
        argsmod, "_call_llm_scanner", lambda *a, **k: '{"is_attack": false, "confidence": 0.9, "reason": "benign"}'
    )
    result = _run(
        argsmod.scan_args_for_threats("run", {"path": "../../etc/passwd"}, llm_provider="anthropic", llm_api_key="x")
    )
    assert result is None


def test_arg_scan_no_llm_needs_review():
    result = _run(argsmod.scan_args_for_threats("run", {"cmd": "; rm -rf /"}))
    assert result is not None
    assert result.get("needs_review") is True


def test_decrypt_field_preserves_pre_encryption_plaintext(monkeypatch):
    pytest.importorskip("cryptography")
    from cryptography.fernet import Fernet

    from mcpsafetywarden.core import database as db

    monkeypatch.setattr(db, "_fernet", Fernet(Fernet.generate_key()))
    plaintext = '{"api_key": "abc123"}'
    assert db._decrypt_field(plaintext) == plaintext

    real = db._fernet.encrypt(b'{"x": 1}').decode()
    assert db._decrypt_field(real) == '{"x": 1}'

    monkeypatch.setattr(db, "_fernet", Fernet(Fernet.generate_key()))
    assert db._decrypt_field(real) == "{}"
