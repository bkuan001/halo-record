"""Regression tests for private-key block masking, mask hygiene, hash-only
records, and internal-IP range coverage."""

from halo_record.record import build
from halo_record.redact import redact_text, scan

PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n"
    "MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\n"
    "MIIEfakefakefake\n"
    "-----END PRIVATE KEY-----"
)


def test_full_pem_block_is_masked():
    out = redact_text("key follows " + PEM + " end")
    assert "[PRIVATE KEY REDACTED]" in out
    # No fragment of the key body survives — not the long lines, not the short one.
    assert "MIIEvQIBADAN" not in out
    assert "MIIEfakefakefake" not in out
    assert "BEGIN PRIVATE KEY" not in out
    assert "END PRIVATE KEY" not in out


def test_truncated_pem_masks_body_too():
    out = redact_text("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj\nshortline\nand then prose continues here")
    assert "BEGIN PRIVATE KEY" not in out
    assert "MIIEvQIBADAN" not in out
    assert "shortline" not in out
    assert "prose continues here" in out  # non-base64 text after the body survives


def test_mask_is_scanner_quiet_and_idempotent():
    mask = "[PRIVATE KEY REDACTED]"
    assert scan(mask) == []
    assert redact_text(mask) == mask


def test_record_summary_carries_no_key_material():
    rec = build("tool_call", "security", tool="deploy",
                tool_input={"pem": PEM}, session_id="s")
    summary = rec["action"]["input"]["summary"]
    assert "MIIE" not in summary
    assert "BEGIN PRIVATE KEY" not in summary


def test_hash_only_records_have_no_samples_or_summaries():
    rec = build("tool_call", "security", tool="pay",
                tool_input={"ssn": "123-45-6789", "email": "jane@example.com"},
                outcome={"status": "ok", "summary": "sent to jane@example.com"},
                summaries=False, session_id="s")
    assert "summary" not in rec["action"]["input"]
    assert "summary" not in rec.get("outcome", {})
    assert rec["findings"], "scanner should still classify"
    for f in rec["findings"]:
        assert "sample" not in f
        assert "type" in f and "severity" in f


def test_internal_ip_covers_172_16_slash_12():
    hits = {f["type"] for f in scan("hosts: 172.16.0.1 172.31.9.9 172.15.0.1 172.32.0.1")}
    assert "ip_internal" in hits
    out = redact_text("172.16.0.1 172.31.9.9 172.15.0.1 172.32.0.1")
    assert "172.16.0.1" not in out          # lower bound: masked
    assert "172.31.9.9" not in out          # upper bound: masked
    assert "172.15.0.1" in out              # below range: untouched
    assert "172.32.0.1" in out              # above range: untouched
