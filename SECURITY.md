# Security Policy

This project asks you to put a recorder inside your agent, so its own security posture should be inspectable and its failure modes reportable.

## Reporting a vulnerability

Email **brian@briankuan.com** with "halo-record security" in the subject. Include what you found, a reproduction if you have one, and how you'd like to be credited.

You will get a human reply within 48 hours. Please give us a chance to ship a fix before public disclosure; we will credit reporters in the release notes unless you prefer otherwise.

## Scope notes

- The recorder makes no network calls except the four opt-in ones in PRIVACY.md (witness anchor, checkpoint fetch, RFC 3161 timestamp, and `halo serve --verify-email` SMTP delivery of a one-time code). Anything else that causes record contents to leave the host is a vulnerability.
- Tool arguments are stored as a canonical hash plus a redacted summary of at most 200 characters. A short argument that matches no secret or PII pattern appears in that summary as written; hash-only mode (`summaries=False`) stores no summary (LIMITS §6, §13). Any path that stores argument text beyond that summary, or a value the scanner detects without masking it, is a vulnerability.
- Integrity claims are load-bearing: any way to alter a chain that still passes `halo verify`, or to fool a completeness check against a witness that follows the protocol, is a critical finding and we would genuinely love to hear about it.
- Records are written after the action runs. A failed write passes the action's result through and is reported on stderr (or the `halo_record` logger when there is no stderr). Strict mode (`HALO_STRICT_RECORDING=1`) writes the same line and then raises, where the framework lets an error reach the caller; LIMITS §18 lists each wrapper. A path that loses a record without that report is a vulnerability.
