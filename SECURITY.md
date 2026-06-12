# Security Policy

This project asks you to put a recorder inside your agent, so its own security posture should be inspectable and its failure modes reportable.

## Reporting a vulnerability

Email **bkuan001@gmail.com** with "halo-record security" in the subject. Include what you found, a reproduction if you have one, and how you'd like to be credited.

You will get a human reply within 48 hours. Please give us a chance to ship a fix before public disclosure; we will credit reporters in the release notes unless you prefer otherwise.

## Scope notes

- The recorder makes no network calls except the opt-in witness anchor. Anything that causes record contents to leave the host is a vulnerability.
- Raw tool arguments must never be written to a chain. Any path that lands unredacted input in a record is a vulnerability.
- Integrity claims are load-bearing: any way to alter a chain that still passes `halo verify`, or to fool a completeness check against an honest witness, is a critical finding and we would genuinely love to hear about it.
