"""RFC 3161 trusted timestamping — an independence increment for checkpoints.

A witness checkpoint records ``(chain_root, count, head, ts)``, but ``ts`` is the
recorder's *own* clock — an operator can backdate it. RFC 3161 replaces that
self-asserted time with a proof from a Timestamp Authority (TSA) the operator
does not control: the TSA cryptographically binds the checkpoint's hash to a real
time, so "this chain reached this head no later than T" becomes verifiable by a
third party. No hosted infrastructure — a public TSA is enough.

Consistent with the rest of the package, this stays **stdlib-only**: it builds
the ASN.1/DER TimeStampReq by hand, POSTs it to the TSA over ``urllib``, and does
a light check (the returned token timestamps *our* digest, and at what time). It
deliberately does NOT verify the TSA's signature or certificate chain — that
needs asymmetric crypto and belongs outside the zero-dependency core. The token
is a standard artifact, so anyone can verify it in full with an off-the-shelf
tool and never touch this library. The token is the base64 ``tsa.token_b64`` in
the witness log; the digest it covers is ``tsa.digest``. base64-decode the token
into a file (``token.tsr``) and:

    openssl ts -verify -digest <tsa.digest> -in token.tsr -CAfile tsa-ca.pem

(``certReq`` is set, so the token embeds the signing cert; a TSA that does not
embed it needs an extra ``-untrusted tsa.crt``.)

That is the point: a third-party time proof, checkable with third-party tools.
This binds a checkpoint's *state* — it proves the chain reached that state no
later than the attested time; individual records' ``ts`` fields stay
self-asserted, and completeness is still the witness's job, not the clock's.
"""

import urllib.request
from datetime import datetime, timezone

DEFAULT_TSA_URL = "https://freetsa.org/tsr"  # free, RFC 3161; point at a
# commercial TSA (DigiCert / Sectigo / your own) for production.

# RFC 3161 tokens are a few KB. Cap the response read so a malicious or
# man-in-the-middled TSA cannot OOM the recorder with a huge body.
_MAX_TSA_RESPONSE = 1 << 21  # 2 MiB

_SHA256_OID = "2.16.840.1.101.3.4.2.1"


# --------------------------------------------------------------------------- #
# Minimal DER encoding (stdlib)
# --------------------------------------------------------------------------- #
def _der_len(n):
    if n < 0x80:
        return bytes([n])
    out = bytearray()
    while n:
        out.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(out)]) + bytes(out)


def _tlv(tag, body):
    return bytes([tag]) + _der_len(len(body)) + body


def _der_int(i):
    if i == 0:
        body = b"\x00"
    else:
        b = bytearray()
        while i:
            b.insert(0, i & 0xFF)
            i >>= 8
        if b[0] & 0x80:            # keep it a positive integer
            b.insert(0, 0)
        body = bytes(b)
    return _tlv(0x02, body)


def _der_oid(oid):
    parts = [int(x) for x in oid.split(".")]
    body = bytearray([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        stack = [p & 0x7F]
        p >>= 7
        while p:
            stack.insert(0, (p & 0x7F) | 0x80)
            p >>= 7
        body.extend(stack)
    return _tlv(0x06, bytes(body))


def _der_seq(*parts):
    return _tlv(0x30, b"".join(parts))


def _message_imprint(digest):
    """MessageImprint ::= SEQUENCE { hashAlgorithm, hashedMessage }."""
    algo = _der_seq(_der_oid(_SHA256_OID), _tlv(0x05, b""))  # SHA-256, NULL params
    return _der_seq(algo, _tlv(0x04, digest))


def build_request(digest, *, cert_req=True):
    """A DER-encoded RFC 3161 TimeStampReq over ``digest`` (32 bytes, SHA-256).
    ``cert_req`` asks the TSA to embed its certificate so the token verifies
    offline."""
    parts = [_der_int(1), _message_imprint(digest)]        # version v1, imprint
    if cert_req:
        parts.append(_tlv(0x01, b"\xFF"))                  # certReq BOOLEAN TRUE
    return _der_seq(*parts)


def request_token(digest_hex, tsa_url=DEFAULT_TSA_URL, *, timeout=20):
    """Ask ``tsa_url`` to timestamp ``digest_hex`` and return the raw DER
    TimeStampResp (which carries the timeStampToken). Network call — this is the
    one place the package reaches out, and only when a caller opts into it."""
    digest = bytes.fromhex(digest_hex)
    req = build_request(digest)
    http = urllib.request.Request(
        tsa_url, data=req,
        headers={"Content-Type": "application/timestamp-query",
                 "Content-Length": str(len(req))},
    )
    with urllib.request.urlopen(http, timeout=timeout) as resp:
        body = resp.read(_MAX_TSA_RESPONSE + 1)
    if len(body) > _MAX_TSA_RESPONSE:
        raise ValueError("TSA response exceeds %d bytes; refusing" % _MAX_TSA_RESPONSE)
    return body


# --------------------------------------------------------------------------- #
# Light verification (stdlib) — imprint match + attested time
# --------------------------------------------------------------------------- #
def _read_tlv(data, i):
    tag = data[i]
    j = i + 1
    length = data[j]
    j += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[j:j + n], "big")
        j += n
    return tag, data[j:j + length], j + length


def _parse_gentime(raw):
    """GeneralizedTime 'YYYYMMDDHHMMSS[.fff]Z' → ISO-8601 UTC string."""
    s = raw.decode("ascii").rstrip("Z")
    frac = ""
    if "." in s:
        s, frac = s.split(".", 1)
    dt = datetime.strptime(s, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    iso = dt.isoformat().replace("+00:00", "Z")
    return iso if not frac else iso[:-1] + "." + frac.rstrip("0") + "Z"


def verify(token_der, expected_digest_hex):
    """Light, dependency-free check of an RFC 3161 token:

    - ``imprint_ok``: the token timestamps *exactly* our checkpoint digest (the
      TSA signed this chain state, not some other).
    - ``gen_time``: the time the TSA attested (ISO-8601 UTC), or None.

    This does NOT validate the TSA's signature or certificate — that requires
    asymmetric crypto and is the job of ``openssl ts -verify``. On its own this
    check confirms the token binds *our* chain state and reads its claimed time;
    only a full openssl verify against a trusted TSA turns that claim into a
    third-party proof."""
    digest = bytes.fromhex(expected_digest_hex)
    imprint = _message_imprint(digest)
    idx = token_der.find(imprint)
    if idx < 0:
        return {"imprint_ok": False, "gen_time": None}
    # In TSTInfo the messageImprint is followed by serialNumber (INTEGER) then
    # genTime (GeneralizedTime, tag 0x18).
    gen_time = None
    try:
        tag, _body, after_serial = _read_tlv(token_der, idx + len(imprint))
        if tag == 0x02:
            tag2, body2, _ = _read_tlv(token_der, after_serial)
            if tag2 == 0x18:
                gen_time = _parse_gentime(body2)
    except (IndexError, ValueError):
        pass
    return {"imprint_ok": True, "gen_time": gen_time}
