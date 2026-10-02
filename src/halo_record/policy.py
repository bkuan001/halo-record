"""Policy corroboration: check recorded agent activity against declared policy.

Deterministic and dependency-free. Reads a Halo log plus a declarative policy
(rules over record fields) and returns a per-rule verdict: which records comply,
which violate, and which policy expectations have NO supporting evidence in the
log at all.

This is EVALUATIVE, not enforcement. It judges records after the fact; it never
blocks an action. Real-time blocking would put Halo in the operator-side
enforcement lane it deliberately stays out of. Because every verdict is computed
from explicit rules over fields (never from a model), it is safe to let this
carry a report's headline claim.

A policy is a list of rules. A rule is a plain dict, so policies can be authored
as JSON/YAML and shipped by a vendor (self-check), a buyer (their contract), or a
framework (AIUC-1 / EU AI Act control sets):

    {
      "id": "refunds-need-human",
      "description": "Any refund must be human-approved.",
      "severity": "HIGH",
      "when":   {"action.tool": "issue_refund"},
      "forbid": {"action.authorization.decision": {"ne": "human_approved"}}
    }

Rule semantics:
  - "when"    selects the records the rule applies to (default: every record).
  - "forbid"  a selected record that ALSO matches this is a violation.
  - "require" a selected record that does NOT match this is a violation.
  - "expect_evidence": true  -> if NO record matches "when", that is a coverage
                               gap ("the policy declares a control the log shows
                               no evidence of"). This is what lets corroboration
                               apply pressure even to thin, pulled ("silver")
                               logs.

Matchers (a condition is {field_path: matcher}; all paths must hold):
  scalar            equality
  {"eq": x}         equals x
  {"ne": x}         not equal to x (a MISSING field counts as not-equal)
  {"in": [...]}     value is one of
  {"nin": [...]}    value is none of
  {"contains": x}   value is a list containing x  (e.g. data.pii_types)
  {"exists": bool}  field is present / absent
  {"gt"|"gte"|"lt"|"lte": n}   numeric comparison

Field paths are dotted. Use "[]" to fan out across an array of objects and match
existentially, e.g. "findings[].severity" or "threats[].type".
"""

import json
import os

_MISSING = object()


# --------------------------------------------------------------------------- #
# Field resolution
# --------------------------------------------------------------------------- #

def _resolve(node, parts):
    """Resolve a dotted path to the list of values it reaches.

    Returns [] when the path is absent. A segment ending in "[]" (e.g.
    "findings[]") descends into that key and fans out across the list, so
    matching against the remaining path is existential and may return several
    values.
    """
    if not parts:
        return [node]
    head, rest = parts[0], parts[1:]
    fan = head.endswith("[]")
    key = head[:-2] if fan else head

    if key:
        if isinstance(node, dict) and key in node:
            node = node[key]
        else:
            return []

    if fan:
        if not isinstance(node, list):
            return []
        out = []
        for item in node:
            out.extend(_resolve(item, rest))
        return out

    return _resolve(node, rest)


def _match(values, spec):
    """True if ANY resolved value satisfies the matcher spec."""
    if isinstance(spec, dict):
        for op, arg in spec.items():
            if op == "exists":
                ok = (len(values) > 0) == bool(arg)
            elif op == "eq":
                ok = arg in values
            elif op == "ne":
                ok = arg not in values            # MISSING -> [] -> not-equal
            elif op == "in":
                ok = any(v in arg for v in values)
            elif op == "nin":
                ok = not any(v in arg for v in values)
            elif op == "contains":
                ok = any(isinstance(v, list) and arg in v for v in values)
            elif op == "gt":
                ok = any(_num(v) is not None and _num(v) > arg for v in values)
            elif op == "gte":
                ok = any(_num(v) is not None and _num(v) >= arg for v in values)
            elif op == "lt":
                ok = any(_num(v) is not None and _num(v) < arg for v in values)
            elif op == "lte":
                ok = any(_num(v) is not None and _num(v) <= arg for v in values)
            else:
                raise ValueError("unknown matcher operator: %r" % op)
            if not ok:
                return False
        return True
    # bare scalar -> equality
    return spec in values


def _num(v):
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return v
    return None


def _holds(record, condition):
    """A condition is {path: matcher}; every path must hold (AND)."""
    for path, spec in condition.items():
        values = _resolve(record, path.split("."))
        if not _match(values, spec):
            return False
    return True


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #

RULE_KEYS = ("id", "description", "severity", "source", "when", "forbid",
             "require", "expect_evidence")
POLICY_KEYS = ("name", "version", "note", "description", "rules", "$schema")
SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
_OPS = {"eq", "ne", "in", "nin", "contains", "exists", "gt", "gte", "lt", "lte"}

FORMAT_HELP = """\
policy format: a JSON list of rules, or {"rules": [...]} (optional "name",
"version", "note"). Each rule:
  id               required; a short name
  description      what the rule asserts
  severity         INFO | LOW | MEDIUM | HIGH | CRITICAL (default MEDIUM)
  source           who declared it (vendor / buyer / framework control id)
  when             {field: matcher} selecting records (default: every record)
  forbid           a selected record that matches this is a violation
  require          a selected record that does not match this is a violation
  expect_evidence  true: no selected record at all is an evidence gap
Every rule needs forbid, require, or expect_evidence. Unknown keys, unknown
matchers, and field paths that are not Runtime Record fields are rejected.
Fields are dotted record paths; "[]" fans out over a list
(findings[].type, threats[].type). Matchers: a bare value (equality), or
{"eq"|"ne"|"in"|"nin"|"contains"|"exists"|"gt"|"gte"|"lt"|"lte": value}.
Bundled packs (run by name): %s. Full guide: examples/policies/README.md in
the source repository."""


def _schema_props():
    try:
        from .verify import load_schema
        return load_schema()
    except (OSError, ValueError):
        return None


def _check_path(path, schema, where):
    if not isinstance(path, str) or not path or any(not p for p in path.split(".")):
        raise ValueError("%s: field path %r is not a dotted record path" % (where, path))
    node = schema
    for part in path.split("."):
        key = part[:-2] if part.endswith("[]") else part
        if node is None:
            return
        if node.get("type") == "array" and isinstance(node.get("items"), dict):
            node = node["items"]
        props = node.get("properties")
        if not props:
            return  # free-form beneath this point
        if key not in props:
            raise ValueError("%s: %r is not a Runtime Record field (in %r; known here: %s)"
                             % (where, key, path, ", ".join(sorted(props))))
        node = props[key]


def _check_condition(cond, schema, where):
    if not isinstance(cond, dict) or not cond:
        raise ValueError("%s: must be a non-empty object of {field: matcher}" % where)
    for path, spec in cond.items():
        _check_path(path, schema, where)
        if isinstance(spec, dict):
            if not spec:
                raise ValueError("%s: empty matcher for %r" % (where, path))
            for op, arg in spec.items():
                if op not in _OPS:
                    raise ValueError("%s: unknown matcher %r for %r (known: %s)"
                                     % (where, op, path, ", ".join(sorted(_OPS))))
                if op in ("in", "nin") and not isinstance(arg, list):
                    raise ValueError("%s: %r needs a list for %r" % (where, op, path))
                if op == "exists" and not isinstance(arg, bool):
                    raise ValueError("%s: 'exists' needs true or false for %r" % (where, path))
                if op in ("gt", "gte", "lt", "lte") and (
                        isinstance(arg, bool) or not isinstance(arg, (int, float))):
                    raise ValueError("%s: %r needs a number for %r" % (where, op, path))


def validate_policy(rules):
    """Reject a policy that could not mean what it says. A misspelled key, an
    unknown matcher, a field path that is not a record field, or a rule with
    nothing to check would otherwise evaluate to a PASS that asserts nothing."""
    if not isinstance(rules, list) or not rules:
        raise ValueError("policy: expected a non-empty list of rules")
    schema = _schema_props()
    seen = set()
    for n, rule in enumerate(rules, start=1):
        where = "policy rule %d" % n
        if not isinstance(rule, dict):
            raise ValueError("%s: must be an object" % where)
        if isinstance(rule.get("id"), str) and rule["id"]:
            where = "policy rule %r" % rule["id"]
        else:
            raise ValueError("%s: needs a non-empty string \"id\"" % where)
        if rule["id"] in seen:
            raise ValueError("%s: duplicate rule id" % where)
        seen.add(rule["id"])
        unknown = sorted(set(rule) - set(RULE_KEYS))
        if unknown:
            raise ValueError("%s: unknown key(s) %s (known: %s)"
                             % (where, ", ".join(map(repr, unknown)), ", ".join(RULE_KEYS)))
        if "forbid" not in rule and "require" not in rule and rule.get("expect_evidence") is not True:
            raise ValueError("%s: has nothing to check — give it forbid, require, or "
                             "\"expect_evidence\": true" % where)
        if "expect_evidence" in rule and not isinstance(rule["expect_evidence"], bool):
            raise ValueError("%s: expect_evidence must be true or false" % where)
        if "severity" in rule and rule["severity"] not in SEVERITIES:
            raise ValueError("%s: severity %r is not one of %s"
                             % (where, rule["severity"], ", ".join(SEVERITIES)))
        for k in ("description", "source"):
            if k in rule and not isinstance(rule[k], str):
                raise ValueError("%s: %s must be a string" % (where, k))
        for k in ("when", "forbid", "require"):
            if k in rule:
                _check_condition(rule[k], schema, "%s %s" % (where, k))
    return rules


# --------------------------------------------------------------------------- #
# Evaluation
# --------------------------------------------------------------------------- #

def evaluate(records, policy):
    """Evaluate a list of record dicts against a policy (list of rule dicts).

    Returns a dict:
      {
        "compliant": bool,                # no violations (gaps reported apart)
        "checked":   <record count>,
        "violations": <count>,
        "gaps":       <count>,
        "rules": [ {id, description, severity, status, matched, violators[]}, ... ]
      }
    status is one of: "pass", "violated", "no_evidence", "no_match".
    The policy is validated first; an invalid one raises ValueError.
    """
    validate_policy(policy)
    rule_results = []
    total_violations = 0
    total_gaps = 0
    total_no_match = 0
    violating = set()

    for rule in policy:
        when = rule.get("when", {})
        forbid = rule.get("forbid")
        require = rule.get("require")
        expect = rule.get("expect_evidence", False)

        matched = 0
        violators = []
        for rec in records:
            if when and not _holds(rec, when):
                continue
            matched += 1
            bad = False
            if forbid is not None and _holds(rec, forbid):
                bad = True
            if require is not None and not _holds(rec, require):
                bad = True
            if bad:
                violators.append(rec.get("record_id", "?"))
                violating.add(id(rec))

        if violators:
            status = "violated"
            total_violations += 1
        elif expect and matched == 0:
            status = "no_evidence"
            total_gaps += 1
        elif matched == 0 and (forbid is not None or require is not None):
            # A rule that would have checked something, but no record fell in
            # its scope. Rendering this as a pass would be an evidence gap
            # wearing a green light; say plainly that nothing was attested.
            status = "no_match"
            total_no_match += 1
        else:
            status = "pass"

        rule_results.append({
            "id": rule.get("id", "?"),
            "description": rule.get("description", ""),
            "severity": rule.get("severity", "MEDIUM"),
            "source": rule.get("source", ""),     # optional: vendor / buyer / framework
            "status": status,
            "matched": matched,
            "violators": violators,
        })

    return {
        "compliant": total_violations == 0,
        "checked": len(records),
        "violations": total_violations,
        # distinct records out of policy, across every violated rule — the
        # number to set beside "violations" (which counts rules)
        "violating_records": len(violating),
        "gaps": total_gaps,
        "unexercised": total_no_match,
        "rules": rule_results,
    }


def load_records(path):
    with open(path, "r", encoding="utf-8") as fh:
        return [json.loads(ln) for ln in fh.read().split("\n") if ln.strip()]


_PACK_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "policies")


def bundled_packs():
    """Names of the starter packs shipped inside the package."""
    try:
        return sorted(n[:-5] for n in os.listdir(_PACK_DIR) if n.endswith(".json"))
    except OSError:
        return []


def resolve_policy_path(path):
    """A policy file path, or the name of a bundled pack (``owasp-starter``)."""
    if os.path.exists(path):
        return path
    name = os.path.basename(path)
    name = name[:-5] if name.endswith(".json") else name
    if path in (name, name + ".json") and name in bundled_packs():
        return os.path.join(_PACK_DIR, name + ".json")
    return path


def load_policy(path):
    """Load and validate a policy file (or a bundled pack by name)."""
    with open(resolve_policy_path(path), "r", encoding="utf-8") as fh:
        try:
            data = json.load(fh)
        except ValueError as e:
            raise ValueError("policy %s is not valid JSON (%s)" % (path, e))
    # accept either a bare list of rules or {"rules": [...]}
    if isinstance(data, dict):
        unknown = sorted(set(data) - set(POLICY_KEYS))
        if unknown:
            raise ValueError("policy %s: unknown top-level key(s) %s (known: %s)"
                             % (path, ", ".join(map(repr, unknown)), ", ".join(POLICY_KEYS)))
        if "rules" not in data:
            raise ValueError("policy %s: an object policy needs a \"rules\" list" % path)
        data = data["rules"]
    return validate_policy(data)


def evaluate_log(log_path, policy_path, *, start=None, end=None, expected_subject=None):
    """Evaluate a policy over a log, but only after the log verifies: a verdict
    computed over records that fail verification is not attestable.

    ``start``/``end`` (aware datetimes, inclusive) limit the records evaluated
    to a review window; the whole chain is still verified. ``expected_subject``
    refuses (ValueError) a chain carrying any other subject id."""
    from .verify import verify_log
    chain_verified = verify_log(log_path, out=lambda *_a, **_k: None)
    policy = load_policy(policy_path)
    try:
        records = load_records(log_path)
    except Exception:
        if chain_verified:
            raise
        records = None
    if records is not None and expected_subject is not None:
        from .report import _record_subject
        found = sorted({json.dumps(_record_subject(r) if isinstance(r, dict) else None)
                        for r in records})
        if found != [json.dumps(expected_subject)]:
            raise ValueError("%s: chain subject id(s) %s are not exactly the expected %s"
                             % (log_path, ", ".join(found), json.dumps(expected_subject)))
    if records is not None and (start is not None or end is not None):
        from .export import in_window
        records = [r for r in records if isinstance(r, dict) and in_window(r, start, end)]
    try:
        if records is None:
            raise ValueError("unreadable records")
        result = evaluate(records, policy)
    except Exception:
        if chain_verified:
            raise
        # An unverifiable log may not even have record shapes to evaluate.
        result = {"compliant": False, "checked": 0, "violations": 0, "gaps": 0,
                  "violating_records": 0, "unexercised": 0, "rules": []}
    result["chain_verified"] = chain_verified
    if not chain_verified:
        result["compliant"] = False
    if start is not None or end is not None:
        result["window"] = {"from": start.isoformat() if start else None,
                            "to": end.isoformat() if end else None}
    if expected_subject is not None:
        result["expected_subject"] = expected_subject
    return result


def _counts_line(result):
    unex = result.get("unexercised", 0)
    return ("%d record(s) checked against %d rule(s): %d rule(s) violated by %d record(s), "
            "%d evidence gap(s), %d rule(s) not exercised." % (
                result["checked"], len(result["rules"]), result["violations"],
                result.get("violating_records", 0), result["gaps"], unex))


# --------------------------------------------------------------------------- #
# Rendering (plain-text verdict; deterministic, no model)
# --------------------------------------------------------------------------- #

_MARK = {"pass": "PASS", "violated": "FAIL", "no_evidence": "GAP ", "no_match": "NONE"}


def render_text(result):
    lines = []
    unex = result.get("unexercised", 0)
    if result.get("chain_verified") is False:
        head = ("NON-ATTESTABLE — the log did not verify; a policy verdict over "
                "records that fail verification attests nothing (run halo verify)")
    elif result["checked"] == 0:
        head = "NO EVIDENCE — 0 records in scope; nothing attested"
    elif unex == len(result["rules"]):
        head = "NO APPLICABLE EVIDENCE — records exist but none fall in any rule's scope"
    elif not result["compliant"]:
        head = "NON-COMPLIANT: %d rule(s) violated by %d record(s)" % (
            result["violations"], result.get("violating_records", 0))
    else:
        head = "COMPLIANT"
        notes = []
        if result["gaps"]:
            notes.append("%d evidence gap(s)" % result["gaps"])
        if unex:
            notes.append("%d rule(s) not exercised" % unex)
        if notes:
            head += " (" + ", ".join(notes) + ")"
    lines.append("Policy verdict: %s" % head)
    lines.append(_counts_line(result))
    lines.append("")
    # exceptions first, routine collapsed (mirrors the report UX doctrine)
    order = {"violated": 0, "no_evidence": 1, "no_match": 2, "pass": 3}
    for r in sorted(result["rules"], key=lambda x: order[x["status"]]):
        line = "[%s] %s  (%s)" % (_MARK[r["status"]], r["id"], r["severity"])
        if r["status"] == "violated":
            line += "  -> %d record(s): %s" % (
                len(r["violators"]),
                ", ".join(r["violators"][:5]) + (" ..." if len(r["violators"]) > 5 else ""))
        elif r["status"] == "no_evidence":
            line += "  -> policy declares this control; log shows no evidence"
        elif r["status"] == "no_match":
            line += "  -> no records in scope — nothing attested"
        else:
            line += "  -> %d matched, none flagged" % r["matched"]
        lines.append(line)
        if r["description"]:
            lines.append("       %s" % r["description"])
    if result["checked"] and result["compliant"]:
        lines.append("")
        lines.append("Scope: a PASS means no flagged item was found in scope for "
                     "that rule — it corroborates over the fields the record "
                     "carries and the scanner's named categories, not an "
                     "independent claim that a secret, PII, or threat is absent.")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# HTML rendering (the Runtime Report verdict panel; deterministic, no model)
# --------------------------------------------------------------------------- #

import html as _html

_HTML_META = {
    "violated":    ("FAIL", "#B23A48", "#F7E4E6"),
    "no_evidence": ("GAP",  "#9A6A00", "#F6ECCF"),
    "pass":        ("PASS", "#3E7C5A", "#E2EFE5"),
    "no_match":    ("NONE", "#6B6354", "#EFEDE7"),
}

_PANEL_CSS = """
.hp-card{max-width:760px;margin:0 auto;background:#FCFAF4;border:1px solid #E6DCC8;
 border-radius:18px;overflow:hidden;box-shadow:0 18px 50px rgba(80,60,20,.10);
 font-family:"Instrument Sans",system-ui,sans-serif;color:#2A2622}
.hp-top{padding:30px 36px 22px;border-bottom:1px solid #EFE7D6}
.hp-eyebrow{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:#A98C4B;font-weight:600}
.hp-h1{font-family:"Instrument Serif",Georgia,serif;font-weight:400;font-size:33px;margin:9px 0 4px}
.hp-sub{font-size:14.5px;line-height:1.5;color:#6B6354;max-width:600px;margin-top:7px}
.hp-rows{padding:12px 18px 18px}
.hp-row{display:flex;gap:15px;padding:15px 18px;border-bottom:1px solid #F1EAD9}
.hp-row:last-child{border-bottom:none}
.hp-badge{flex:0 0 auto;align-self:flex-start;font-size:11px;font-weight:700;letter-spacing:.08em;
 padding:5px 9px;border-radius:7px;margin-top:2px;min-width:46px;text-align:center}
.hp-rh{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.hp-rid{font-family:"Instrument Serif",Georgia,serif;font-size:19px}
.hp-sev{font-size:11px;font-weight:600;letter-spacing:.05em;color:#7A6E58;border:1px solid #E0D6C0;border-radius:6px;padding:2px 7px}
.hp-src{font-size:11.5px;color:#A98C4B;font-weight:600}
.hp-desc{font-size:14px;color:#4A4438;margin-top:5px;line-height:1.45}
.hp-detail{font-size:13px;color:#857B68;margin-top:4px}
.hp-foot{padding:15px 36px 24px;border-top:1px solid #EFE7D6;font-size:12.5px;color:#9A8F79;
 display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap}
.hp-foot b{color:#6B6354;font-weight:600}
"""


def verdict_panel(result, subject=None):
    """Return the self-contained HTML fragment for the verdict panel (embeddable).

    Includes its own scoped (`hp-`) styles so it can drop into the Runtime Report
    or stand alone. Deterministic: every line is rendered from `result`, which is
    computed by `evaluate` from rules, never from a model.

    Deliberately renders no static "integrity verified / witnessed" pills.
    When embedded in the Runtime Report, that page proves integrity and
    completeness with its own live in-browser verdicts; a static pill would
    only compete with — and could contradict — the real one.
    """
    order = {"violated": 0, "no_evidence": 1, "no_match": 2, "pass": 3}
    rows = []
    for r in sorted(result["rules"], key=lambda x: order[x["status"]]):
        tag, fg, bg = _HTML_META[r["status"]]
        if r["status"] == "violated":
            detail = "%d record(s) out of policy: %s" % (
                len(r["violators"]), ", ".join(r["violators"]))
        elif r["status"] == "no_evidence":
            detail = "Policy declares this control. The log contains no evidence of it."
        elif r["status"] == "no_match":
            detail = "No records in scope — nothing attested."
        else:
            detail = "%d matching action(s), all within policy." % r["matched"]
        src = ('<span class="hp-src">%s</span>' % _html.escape(r["source"])) if r["source"] else ""
        rows.append(
            '<div class="hp-row">'
            '<div class="hp-badge" style="color:%s;background:%s">%s</div>'
            '<div><div class="hp-rh"><span class="hp-rid">%s</span>'
            '<span class="hp-sev">%s</span>%s</div>'
            '<div class="hp-desc">%s</div><div class="hp-detail">%s</div></div></div>'
            % (fg, bg, tag, _html.escape(r["id"]), _html.escape(r["severity"]), src,
               _html.escape(r["description"]), _html.escape(detail)))

    if result.get("chain_verified") is False:
        verdict, vcolor = "NON-ATTESTABLE — LOG DID NOT VERIFY", "#B23A48"
    elif result["checked"] == 0:
        verdict, vcolor = "NO EVIDENCE — 0 RECORDS IN SCOPE", "#6B6354"
    elif result.get("unexercised", 0) == len(result["rules"]):
        verdict, vcolor = "NO APPLICABLE EVIDENCE — NO RULES EXERCISED", "#6B6354"
    elif not result["compliant"]:
        verdict, vcolor = "NON-COMPLIANT", "#B23A48"
    elif result["gaps"]:
        # a declared control with no evidence is an open item, not a pass
        verdict, vcolor = "COMPLIANT, WITH GAPS", "#9A6A00"
    else:
        verdict, vcolor = "COMPLIANT", "#3E7C5A"

    sub = _counts_line(result)
    subj = ("halo-record &middot; %s" % _html.escape(subject)) if subject else "halo-record"

    return (
        '<style>%s</style>'
        '<div class="hp-card"><div class="hp-top">'
        '<div class="hp-eyebrow">Runtime Report &middot; Policy Corroboration</div>'
        '<div class="hp-h1">Verdict: <span style="color:%s">%s</span></div>'
        '<div class="hp-sub">%s</div></div>'
        '<div class="hp-rows">%s</div>'
        '<div class="hp-foot"><span>%s <b>No model judgment.</b></span><span>%s</span></div></div>'
        % (_PANEL_CSS, vcolor, verdict, _html.escape(sub), "".join(rows),
           _html.escape(_FOOT), subj))


_FOOT = ("Each verdict is computed by deterministic rules over the record fields, "
         "when this panel was generated.")


def render_html(result, subject=None):
    """Wrap the verdict panel in a complete standalone HTML document."""
    return (
        '<!doctype html><html><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<style>body{background:#F4EEE2;margin:0;padding:46px}</style></head>'
        '<body>%s</body></html>' % verdict_panel(result, subject))
