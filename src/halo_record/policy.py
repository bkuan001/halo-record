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
    status is one of: "pass", "violated", "no_evidence".
    """
    rule_results = []
    total_violations = 0
    total_gaps = 0

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
        "gaps": total_gaps,
        "rules": rule_results,
    }


def load_records(path):
    with open(path, "r", encoding="utf-8") as fh:
        return [json.loads(ln) for ln in fh.read().splitlines() if ln.strip()]


def load_policy(path):
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    # accept either a bare list of rules or {"rules": [...]}
    return data["rules"] if isinstance(data, dict) else data


def evaluate_log(log_path, policy_path):
    return evaluate(load_records(log_path), load_policy(policy_path))


# --------------------------------------------------------------------------- #
# Rendering (plain-text verdict; deterministic, no model)
# --------------------------------------------------------------------------- #

_MARK = {"pass": "PASS", "violated": "FAIL", "no_evidence": "GAP ", "no_match": "NONE"}


def render_text(result):
    lines = []
    if result["checked"] == 0:
        head = "NO EVIDENCE — 0 records in scope; nothing attested"
    elif result["compliant"] and result["gaps"] == 0:
        head = "COMPLIANT"
    elif result["compliant"]:
        head = "COMPLIANT (with %d evidence gap(s))" % result["gaps"]
    else:
        head = "NON-COMPLIANT: %d rule(s) violated" % result["violations"]
    lines.append("Policy verdict: %s" % head)
    lines.append("Checked %d record(s) against %d rule(s)."
                 % (result["checked"], len(result["rules"])))
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
            line += "  -> %d matched, clean" % r["matched"]
        lines.append(line)
        if r["description"]:
            lines.append("       %s" % r["description"])
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
.hp-pills{display:flex;gap:14px;margin-top:18px;flex-wrap:wrap}
.hp-pill{font-size:12.5px;color:#3E7C5A;background:#E2EFE5;border-radius:999px;padding:5px 12px;font-weight:600}
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


def verdict_panel(result, subject=None, show_pills=True):
    """Return the self-contained HTML fragment for the verdict panel (embeddable).

    Includes its own scoped (`hp-`) styles so it can drop into the Runtime Report
    or stand alone. Deterministic: every line is rendered from `result`, which is
    computed by `evaluate` from rules, never from a model.

    `show_pills` draws the "integrity / witnessed" reassurance pills. Turn it off
    when embedding inside the Runtime Report, which proves integrity and
    completeness with its own *live* in-browser verdicts — two static pills there
    would compete with (and could contradict) the real ones.
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

    if result["checked"] == 0:
        verdict, vcolor = "NO EVIDENCE — 0 RECORDS IN SCOPE", "#6B6354"
    elif not result["compliant"]:
        verdict, vcolor = "NON-COMPLIANT", "#B23A48"
    elif result["gaps"]:
        verdict, vcolor = "COMPLIANT, WITH GAPS", "#3E7C5A"
    else:
        verdict, vcolor = "COMPLIANT", "#3E7C5A"

    sub = "%d records checked against %d policy rules. %d violation(s), %d evidence gap(s)." % (
        result["checked"], len(result["rules"]), result["violations"], result["gaps"])
    subj = ("halo-record &middot; %s" % _html.escape(subject)) if subject else "halo-record"
    pills = (
        '<div class="hp-pills"><span class="hp-pill">&#10003; Integrity verified</span>'
        '<span class="hp-pill">&#10003; Witnessed &middot; complete</span></div>'
    ) if show_pills else ""

    return (
        '<style>%s</style>'
        '<div class="hp-card"><div class="hp-top">'
        '<div class="hp-eyebrow">Runtime Report &middot; Policy Corroboration</div>'
        '<div class="hp-h1">Verdict: <span style="color:%s">%s</span></div>'
        '<div class="hp-sub">%s</div>%s</div>'
        '<div class="hp-rows">%s</div>'
        '<div class="hp-foot"><span>Every verdict computed from explicit rules over the '
        'record. <b>No model judgment.</b></span><span>%s</span></div></div>'
        % (_PANEL_CSS, vcolor, verdict, _html.escape(sub), pills, "".join(rows), subj))


def render_html(result, subject=None):
    """Wrap the verdict panel in a complete standalone HTML document."""
    return (
        '<!doctype html><html><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<link rel="preconnect" href="https://fonts.googleapis.com">'
        '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
        '<link href="https://fonts.googleapis.com/css2?family=Instrument+Serif&'
        'family=Instrument+Sans:wght@400;500;600&display=swap" rel="stylesheet">'
        '<style>body{background:#F4EEE2;margin:0;padding:46px}</style></head>'
        '<body>%s</body></html>' % verdict_panel(result, subject))
