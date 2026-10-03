"""Render one tenant's runtime record as a shareable web page whose script
re-computes the embedded records' hash chain in the viewer's browser.

``halo report customer.jsonl -o customer.html`` produces a single self-contained
HTML file (no build step, no external JS) that:

  * presents what the agent did — every recorded action, its authorization,
    scope, and outcome — as a procurement-facing Runtime Report, and
  * re-verifies the hash chain in the *viewer's own browser* (SHA-256 over
    RFC 8785 canonical JSON, mirroring the Python verifier), so the reader
    confirms tamper-evidence themselves without trusting any server.

It renders exactly one chain — i.e. one ``subject``/customer — so a report is
safe to share with that customer and no other (segmentation by construction).
"""

import json
import re
import os

from .canon import GENESIS_PREV
from .anchor import chain_root as _chain_root
from .verify import read_log_lines
from . import _view


def _load(path):
    from .verify import parse_record_line
    lines = read_log_lines(path)
    records = []
    for n, ln in enumerate(lines, start=1):
        try:
            records.append(parse_record_line(ln))
        except (ValueError, RecursionError) as e:
            raise ValueError(
                "record %d is not readable (%s) — run `halo verify %s` for "
                "the full picture" % (n, e, path)) from e
    return records


_LONE_SURROGATE_RE = re.compile("[\ud800-\udfff]")


def _record_subject(r):
    """A record's subject id as a comparable value; ids that are not plain
    strings or numbers (chain data is untrusted) are serialized, never raised on."""
    s = r.get("subject")
    sid = (s.get("id") or None) if isinstance(s, dict) else None
    if sid is None or isinstance(sid, (str, int, float, bool)):
        return sid
    return json.dumps(sid, sort_keys=True, default=str)


# What the page displays is derived from its records in one place (``_view``),
# mirrored by the page's own JavaScript so the browser re-renders it from the
# records it verifies. These names are kept for existing callers.
_subject_note = _view.subject_note
_subject_label = _view.subject_label
_subject_id = _view.subject_id
_agents = _view.agents
_agent_meta = _view.agent_meta
_fmt_ts = _view.fmt_ts
_summary_stats = _view.stats
_esc = _view.esc
_CAP_TITLE = _view.CAP_TITLE
_PLAIN_VERB = _view.PLAIN_VERB
_PLAIN_KEYS = _view.PLAIN_KEYS
_plain = _view.plain
_row = _view.row


def chain_breaks(records):
    """Indices of records whose sealed hash or predecessor link does not hold.

    Operates on a list rather than a file so a *window* can be verified on its
    own terms: each record's hash is recomputed against the predecessor it
    declares, and consecutive records must link. A window legitimately starts
    mid-chain, so the first record's `prev_hash` is taken as its anchor and is
    not compared to genesis — anchoring the window to the wider chain is a
    separate claim, made by the witness, not by this function.
    """
    from .canon import compute_hash
    bad = []
    for i, r in enumerate(records):
        integ = r.get("integrity") or {}
        declared_prev = integ.get("prev_hash")
        try:
            recomputed = compute_hash(r, declared_prev)
        except (ValueError, TypeError):
            recomputed = None
        if recomputed is None or integ.get("hash") != recomputed:
            bad.append(i)
        elif i and declared_prev != ((records[i - 1].get("integrity") or {}).get("hash")):
            bad.append(i)
    return bad


_ANCHOR_RE = re.compile(r"^[0-9a-f]{64}$")


def _js_anchor(anchor):
    """A chain anchor as a JavaScript string literal. The anchor comes from the
    chain itself, so it is treated as untrusted: it must be a 64-character
    lowercase SHA-256 hex digest, and it is serialized, never interpolated."""
    if not isinstance(anchor, str) or not _ANCHOR_RE.match(anchor):
        raise ValueError("halo-record: chain anchor is not a SHA-256 hex digest; "
                         "refusing to render the report")
    return json.dumps(anchor)

_VERIFY_JS = r"""
const GENESIS = %(genesis)s;
const WINDOW = %(window_json)s;
// A lone surrogate is hashed as U+FFFD, as the Python and TypeScript verifiers
// do; JSON.stringify would otherwise write it as a \\u escape and disagree.
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g;
function canonStr(s){ return JSON.stringify(s.replace(LONE_SURROGATE, "\ufffd")); }
function canon(v){
  if (v === true) return "true";
  if (v === false) return "false";
  if (v === null) return "null";
  const t = typeof v;
  if (t === "string") return canonStr(v);
  if (t === "number") return String(v);
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  if (t === "object") {
    const keys = Object.keys(v).sort();
    return "{" + keys.map(k => canonStr(k) + ":" + canon(v[k])).join(",") + "}";
  }
  throw new Error("cannot canonicalize");
}
function hex(buf){
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}
async function recordHash(rec, prev){
  const clone = JSON.parse(JSON.stringify(rec));
  clone.integrity = clone.integrity || {};
  clone.integrity.prev_hash = prev;
  delete clone.integrity.hash;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canon(clone)));
  return hex(digest);
}
async function verify(records){
  let prev = GENESIS;
  for (let i = 0; i < records.length; i++){
    const r = records[i], integ = r.integrity || {};
    if (integ.prev_hash !== prev) return {ok:false, at:i+1, why:"chain break (prev_hash)"};
    const got = await recordHash(r, prev);
    if (got !== integ.hash) return {ok:false, at:i+1, why:"hash mismatch"};
    prev = integ.hash;
  }
  return {ok:true, head:prev};
}
function repeatedKey(text){
  // The first key repeated in one object of the records JSON (at any depth),
  // and the record (1-based) that holds it; null if none. halo verify refuses
  // such a line: parsers disagree on which value wins, so it can carry text
  // the hash never covered. Assumes text is JSON that JSON.parse accepted.
  const stack = [];
  let i = 0, item = 1;
  const n = text.length;
  while (i < n){
    const c = text[i];
    if (c === '"'){
      let j = i + 1;
      while (text[j] !== '"'){ if (text[j] === "\\") j++; j++; }
      const top = stack.length ? stack[stack.length - 1] : null;
      if (top && top.obj && top.expectKey){
        const key = JSON.parse(text.slice(i, j + 1));
        if (top.keys.has(key)) return {at: item, key: key};
        top.keys.add(key);
        top.expectKey = false;
      }
      i = j + 1;
      continue;
    }
    if (c === "{") stack.push({obj: true, keys: new Set(), expectKey: true});
    else if (c === "[") stack.push({obj: false});
    else if (c === "}" || c === "]") stack.pop();
    else if (c === ","){
      const top = stack.length ? stack[stack.length - 1] : null;
      if (top && top.obj) top.expectKey = true;
      else if (stack.length === 1) item++;
    }
    i++;
  }
  return null;
}
async function verifyText(text){
  // Verify the records as embedded: a repeated key fails before any hashing.
  const records = JSON.parse(text);
  const dup = repeatedKey(text);
  if (dup) return {ok:false, at:dup.at, why:"duplicate key " + JSON.stringify(dup.key) + " in one object"};
  return verify(records);
}
function cleanCheckpoints(list){
  // Checkpoints arrive from the page or from a witness URL the report names, so
  // they are untrusted: keep only well-formed {count: positive integer, head:
  // SHA-256 hex} entries before any of them reaches a verdict.
  return (Array.isArray(list) ? list : []).filter(function(c){
    return c && typeof c === "object" && Number.isInteger(c.count) && c.count >= 1 &&
           typeof c.head === "string" && /^[0-9a-f]{64}$/.test(c.head);
  });
}
function witnessBase(url){
  // Only an https witness (or http on this machine, for local testing) is fetched.
  try {
    const u = new URL(String(url));
    if (u.username || u.password) return null;  // "https://known.example@other.example" is refused
    const local = u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "[::1]";
    if (u.protocol === "https:" || (u.protocol === "http:" && local))
      return u.origin + u.pathname.replace(/\/+$/, "");
  } catch (e){}
  return null;
}
function completeness(records, cps){
  // Assumes the chain already verified. Mirrors anchor.verify_completeness:
  // every head the notary independently witnessed must still be present here.
  // In a windowed report only the checkpoints that land inside the window can
  // be re-checked in the browser; the ones before/beyond it are disclosed.
  if (!cps.length) return {ok:null};
  let latest = 0;
  for (const c of cps) if (c.count > latest) latest = c.count;
  if (!WINDOW && records.length < latest)
    return {ok:false, why:"truncated below witnessed length", have:records.length, witnessed:latest};
  // A window is cut from a chain of WINDOW.total records; a witness holding a
  // longer chain means records exist that this report's source chain lacks.
  if (WINDOW && latest > WINDOW.total)
    return {ok:false, why:"the witness holds " + latest + " records but this report was cut from a " +
            WINDOW.total + "-record chain", have:WINDOW.total, witnessed:latest};
  let inWin = 0, before = 0, beyond = 0;
  for (const c of cps){
    const n = c.count;
    if (WINDOW){
      if (n < WINDOW.first){ before++; continue; }
      if (n > WINDOW.last){ beyond++; continue; }
      const h = (records[n - WINDOW.first].integrity || {}).hash;
      if (h !== c.head) return {ok:false, why:"record altered or dropped before witnessed point", at:n};
      inWin++;
    } else {
      if (n < 1 || n > records.length) return {ok:false, why:"witnessed count out of range", at:n};
      const h = (records[n-1].integrity || {}).hash;
      if (h !== c.head){
        const root = (records[0].integrity || {}).hash;
        const other = (typeof c.chain_root === "string" && c.chain_root !== root);
        return {ok:false, at:n, why:"record altered or dropped before witnessed point" +
          (other ? "; the witness holds this checkpoint for a different chain root under the same subject" +
                   " (a second or restarted chain, or this chain was re-rooted)" : "")};
      }
    }
  }
  if (WINDOW && !inWin)
    return {ok:null, windowed:true, before:before, beyond:beyond, latest:latest};
  return {ok:true, witnessed:cps.length, latest:latest, inWin:inWin, before:before, beyond:beyond};
}
async function liveCheckpoints(cfg, embedded){
  // Completeness must be checked against the notary, not against checkpoints the
  // vendor embedded in (and served with) this page. When a hosted Halo witness
  // is configured, fetch its checkpoints directly (CORS-open) so the verdict
  // rests on a party the vendor doesn't control. Fall back to the embedded
  // snapshot only if the live witness is unreachable.
  if (!cfg.witnessUrl) return {cps: cleanCheckpoints(embedded), live: false, error: null};
  const base = witnessBase(cfg.witnessUrl);
  if (!base) return {cps: cleanCheckpoints(embedded), live: false, error: "witness URL must be https"};
  try {
    const q = cfg.subject ? "subject=" + encodeURIComponent(cfg.subject)
            : (cfg.chainRoot ? "chain_root=" + encodeURIComponent(cfg.chainRoot) : null);
    if (!q) return {cps: cleanCheckpoints(embedded), live: false, error: "no subject or chain root to look up"};
    const u = base + "/v1/checkpoints?" + q;
    const resp = await fetch(u, {mode: "cors"});
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    // Read as halo's own clients read it: a key repeated in one object is
    // refused, since parsers disagree on which of its values wins.
    const text = await resp.text();
    const data = JSON.parse(text);
    const dup = repeatedKey(text);
    if (dup) throw new Error("the witness response repeats the key " + JSON.stringify(dup.key) +
                             " (duplicate key in one object)");
    return {cps: cleanCheckpoints(data.checkpoints), live: true, error: null};
  } catch (e){
    return {cps: cleanCheckpoints(embedded), live: false, error: e.message};
  }
}
function haloSet(id, html){
  const node = document.getElementById(id);
  if (node) node.innerHTML = html;
}
function haloRefuseLayout(problem){
  // A layout refusal is kept for the life of the page.
  window.__haloLayoutRefused = true;
  const copies = (document.querySelectorAll && document.querySelectorAll('[id="verdict"]')) || [];
  const one = document.getElementById("verdict");
  const targets = copies.length ? Array.prototype.slice.call(copies) : (one ? [one] : []);
  targets.forEach(function(v){
    v.className = "verdict fail";
    v.innerHTML = "&#10007; Not verified &mdash; " + haloEsc(problem.why) +
      " Run halo verify on the JSONL instead.";
  });
  haloWithhold(problem.why);
  const cel = document.getElementById("completeness");
  if (cel){ cel.className = "verdict fail"; cel.innerHTML = "Completeness not checked: " + haloEsc(problem.why); }
}
function haloLayoutProblem(){
  // An edited page can repeat an element id these scripts write to (a hidden
  // copy placed first takes the verified content while a visible copy keeps
  // static text), or hide the regions they write to with page CSS. Either way
  // what shows is not what was verified, so the page withholds.
  const all = (document.querySelectorAll && document.querySelectorAll("[id]")) || [];
  const seen = {}, dups = [];
  for (let i = 0; i < all.length; i++){
    const id = all[i].id;
    if (!id) continue;
    if (seen[id] && dups.indexOf(id) < 0) dups.push(id);
    seen[id] = true;
  }
  if (dups.length)
    return {ids: dups, early: true, why: "this page repeats the element id" + (dups.length > 1 ? "s " : " ") +
            dups.map(function(d){ return JSON.stringify(d); }).join(", ") +
            ", so what it shows cannot be tied to the verified records."};
  if (typeof window.getComputedStyle !== "function") return null;
  // A hidden document, or a viewport too small to show the regions (a frame
  // or preview pane collapsed to a few pixels, a frame loaded at zero height),
  // says nothing about what the reader is shown: the check waits for a
  // viewport that can show them.
  if (haloLayoutWaits()) return {wait: true};
  // Every region whose content the badge or the scripts vouch for.
  const watched = ["verdict", "completeness", "r-h1", "r-meta", "r-period", "r-cards",
                   "tablewrap", "activity-body", "rowcount"];
  for (let i = 0; i < watched.length; i++){
    const n = document.getElementById(watched[i]);
    if (!n || typeof n.getClientRects !== "function") continue;
    if (haloHidden(n))
      return {ids: [watched[i]], why: "this page hides the region (#" + watched[i] + ") the verifier " +
              "writes to, so what it shows cannot be tied to the verified records."};
  }
  return null;
}
function haloFlat(transform){
  // A transform that collapses the box (scale(0) and the like).
  const m = /^matrix(3d)?\(([^)]*)\)$/.exec(String(transform).trim());
  if (!m) return false;
  const v = m[2].split(",").map(parseFloat);
  const det = m[1] ? v[0] * v[5] - v[1] * v[4] : v[0] * v[3] - v[1] * v[2];
  return !(Math.abs(det) >= 0.01);
}
function haloLayoutWaits(){
  if (document.visibilityState === "hidden") return true;
  const w = window.innerWidth, h = window.innerHeight;
  return typeof w === "number" && typeof h === "number" && (w < 100 || h < 100);
}
function haloHidden(n){
  // Not displayed, invisible, without area, off the page, or under an
  // ancestor that clips, masks, filters, flattens or skips it. Page CSS can
  // still mislead in ways computed layout does not show (see LIMITS.md).
  if (n.getClientRects().length === 0) return true;
  const own = getComputedStyle(n);
  if (own.visibility !== "visible") return true;
  const sized = /\S/.test(n.textContent || "") && typeof n.getBoundingClientRect === "function";
  const r = sized ? n.getBoundingClientRect() : null;
  if (r){
    if (!(r.width >= 1 && r.height >= 1)) return true;
    const sx = window.scrollX || window.pageXOffset || 0;
    const sy = window.scrollY || window.pageYOffset || 0;
    const vw = (document.documentElement && document.documentElement.clientWidth) || window.innerWidth || 0;
    if (r.right + sx <= 0 || r.bottom + sy <= 0 || (vw > 0 && r.left + sx >= vw)) return true;
  }
  for (let p = n; p && p.nodeType === 1; p = p.parentElement){
    const cs = p === n ? own : getComputedStyle(p);
    if (r && p !== document.documentElement && p !== document.body &&
        (cs.overflowX !== "visible" || cs.overflowY !== "visible")){
      // A clipping box with no room inside, or (when it does not scroll)
      // one the region lies wholly outside of.
      if (!(p.clientWidth >= 1 && p.clientHeight >= 1)) return true;
      if (/^(hidden|clip)$/.test(cs.overflowX) && /^(hidden|clip)$/.test(cs.overflowY) && p !== n){
        const b = p.getBoundingClientRect();
        if (r.right <= b.left || r.left >= b.right || r.bottom <= b.top || r.top >= b.bottom) return true;
      }
    }
    if (parseFloat(cs.opacity) === 0) return true;
    if (cs.clipPath && cs.clipPath !== "none") return true;
    const mask = cs.maskImage || cs.webkitMaskImage;
    if (mask && mask !== "none") return true;
    if (cs.filter && cs.filter !== "none") return true;
    if (cs.contentVisibility && cs.contentVisibility !== "visible") return true;
    if (cs.transform && cs.transform !== "none" && haloFlat(cs.transform)) return true;
  }
  return false;
}
async function haloBind(records, cfg){
  // Re-render everything the page derives from its records, from the records
  // this script just verified, so edited static HTML cannot show under the badge.
  if (typeof HaloView === "undefined") return false;
  // The page carries the policy file's exact text; its SHA-256 is what
  // `shasum -a 256 <policy file>` prints, and the rules are parsed from it here.
  const polEl = document.getElementById("halo-policy");
  let text = null, rules = null, digest = null, polErr = null;
  try {
    text = polEl ? JSON.parse(polEl.textContent || "null") : null;
    if (text !== null){
      if (typeof text !== "string") throw new Error("the embedded policy is not policy text");
      digest = hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
      // Read exactly as `halo policy` reads the file: a repeated key, a
      // non-finite number, an unknown top-level key or an invalid rule is
      // refused here, so the page never shows a verdict the CLI would refuse.
      if (typeof HaloView.parsePolicyText !== "function") throw new Error("this page cannot read a policy");
      const read = HaloView.parsePolicyText(text);
      if (read.error !== null) throw new Error(read.error);
      rules = read.rules;
    }
  } catch (e){ polErr = e.message; rules = null; }
  const chainOk = WINDOW ? cfg.chainVerified !== false : true;
  const R = HaloView.regions(records, rules, chainOk, digest);
  let policy = "none";
  if (polErr !== null){
    R.policy = "<div class='verdict fail'>Policy verdict withheld &mdash; the policy embedded in this page " +
               "is not a valid policy (" + haloEsc(polErr) + ").</div>";
    policy = "invalid";
  } else if (text === null){
    R.policy = "<div class='verdict neutral'>No policy is embedded in this page; no policy verdict is shown.</div>";
  } else {
    policy = R.policyEvaluated ? "ok" : "invalid";
  }
  haloSet("r-h1", R.h1);
  haloSet("r-meta", R.meta);
  haloSet("r-subject-note", R.subject_note);
  haloSet("r-period", R.period);
  haloSet("r-cards", R.cards);
  haloSet("r-scopes", R.scopes);
  haloSet("r-provenance", R.provenance);
  haloSet("r-policy", R.policy);
  try { document.title = R.title + " — Runtime Report"; } catch (e){}
  if (typeof window.__haloSetRows === "function") window.__haloSetRows(R.rows);
  else {
    // The table script has not run yet. Leave it these rows to take as the
    // whole table, so it never adds the page's static rows to them.
    window.__haloPendingRows = R.rows;
    haloSet("activity-body", R.rows.join("\n"));
  }
  return {policy: policy, digest: digest};
}
function haloWithhold(why){
  // Nothing derived from unverified records is presented as if it verified.
  const msg = "<div class='verdict fail'>Withheld &mdash; " + why + " The table below is the page's " +
              "unverified static text.</div>";
  window.__haloWithheld = msg;  // the table's row counter keeps showing this
  haloSet("r-policy", document.getElementById("halo-policy") &&
          document.getElementById("halo-policy").textContent.trim() !== "null"
          ? "<div class='verdict fail'>Policy verdict withheld &mdash; " + why + "</div>" : "");
  haloSet("r-cards", "");
  haloSet("rowcount", msg);
}
function haloEsc(s){
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
async function haloCompleteness(records, embedded, cfg, pinned){
  const cel = document.getElementById("completeness");
  if (!cel || window.__haloLayoutRefused) return;
  const lookup = pinned || cfg.subject;
  const pinNote = pinned
    ? ""
    : (cfg.subject
        ? " <span class='dim'>Subject not pinned: looked up by the id the records carry (" +
          haloEsc(JSON.stringify(cfg.subject)) + "), which the vendor writes. Enter the customer id " +
          "you expect below to check against that id instead.</span>"
        : "");
  if (pinned){
    const ids = new Set(records.map(function(r){
      const s = r.subject; return (s && typeof s === "object" && s.id) ? s.id : null; }));
    if (ids.size !== 1 || !ids.has(pinned)){
      cel.className = "verdict fail";
      cel.innerHTML = "&#10007; SUBJECT MISMATCH &mdash; you expect " + haloEsc(JSON.stringify(pinned)) +
        "; the records carry " + haloEsc(JSON.stringify(Array.from(ids))) + ".";
      return;
    }
  }
  const pinnedEmbedded = (Array.isArray(embedded) ? embedded : []).filter(function(c){
    return !(c && typeof c === "object" && "subject" in c && c.subject !== null) || c.subject === lookup;
  });
  const src = await liveCheckpoints({witnessUrl: cfg.witnessUrl, subject: lookup, chainRoot: cfg.chainRoot},
                                    pinnedEmbedded);
  let comp;
  try {
    comp = completeness(records, src.cps);
  } catch (e){
    comp = {ok:false, why:"completeness could not be checked (" + e.message + ")"};
  }
  const witness = src.live ? "the live witness log" : "the witness log embedded in this report";
  const note = (src.error
    ? " <span class='dim'>(couldn't reach the live witness — checked the embedded snapshot instead)</span>"
    : "") + pinNote;
  const forWho = pinned ? " for " + haloEsc(JSON.stringify(pinned)) : "";
  if (window.__haloLayoutRefused) return;
  if (comp.ok === null && comp.windowed){
    cel.className = "verdict neutral";
    cel.innerHTML = "No witness checkpoint" + forWho + " falls inside this window — window integrity is " +
      "verified against its anchor above" +
      (comp.beyond ? "; the witness holds " + comp.beyond + " checkpoint(s) beyond this window, up to record " +
                     comp.latest + " of the " + WINDOW.total + "-record chain" : "") +
      (comp.before ? "; " + comp.before + " checkpoint(s) precede the window and cannot be checked from this page (run halo anchor --check on the full chain)" : "") +
      "." + note;
  } else if (comp.ok === null){
    cel.className = "verdict open";
    cel.innerHTML = "<b>Not yet anchored" + forWho + ".</b> No witness checkpoint was found — " +
      "completeness rests on the vendor alone until the chain is witnessed. " +
      "Integrity is verified above; completeness is not." + note;
  } else if (comp.ok && WINDOW){
    cel.className = "verdict neutral";
    cel.innerHTML = (src.live
        ? "Consistent within window" + forWho + " &mdash; "
        : "Self-attested" + forWho + " &mdash; the checkpoint was supplied with this report by its operator, so treat completeness as self-attested until a witness outside the operator confirms it. Within the window it is consistent: ") +
      witness + " confirmed " + comp.inWin +
      " checkpoint(s) inside this window" +
      (comp.beyond ? "; chain continues beyond the window (witnessed to record " + comp.latest + ")" : "") +
      (comp.before ? "; " + comp.before + " earlier checkpoint(s) precede it" : "") +
      ". No witnessed record in this window has been dropped or altered." +
      (src.live
        ? " Whether this counts as independent verification depends on who operates the witness at " + haloEsc(String(witnessBase(cfg.witnessUrl) || "the configured URL")) + " &mdash; treat it as self-attested unless that party is outside the operator's control."
        : "") + note;
  } else if (comp.ok){
    cel.className = "verdict neutral";
    cel.innerHTML = (src.live
        ? "Consistent" + forWho + " &mdash; "
        : "Self-attested" + forWho + " &mdash; the checkpoint was supplied with this report by its operator, so treat completeness as self-attested until a witness outside the operator confirms it. Against that checkpoint the chain is consistent: ") +
      witness + " confirmed " + comp.witnessed +
      " checkpoint(s) up to record " + comp.latest +
      ". No record the witness saw has been dropped or altered." +
      (src.live
        ? " Whether this counts as independent verification depends on who operates the witness at " + haloEsc(String(witnessBase(cfg.witnessUrl) || "the configured URL")) + " &mdash; treat it as self-attested unless that party is outside the operator's control."
        : "") + note;
  } else {
    cel.className = "verdict fail";
    cel.innerHTML = "&#10007; INCOMPLETE" + forWho + " &mdash; conflicts with " + witness + " (" +
      haloEsc(comp.why) + (comp.at ? " at record " + comp.at : "") + ")." + note;
  }
}
(async function(){
  // Check the page as parsed in full: static markup after this script (a
  // style rule, a repeated id) is in place before anything is judged.
  if (document.readyState === "loading")
    await new Promise(function(r){ document.addEventListener("DOMContentLoaded", r, {once: true}); });
  const el = document.getElementById("verdict");
  const recordsText = document.getElementById("records").textContent;
  const records = JSON.parse(recordsText);
  const embedded = JSON.parse(document.getElementById("checkpoints").textContent);
  const cfg = JSON.parse(document.getElementById("halo-config").textContent);
  const cel = document.getElementById("completeness");
  // A repeated id refuses here, before anything is written. A hidden region
  // is checked once the verified content is in place, below.
  const problem = haloLayoutProblem();
  if (problem && problem.early){ haloRefuseLayout(problem); return; }
  if (!(window.crypto && crypto.subtle)){
    el.className = "verdict neutral";
    el.innerHTML = "Not verified &mdash; self-verification needs a secure context (https or localhost). " +
      "Nothing on this page has been checked; run halo verify on the JSONL instead.";
    haloWithhold("this browser could not verify the records.");
    return;
  }
  try {
    if (!records.length){
      el.className = "verdict neutral";
      el.innerHTML = "0 records — an empty chain; nothing to attest.";
      await haloBind(records, cfg);
      if (cel){ cel.className = "verdict neutral"; cel.innerHTML = "No records to check for completeness."; }
      return;
    }
    const res = await verifyText(recordsText);
    window.__haloVerify = res;  // the drawer's chain-position note reads this
    if (!res.ok){
      el.className = "verdict fail";
      el.innerHTML = "&#10007; Verification FAILED at record " + res.at + " (" + haloEsc(res.why) + ").";
      haloWithhold("the records embedded in this page failed verification.");
      if (cel){ cel.className = "verdict fail"; cel.innerHTML = "Completeness not checked: the records failed verification."; }
      return;
    }
    const bound = await haloBind(records, cfg);
    let shown = "";
    if (bound){
      shown = " This page's scripts re-rendered the table and summary from the verified " +
              "records; the page's styling and any added content are not checked &mdash; " +
              "run <span class='mono'>halo verify</span> on the JSONL for evidence.";
      if (bound.policy === "ok")
        shown += " The policy verdict was re-computed from them under the policy embedded in this page " +
                 "by whoever generated it (sha256 <span class='mono'>" + bound.digest.slice(0, 16) +
                 "&hellip;</span>; compare with <span class='mono'>shasum -a 256</span> of the policy file you hold).";
    }
    const limit = " <span class='dim'>Integrity relative to this head only: compare it with a head you hold " +
      "(a witness checkpoint, or <span class='mono'>halo verify</span> on the JSONL). This page runs code " +
      "supplied with the report.</span>";
    el.className = "verdict ok";
    if (WINDOW){
      el.innerHTML = "&#10003; Verified in your browser — records " + WINDOW.first +
        "&ndash;" + WINDOW.last + " of " + WINDOW.total +
        ", window chain intact from its anchor to window head <span class='mono'>" +
        res.head.slice(0,16) + "&hellip;</span>." + shown + limit;
    } else {
      el.innerHTML = "&#10003; Verified in your browser — " + records.length +
        " records, hash chain intact from the first record to head <span class='mono'>" +
        res.head.slice(0,16) + "&hellip;</span>." + shown + limit;
    }
  } catch (e){
    el.className = "verdict fail";
    el.textContent = "Verification error: " + e.message;
    haloWithhold("the records could not be verified.");
    return;
  }
  // Stylesheets that finish loading later, animations and transitions, and
  // print can still hide what was written, so check again on each, and about
  // once a second for changes that fire no event.
  // A refusal is kept for the life of the page. While the viewport is too
  // small to show the regions, or the document is hidden, the check waits.
  const recheck = function(){
    if (window.__haloLayoutRefused) return;
    const p = haloLayoutProblem();
    if (p && !p.wait) haloRefuseLayout(p);
  };
  recheck();
  if (window.__haloLayoutRefused) return;
  if (typeof window.addEventListener === "function"){
    if (document.readyState !== "complete") window.addEventListener("load", recheck);
    window.addEventListener("beforeprint", recheck);
    window.addEventListener("resize", recheck);
    document.addEventListener("visibilitychange", recheck);
    ["animationstart", "animationiteration", "animationend", "transitionend"].forEach(function(t){
      document.addEventListener(t, recheck, true);
    });
  }
  // The periodic check runs at a random time in each 0.5-1.5 s, so an
  // animation cannot keep a region visible at every check by matching its
  // period to the check's.
  if (typeof window.setTimeout === "function" && typeof window.getComputedStyle === "function"){
    const tick = function(){
      recheck();
      if (!window.__haloLayoutRefused) window.setTimeout(tick, 500 + Math.random() * 1000);
    };
    window.setTimeout(tick, 500 + Math.random() * 1000);
  }
  let pinned = cfg.expectedSubject || null;
  try {
    const m = /(?:^#|&)expect=([^&]*)/.exec(String((window.location && window.location.hash) || ""));
    if (m) pinned = decodeURIComponent(m[1]) || pinned;
  } catch (e){}
  const input = document.getElementById("pin-subject");
  if (input && pinned) input.value = pinned;
  await haloCompleteness(records, embedded, cfg, pinned);
  const form = document.getElementById("pin");
  if (form && form.addEventListener) form.addEventListener("submit", function(ev){
    ev.preventDefault();
    const v = input ? String(input.value).trim() : "";
    haloCompleteness(records, embedded, cfg, v || null);
  });
})();
"""


# Activity rows are rendered newest-first. The first batch sits in the table;
# the rest wait in an inert <template> and stream in as the reader scrolls, so
# the page stays responsive on multi-thousand-record chains while row rendering
# stays entirely in Python (the template holds ready-made rows, not data).
_ROW_BATCH = 100

_PAGINATE_JS = r"""
(function(){
  var tbody = document.getElementById("activity-body");
  var tpl = document.getElementById("more-rows");
  var wrap = document.getElementById("tablewrap");
  var counter = document.getElementById("rowcount");
  var sentinel = document.getElementById("more-sentinel");
  if (!tbody || !tpl || !wrap || !sentinel) return;
  var BATCH = 100;

  /* One array owns every row; the table body is a rendered view of the
     filtered+sorted subset. Rows never go back into the template. */
  var ALL = [];
  function rowsOf(rowsHtml){
    var t = document.createElement("template");
    t.innerHTML = rowsHtml.join("");
    return Array.prototype.slice.call(t.content.querySelectorAll("tr"));
  }
  if (Array.isArray(window.__haloPendingRows)){
    // Verification finished first: the table is the re-rendered verified
    // rows only; the static rows (table and template) are not read.
    ALL = rowsOf(window.__haloPendingRows);
    window.__haloPendingRows = null;
  } else {
    Array.prototype.push.apply(ALL, tbody.querySelectorAll("tr"));
    Array.prototype.push.apply(ALL, tpl.content.querySelectorAll("tr"));
  }
  ALL = ALL.filter(function(r){ return r.hasAttribute("data-ts"); });
  tpl.remove();
  if (!ALL.length) return;

  var view = ALL.slice();     // current filtered+sorted set
  var drawn = 0;              // how many of `view` are in the DOM

  /* The verifier re-renders the rows from the records it verified and hands
     them over here; from then on the table is that set, not the static one. */
  window.__haloSetRows = function(rowsHtml){
    ALL = rowsOf(rowsHtml);
    fillOptions(fTool, "data-tool");
    fillOptions(fType, "data-type");
    paintTimes();
    apply();
  };

  /* --- local time -------------------------------------------------------
     Records are sealed in UTC. A reader investigating "what happened at 3pm"
     means their own 3pm, so the displayed time follows the viewer's clock by
     default, with UTC one click away. The underlying record is untouched. */
  // UTC first: the frame of the period line and the static rows. Local time
  // is a toggle, labeled with the viewer's zone while shown.
  var localMode = false;
  var TZ = "";
  try {
    TZ = Intl.DateTimeFormat().resolvedOptions().timeZone || "";
  } catch (e) { TZ = ""; }
  function pad(n){ return (n < 10 ? "0" : "") + n; }
  function stamp(iso){
    if (!localMode) return (typeof HaloView !== "undefined") ? HaloView.fmtTs(iso) : String(iso).slice(0, 19);
    var d = new Date(iso);
    if (isNaN(d)) return String(iso).slice(0, 19);
    return d.getFullYear() + "-" + pad(d.getMonth()+1) + "-" + pad(d.getDate()) + " " +
           pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  }
  function paintTimes(){
    for (var i = 0; i < ALL.length; i++){
      var cell = ALL[i].querySelector(".ts-cell");
      if (cell) cell.textContent = stamp(ALL[i].getAttribute("data-ts"));
    }
    var th = document.getElementById("th-time");
    if (th) th.firstChild.textContent = localMode
      ? ("Time (" + (TZ || "local") + ")") : "Time (UTC)";
    var btn = document.getElementById("tz-toggle");
    if (btn) btn.textContent = localMode ? "Show UTC" : "Show local time";
  }

  /* --- filtering -------------------------------------------------------- */
  var q = document.getElementById("f-q");
  var fTool = document.getElementById("f-tool");
  var fType = document.getElementById("f-type");
  var fSev = document.getElementById("f-sev");
  var fFrom = document.getElementById("f-from");
  var fTo = document.getElementById("f-to");
  var fFlags = document.getElementById("f-flags");
  var fReset = document.getElementById("f-reset");

  function fillOptions(sel, attr){
    if (!sel) return;
    while (sel.options.length > 1) sel.remove(1);
    var seen = {}, vals = [];
    for (var i = 0; i < ALL.length; i++){
      var v = ALL[i].getAttribute(attr);
      if (v && !seen[v]){ seen[v] = 1; vals.push(v); }
    }
    vals.sort();
    for (var j = 0; j < vals.length; j++){
      var o = document.createElement("option");
      // The value stays as recorded (rows are matched on it); the label
      // marks an invisible character, as the row cells do.
      o.value = vals[j]; o.textContent = shownId(vals[j]);
      sel.appendChild(o);
    }
  }
  fillOptions(fTool, "data-tool");
  fillOptions(fType, "data-type");

  /* Datetime-local inputs are read in the same frame as the displayed time,
     so a range typed against local timestamps selects what the reader sees. */
  function bound(input){
    if (!input || !input.value) return null;
    var d = localMode ? new Date(input.value) : new Date(input.value + "Z");
    return isNaN(d) ? null : d.getTime();
  }
  function matches(row){
    if (q && q.value.trim()){
      var terms = q.value.toLowerCase().split(/\s+/);
      var hay = row.getAttribute("data-text") || "";
      for (var i = 0; i < terms.length; i++)
        if (terms[i] && hay.indexOf(terms[i]) === -1) return false;
    }
    if (fTool && fTool.value && row.getAttribute("data-tool") !== fTool.value) return false;
    if (fType && fType.value && row.getAttribute("data-type") !== fType.value) return false;
    if (fSev && fSev.value && row.getAttribute("data-sev") !== fSev.value) return false;
    if (fFlags && fFlags.checked && row.getAttribute("data-flags") === "0") return false;
    var lo = bound(fFrom), hi = bound(fTo);
    if (lo !== null || hi !== null){
      var t = new Date(row.getAttribute("data-ts")).getTime();
      if (isNaN(t)) return false;
      if (lo !== null && t < lo) return false;
      if (hi !== null && t > hi) return false;
    }
    return true;
  }

  /* --- sorting ---------------------------------------------------------- */
  var sortKey = "data-ts", sortDir = -1;   // newest first, as rendered
  function cmp(a, b){
    var av = a.getAttribute(sortKey) || "", bv = b.getAttribute(sortKey) || "";
    if (sortKey === "data-flags"){ av = +av; bv = +bv; }
    if (sortKey === "data-ts"){
      // Sort by instant, not by text: offsets and precision vary across records.
      // Seconds and their microseconds are compared exactly (HaloView.cmpTs);
      // a timestamp that does not parse sorts as the oldest.
      var ta = (typeof HaloView !== "undefined") ? HaloView.tsUtc(av) : null,
          tb = (typeof HaloView !== "undefined") ? HaloView.tsUtc(bv) : null;
      if (ta && tb){
        var c = HaloView.cmpTs(ta, tb);
        return c < 0 ? -sortDir : (c > 0 ? sortDir : 0);
      }
      av = ta ? 1 : 0;
      bv = tb ? 1 : 0;
    }
    if (sortKey === "data-sev"){
      var rank = {INFO:0, LOW:1, MEDIUM:2, HIGH:3, CRITICAL:4};
      av = rank[av] === undefined ? -1 : rank[av];
      bv = rank[bv] === undefined ? -1 : rank[bv];
    }
    if (av < bv) return -sortDir;
    if (av > bv) return sortDir;
    return 0;
  }

  function render(){
    tbody.textContent = "";
    drawn = 0;
    draw();
    if (wrap) wrap.scrollTop = 0;
  }
  function draw(){
    var frag = document.createDocumentFragment();
    var end = Math.min(drawn + BATCH, view.length);
    for (var i = drawn; i < end; i++) frag.appendChild(view[i]);
    tbody.appendChild(frag);
    drawn = end;
    update();
  }
  function update(){
    if (!counter) return;
    // Once the page has withheld its verdict, the notice that the table is
    // unverified static text stays, whatever the table does next.
    if (window.__haloWithheld){ counter.innerHTML = window.__haloWithheld; return; }
    var filtered = view.length !== ALL.length;
    counter.textContent = "Showing " + drawn + " of " + view.length + " actions" +
      (filtered ? " (filtered from " + ALL.length + ")" : "") +
      (drawn < view.length ? " — scroll the table for more" : "");
  }
  function apply(){
    view = ALL.filter(matches);
    view.sort(cmp);
    render();
  }

  var heads = document.querySelectorAll("th[data-sort]");
  for (var h = 0; h < heads.length; h++){
    (function(th){
      th.setAttribute("tabindex", "0");
      th.setAttribute("role", "button");
      th.setAttribute("aria-sort", th.getAttribute("data-active") === "desc" ? "descending" : "none");
      var activate = function(){
        var key = th.getAttribute("data-sort");
        if (sortKey === key) sortDir = -sortDir;
        else { sortKey = key; sortDir = (key === "data-ts") ? -1 : 1; }
        for (var k = 0; k < heads.length; k++){
          heads[k].removeAttribute("data-active");
          heads[k].setAttribute("aria-sort", "none");
        }
        th.setAttribute("data-active", sortDir > 0 ? "asc" : "desc");
        th.setAttribute("aria-sort", sortDir > 0 ? "ascending" : "descending");
        apply();
      };
      th.addEventListener("click", activate);
      th.addEventListener("keydown", function(e){
        if (e.key === "Enter" || e.key === " " || e.key === "Spacebar"){
          e.preventDefault();
          activate();
        }
      });
    })(heads[h]);
  }

  var inputs = [q, fTool, fType, fSev, fFrom, fTo, fFlags];
  for (var n = 0; n < inputs.length; n++){
    if (!inputs[n]) continue;
    inputs[n].addEventListener(inputs[n] === q ? "input" : "change", apply);
  }
  if (fReset) fReset.addEventListener("click", function(){
    if (q) q.value = "";
    if (fTool) fTool.value = "";
    if (fType) fType.value = "";
    if (fSev) fSev.value = "";
    if (fFrom) fFrom.value = "";
    if (fTo) fTo.value = "";
    if (fFlags) fFlags.checked = false;
    apply();
  });
  var tz = document.getElementById("tz-toggle");
  if (tz) tz.addEventListener("click", function(){
    localMode = !localMode;
    paintTimes();
    apply();
  });

  if ("IntersectionObserver" in window){
    var io = new IntersectionObserver(function(entries){
      for (var i = 0; i < entries.length; i++)
        if (entries[i].isIntersecting && drawn < view.length){ draw(); break; }
    }, {root: wrap, rootMargin: "600px"});
    io.observe(sentinel);
  } else {
    wrap.addEventListener("scroll", function(){
      if (drawn < view.length &&
          wrap.scrollTop + wrap.clientHeight > wrap.scrollHeight - 600) draw();
    });
  }

  /* --- record detail ----------------------------------------------------
     A row is a summary; the record is the evidence. Clicking a row opens the
     whole sealed record — every field, the findings that matched, and the
     hash linkage a reader can check by hand against the JSONL. */
  var RECORDS = [];
  try {
    RECORDS = JSON.parse(document.getElementById("records").textContent) || [];
  } catch (e) { RECORDS = []; }
  var byId = new Map();
  for (var ri = 0; ri < RECORDS.length; ri++){
    var rid = RECORDS[ri].record_id;
    if (rid) byId.set(String(rid), ri);
  }
  var panel = document.getElementById("detail");
  var panelBody = document.getElementById("detail-body");
  var panelClose = document.getElementById("detail-close");

  function esc(s){
    return String(s === undefined || s === null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }
  // An identifier with an invisible character in it is shown with a marker.
  function shownId(v){
    return (typeof v === "string" && typeof HaloView !== "undefined" && HaloView.showId) ? HaloView.showId(v) : v;
  }
  function field(label, value, mono){
    if (value === undefined || value === null || value === "") return "";
    return '<div class="d-row"><div class="d-k">' + esc(label) + '</div>' +
           '<div class="d-v' + (mono ? " mono" : "") + '">' + esc(value) + '</div></div>';
  }
  function openDetail(rid, rowEl){
    var idx = byId.get(String(rid));
    if (idx === undefined || !panel || !panelBody) return;
    var r = RECORDS[idx];
    var a = r.action || {}, auth = a.authorization || {}, o = r.outcome || {},
        integ = r.integrity || {}, inp = a.input || {},
        f = Array.isArray(r.findings) ? r.findings : [];
    var prev = idx > 0 ? RECORDS[idx - 1] : null;
    var linkOk = prev ? ((prev.integrity || {}).hash === integ.prev_hash) : null;

    var h = "";
    var plainCell = rowEl ? rowEl.querySelector("td:nth-last-child(2)") : null;
    h += '<div class="d-plain">' + esc(plainCell ? plainCell.textContent : "") + "</div>";
    h += '<div class="d-sec">When</div>';
    h += field("Recorded at", stamp(r.ts) + (localMode ? " (your time)" : " (UTC)"));
    h += field("Sealed timestamp", r.ts, true);
    h += '<div class="d-sec">What ran</div>';
    h += field("Tool", shownId(a.tool));
    h += field("Action type", a.type);
    h += field("Category", a.category);
    h += field("Agent", shownId((r.agent || {}).name || (r.agent || {}).id));
    h += field("Session", shownId(r.session_id), true);
    h += field("Parent action", r.parent_id, true);
    var pr = r.principal || {};
    if (pr && typeof pr === "object"){
      h += field("On behalf of (human)", shownId(pr.human_id));
      h += field("Creator", shownId(pr.creator_id));
      h += field("Service account", shownId(pr.service_account));
      h += field("Role scope", shownId(pr.role_scope));
    }
    h += '<div class="d-sec">Arguments (as recorded)</div>';
    h += '<pre class="d-pre">' + esc(inp.summary || "(none recorded)") + "</pre>";
    h += field("Argument hash", inp.hash, true);
    h += '<div class="d-sec">Permission</div>';
    h += field("Scope", shownId(auth.scope));
    h += field("Decision", auth.decision);
    h += field("Approver", shownId(auth.approver));
    var ver = (r.verification && typeof r.verification === "object") ? r.verification : null;
    h += '<div class="d-sec">Verification gate</div>';
    if (ver){
      h += field("Status", ver.status);
      h += field("Verifier", ver.verifier);
      h += field("Policy ref", ver.policy_ref, true);
      h += field("Checked at", ver.checked_at, true);
      h += '<div class="d-note">As supplied by the reporting gate; not re-checked by the recorder.</div>';
    } else {
      h += '<div class="d-note">No verification claim was recorded for this action.</div>';
    }
    h += '<div class="d-sec">Result</div>';
    h += field("Status", o.status);
    if (o.summary){ h += '<pre class="d-pre">' + esc(o.summary) + "</pre>"; }
    h += field("Result hash", o.hash, true);
    var th = Array.isArray(r.threats) ? r.threats : [];
    h += '<div class="d-sec">Threat flags (' + esc(String(th.length)) + ")</div>";
    if (!th.length){
      h += '<div class="d-note">No threat flag was supplied with this record.</div>';
    } else {
      for (var ti = 0; ti < th.length; ti++){
        var tt = (th[ti] && typeof th[ti] === "object") ? th[ti] : {};
        h += field(tt.type || "?", tt.ref || "(no reference)");
      }
      h += '<div class="d-note">Threat flags are ingested from an upstream detector, not judged by the recorder.</div>';
    }
    h += '<div class="d-sec">Flags (' + esc(String(f.length)) + ")</div>";
    h += field("Severity", r.severity);
    if (!f.length){
      h += '<div class="d-note">No redaction pattern matched. That is not a ' +
           "guarantee no sensitive data is present — unstructured personal data " +
           "has no pattern to match.</div>";
    } else {
      for (var i = 0; i < f.length; i++){
        var fi = (f[i] && typeof f[i] === "object") ? f[i] : {};
        h += '<div class="d-row"><div class="d-k">' + esc(fi.type || "?") +
             '</div><div class="d-v">' + esc(fi.severity || "") +
             (fi.sample ? ' &middot; <span class="mono">' + esc(fi.sample) + "</span>" : "") +
             "</div></div>";
      }
      h += '<div class="d-note">A flag marks a pattern the redactor matched and ' +
           "masked in the stored summary. The sample above is already masked.</div>";
    }
    h += '<div class="d-sec">Chain position</div>';
    h += field("Record id", r.record_id, true);
    h += field("This record's hash", integ.hash, true);
    h += field("Points back to", integ.prev_hash, true);
    // The declared-linkage check below compares this record's prev_hash to the
    // PREVIOUS record's DECLARED hash — file order only. The cryptographic
    // verdict belongs to the page-level verification; if that failed at or
    // before this record, the declared linkage means nothing and must not
    // render as a green check.
    var pageVerify = window.__haloVerify;
    var brokenHere = pageVerify && pageVerify.ok === false &&
                     typeof pageVerify.at === "number" && (idx + 1) >= pageVerify.at;
    if (brokenHere){
      h += '<div class="d-note bad">✗ Chain verification failed at record ' +
           pageVerify.at + " — this record's position cannot be verified " +
           "(declared links after a break prove nothing; see the banner).</div>";
    } else if (linkOk !== null){
      h += '<div class="d-note' + (linkOk ? " ok" : " bad") + '">' +
           (linkOk
             ? "✓ prev_hash matches the preceding record's declared hash (file order — the cryptographic verdict is the banner above)."
             : "✗ Does not match the previous record's hash in this file.") +
           "</div>";
    } else {
      h += '<div class="d-note">First record in this file — its predecessor is ' +
           "outside the exported window.</div>";
    }
    panelBody.innerHTML = h;
    panel.classList.add("open");
    panel.setAttribute("aria-hidden", "false");
  }
  function closeDetail(){
    if (!panel) return;
    panel.classList.remove("open");
    panel.setAttribute("aria-hidden", "true");
  }
  tbody.addEventListener("click", function(ev){
    var tr = ev.target.closest("tr[data-rid]");
    if (tr) openDetail(tr.getAttribute("data-rid"), tr);
  });
  tbody.addEventListener("keydown", function(ev){
    if (ev.key !== "Enter" && ev.key !== " ") return;
    var tr = ev.target.closest("tr[data-rid]");
    if (tr){ ev.preventDefault(); openDetail(tr.getAttribute("data-rid"), tr); }
  });
  if (panelClose) panelClose.addEventListener("click", closeDetail);
  document.addEventListener("keydown", function(ev){
    if (ev.key === "Escape") closeDetail();
  });

  paintTimes();
  apply();
})();
"""


_STYLE = """
:root{--ink:#1a1714;--dim:#8a7f74;--line:#ece5db;--bg:#fbf8f3;--gold:#b8860b;
--gold-soft:#f3e9cf;--ok:#2f7d4f;--ok-bg:#e6f1ea;--warn:#9a5b00;--warn-bg:#f7ecd9;
--fail:#a3302a;--fail-bg:#f6e3e1;--neutral-bg:#eee8df;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font-family:"Instrument Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
line-height:1.5;-webkit-font-smoothing:antialiased}
.wrap{max-width:1020px;margin:0 auto;padding:56px 28px 80px}
.eyebrow{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--gold);font-weight:600}
h1{font-family:"Instrument Serif",Georgia,serif;font-weight:400;font-size:46px;
line-height:1.05;margin:10px 0 6px;letter-spacing:-.01em}
.meta{color:var(--dim);font-size:14px;margin-bottom:10px}
.meta b{color:var(--ink);font-weight:600}
/* "What period does this cover?" is the first question an assessor asks of an
   evidence artifact, so the span the records actually cover gets its own line
   instead of sitting mid-sentence in the metadata. */
.period{display:inline-flex;align-items:baseline;gap:8px;flex-wrap:wrap;
margin:0 0 26px;padding:8px 14px;border:1px solid var(--line);border-radius:10px;
background:#fff;font-size:15px;color:var(--ink)}
.period b{font-weight:600;font-variant-numeric:tabular-nums}
.period-l{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--dim);
font-weight:600}
.period-tz{font-size:12px;color:var(--dim)}
.verdict{border-radius:12px;padding:16px 20px;font-size:15px;font-weight:500;margin:0 0 28px;
border:1px solid var(--line);background:#fff}
.verdict.ok{background:var(--ok-bg);border-color:#cfe6d8;color:var(--ok)}
.verdict.fail{background:var(--fail-bg);border-color:#eccdca;color:var(--fail)}
.verdict.neutral{background:var(--neutral-bg);color:var(--dim)}
/* An un-anchored report is integrity-only: nobody outside the operator has
   attested it. That is the single most consequential limit on the page, so it
   is styled as an open question rather than as neutral chrome — it should
   read as unresolved, never as a passing state. */
.verdict.open{background:var(--warn-bg);border-color:#e6d3ae;color:var(--warn)}
.verdict.open b{color:var(--warn)}
.note{font-size:13px;color:var(--dim);margin:-18px 0 30px}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:34px}
.card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:16px 18px}
.card .n{font-family:"Instrument Serif",Georgia,serif;font-size:32px;line-height:1}
.card .l{font-size:12px;color:var(--dim);text-transform:uppercase;letter-spacing:.08em;margin-top:6px}
h2{font-family:"Instrument Serif",Georgia,serif;font-weight:400;font-size:24px;margin:0 0 14px}
.tablewrap{max-height:72vh;overflow:auto;background:#fff;border:1px solid var(--line);
border-radius:12px;margin-bottom:8px}
table{width:100%;min-width:960px;border-collapse:separate;border-spacing:0;font-size:13px;background:#fff}
th{text-align:left;font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--dim);
font-weight:600;padding:11px 12px;border-bottom:1px solid var(--line);background:#fdfbf7;
position:sticky;top:0;z-index:2}
td{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
td:first-child{white-space:nowrap}
tbody tr:last-child td{border-bottom:none}
.rowcount{font-size:12px;color:var(--dim);margin:-6px 0 10px}
/* An assessor's first move on a large record is to narrow it: by time, by tool,
   by what got flagged. The controls sit above the table so the narrowing is
   visible in any screenshot of the result. */
.filters{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:0 0 12px}
.filters input[type=search],.filters select,.filters input[type=datetime-local]{
font:inherit;font-size:13px;color:var(--ink);background:#fff;
border:1px solid var(--line);border-radius:8px;padding:6px 9px}
.filters .f-grow{flex:1 1 260px;min-width:200px}
.filters input[type=search]:focus,.filters select:focus,
.filters input[type=datetime-local]:focus,.f-btn:focus-visible{
outline:2px solid var(--gold);outline-offset:1px}
.f-lab,.f-check{display:inline-flex;align-items:center;gap:6px;
font-size:12px;color:var(--dim)}
.f-btn{font:inherit;font-size:12px;color:var(--ink);background:#fff;cursor:pointer;
border:1px solid var(--line);border-radius:8px;padding:6px 11px}
.f-btn:hover{background:var(--gold-soft);border-color:var(--gold)}
th[data-sort]{cursor:pointer;user-select:none;white-space:nowrap}
th[data-sort]:hover{color:var(--gold)}
th[data-sort]:focus-visible{outline:2px solid var(--gold);outline-offset:2px;color:var(--gold)}
th[data-sort]::after{content:"\\2195";opacity:.3;margin-left:5px;font-size:11px}
th[data-active=asc]::after{content:"\\2191";opacity:1;color:var(--gold)}
th[data-active=desc]::after{content:"\\2193";opacity:1;color:var(--gold)}
@media print{.filters{display:none}}
tr.rowclick{cursor:pointer}
tr.rowclick:hover td{background:var(--gold-soft)}
tr.rowclick:focus-visible{outline:2px solid var(--gold);outline-offset:-2px}
/* The row answers "what happened"; the drawer answers "show me the record".
   It slides over rather than expanding inline so the reader keeps their place
   in the table. */
.detail{position:fixed;top:0;right:0;width:min(560px,92vw);height:100%;
background:#fff;border-left:1px solid var(--line);box-shadow:-8px 0 28px rgba(26,23,20,.12);
padding:22px 24px 40px;overflow:auto;transform:translateX(101%);
transition:transform .18s ease;z-index:40}
.detail.open{transform:translateX(0)}
.detail-head{display:flex;align-items:center;justify-content:space-between;
gap:12px;margin-bottom:14px}
.detail-title{font-family:"Instrument Serif",Georgia,serif;font-size:24px}
.d-plain{font-size:15px;line-height:1.45;background:var(--gold-soft);
border:1px solid #eadfc0;border-radius:10px;padding:12px 14px;margin-bottom:16px}
.d-sec{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--gold);
font-weight:600;margin:18px 0 8px;padding-bottom:5px;border-bottom:1px solid var(--line)}
.d-row{display:flex;gap:12px;padding:5px 0;font-size:13px;align-items:baseline}
.d-k{flex:0 0 150px;color:var(--dim)}
.d-v{flex:1 1 auto;word-break:break-word}
.d-pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;
background:var(--bg);border:1px solid var(--line);border-radius:8px;
padding:10px 12px;white-space:pre-wrap;word-break:break-word;max-height:240px;overflow:auto}
.d-note{font-size:12px;color:var(--dim);margin-top:8px;line-height:1.5}
.d-note.ok{color:var(--ok)}
.d-note.bad{color:var(--fail)}
@media print{.detail{display:none}}
#more-sentinel{height:1px}
.mono{font-family:"SF Mono",ui-monospace,Menlo,monospace;font-size:12px}
.dim{color:var(--dim)}
.trunc{max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:600;
background:var(--neutral-bg);color:var(--ink)}
.pill.ok{background:var(--ok-bg);color:var(--ok)}
.pill.warn{background:var(--warn-bg);color:var(--warn)}
.pill.neutral{background:var(--neutral-bg);color:var(--dim)}
.pill.cap{background:var(--gold-soft);color:#7a5a04}
.pill.ing{background:var(--neutral-bg);color:var(--dim)}
.scopes{margin:2px 0 34px;display:flex;flex-wrap:wrap;gap:8px}
.scopes .pill{background:var(--gold-soft);color:#7a5a04}
@media print{.tablewrap{max-height:none;overflow:visible}}
.provgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px;margin-bottom:14px}
.prov{display:flex;align-items:center;gap:10px;background:#fff;border:1px solid var(--line);
border-radius:10px;padding:11px 14px}
.prov .pill{flex:none}
.prov-via{font-size:13px;font-weight:500;color:var(--ink);flex:1;min-width:0}
.prov-n{font-size:12px;color:var(--dim);white-space:nowrap;margin-left:8px}
.prov-note{margin:0 0 30px}
footer{margin-top:42px;color:var(--dim);font-size:12px;text-align:center}
footer a{color:var(--gold);text-decoration:none}
@media(max-width:720px){.cards{grid-template-columns:repeat(2,1fr)}h1{font-size:36px}}
"""


def render(records, checkpoints=None, *, witness_url=None, policy=None, window=None,
           expected_subject=None, policy_text=None):
    """Return the full HTML for a runtime-record report over ``records``.

    If ``checkpoints`` (a list of notary witnesses for this chain) is given, the
    page re-checks completeness in the browser against those witnesses. If
    ``witness_url`` (a hosted Halo witness) is given, the page instead fetches
    the checkpoints live from that witness. The embedded checkpoints remain as
    an offline fallback.

    If ``policy`` (a list of rule dicts) is given, a deterministic
    policy-corroboration verdict is rendered beside the integrity/completeness
    verdicts. ``policy_text`` is the policy file's exact text: the page carries
    it, re-reads the rules from it, and names its SHA-256 (what ``shasum -a 256``
    prints for the file). Without it, the rules' RFC 8785 canonical JSON is the
    text carried.

    Everything the page derives from the records (heading, period, counts,
    scopes, provenance, the activity table, the policy verdict) is rendered here
    and re-rendered in the browser from the records the page verifies, so the
    verification badge covers what is displayed (see ``_view``).

    ``expected_subject`` pins the customer id the page checks completeness
    under; a reader can also pin one on the page itself.

    If ``window`` is given (see ``write_report``), the page carries only the
    windowed records: in-browser verification is seeded with the window's
    anchor (the chain head immediately before the window) instead of genesis,
    and the window's position in the full chain is disclosed on the page."""
    checkpoints = checkpoints or []
    ids = [r.get("record_id") for r in records if r.get("record_id")]
    if len(ids) != len(set(ids)):
        raise ValueError("halo-record: duplicate record_id in chain; refusing to render "
                         "a report whose rows could not be told apart")
    policy_digest = None
    if policy:
        from .policy import policy_sha256, validate_policy
        validate_policy(policy)
        if policy_text is None:
            from .canon import canon
            policy_text = canon(policy)
        policy_digest = policy_sha256(policy_text)
    else:
        policy_text = None
    if window is not None:
        chain_verified = window.get("chain_verified", True)
    else:
        from .verify import verify_records
        chain_verified = verify_records(records)
    reg = _view.regions(records, policy, chain_verified, policy_digest)
    multi_agent = len(_view.agents(records)) > 1
    row_html = reg["rows"]
    if row_html:
        rows = "\n".join(row_html[:_ROW_BATCH])
        more_rows = "\n".join(row_html[_ROW_BATCH:])
        rowcount = (
            '<div class="rowcount" id="rowcount">Showing %d of %d actions, '
            "newest first%s</div>"
            % (min(len(row_html), _ROW_BATCH), len(row_html),
               " — scroll the table for more" if len(row_html) > _ROW_BATCH else ""))
        noscript = (
            '<noscript><div class="note">JavaScript is off — nothing on this page has been '
            "verified, and only the newest %d recorded actions are shown. Run "
            "<span class=\"mono\">halo verify</span> on the JSONL to check the records.</div>"
            "</noscript>" % _ROW_BATCH)
    else:
        rows = (
            '<tr><td colspan="%d" class="dim" style="padding:24px;text-align:center">'
            "No actions recorded yet — this report populates as the agent operates."
            "</td></tr>" % (11 if multi_agent else 10))
        more_rows = ""
        rowcount = '<div class="rowcount" id="rowcount"></div>'
        noscript = ""
    agent_th = "<th>Agent</th>" if multi_agent else ""
    # Escape "<" so a record value containing "</script>" can't break out of
    # the embedded JSON block. The in-browser JSON.parse reads these unchanged.
    records_json = json.dumps(records, separators=(",", ":")).replace("<", "\\u003c")
    checkpoints_json = json.dumps(checkpoints, separators=(",", ":")).replace("<", "\\u003c")
    policy_json = json.dumps(policy_text).replace("<", "\\u003c")
    # The completeness half of the banner only holds when the report is actually
    # anchored; an un-anchored report is integrity-only and must say so, not imply
    # a witness it never had.
    anchored = bool(checkpoints) or bool(witness_url)
    own_check = ("This page runs code supplied with the report; for a check that does not "
                 "depend on it, run <span class=\"mono\">halo verify</span> on the JSONL "
                 "yourself (see REVIEWERS.md).")
    if anchored:
        integrity_note = ("This page re-computes the SHA-256 / RFC 8785 hash chain of the records it "
                          "embeds, in your browser (integrity), re-renders what it displays from "
                          "those records, and checks them against the witness checkpoints for the "
                          "pinned customer id (completeness). Whether completeness counts as "
                          "independently verified depends on who operates the witness — confirm "
                          "that before relying on it. " + own_check)
    else:
        integrity_note = ("This page re-computes the SHA-256 / RFC 8785 hash chain of the records it "
                          "embeds, in your browser (integrity), and re-renders what it displays from "
                          "those records. Completeness — that no records were dropped — is "
                          "<b>not yet witnessed</b>: this report is anchored to no external witness, "
                          "so completeness rests on the vendor until one holds checkpoints for this "
                          "chain (see below). " + own_check)
    config_json = json.dumps(
        {"witnessUrl": witness_url, "subject": _subject_id(records),
         "chainRoot": (_chain_root(records) if records and _subject_id(records) is None else None),
         "expectedSubject": expected_subject,
         "chainVerified": bool(chain_verified)},
        separators=(",", ":")).replace("<", "\\u003c")
    review_window = ""
    if window:
        window_json = json.dumps(
            {"first": window["first"], "last": window["last"], "total": window["total"]},
            separators=(",", ":"))
        verify_js = _VERIFY_JS % {"genesis": _js_anchor(window["anchor"] or GENESIS_PREV),
                                  "window_json": window_json}
        bounds = " to ".join(x for x in [window.get("from"), window.get("to")] if x)
        if window["last"]:
            span = "records <b>%s&ndash;%s</b> of a <b>%s</b>-record chain" % (
                window["first"], window["last"], window["total"])
        else:
            span = "<b>0</b> of the chain's <b>%s</b> records fall in this window" % window["total"]
        n_outside = window.get("outside_breaks") or 0
        if n_outside:
            # Disclosed, not hidden: the window's own integrity is what this
            # report attests, and the reader is told plainly what lies outside it.
            outside_note = (
                ' Outside this window the chain carries <b>%d</b> sequence '
                'break(s)%s; those records are not part of this report and are '
                'not covered by its verdict.'
                % (n_outside,
                   (" (%s to %s UTC)" % (_esc(_fmt_ts(window.get("outside_first_ts"))),
                                         _esc(_fmt_ts(window.get("outside_last_ts")))))
                   if window.get("outside_first_ts") else ""))
        else:
            outside_note = (" When this page was generated, halo-record reported the full chain "
                            '<span class="mono">(head %s&hellip;)</span> as verifying; this page '
                            "cannot re-check records outside the window &mdash; run "
                            '<span class="mono">halo verify</span> on the full JSONL to confirm.'
                            % _esc((window["chain_head"] or "")[:16]))
        window_block = (
            '<div class="verdict neutral">Date-windowed report &mdash; showing %s%s. '
            'Window integrity verifies in your browser against its anchor '
            '<span class="mono">%s&hellip;</span>.%s Records outside the window are '
            'not embedded in this page.</div>'
            % (span,
               (" (%s)" % _esc(bounds)) if bounds else "",
               _esc((window["anchor"] or GENESIS_PREV)[:16]),
               outside_note))
        review_window = (
            '<div class="period"><span class="period-l">Review window</span> '
            "<b>%s</b> &ndash; <b>%s</b> <span class=\"period-tz\">UTC, as requested</span></div>\n"
            % (_esc(_fmt_ts(window.get("from")) if window.get("from") else "start of chain"),
               _esc(_fmt_ts(window.get("to")) if window.get("to") else "end of chain")))
    else:
        verify_js = _VERIFY_JS % {"genesis": _js_anchor(GENESIS_PREV), "window_json": "null"}
        window_block = ""
    policy_block = ""
    if policy:
        from .policy import _PANEL_CSS
        policy_block = ('<h2>Policy corroboration</h2>\n<style>%s</style>'
                        '<div style="margin:0 0 30px" id="r-policy">%s<!--/r-policy--></div>'
                        % (_PANEL_CSS, reg["policy"]))
    pin_value = _esc(expected_subject) if expected_subject is not None else ""

    return """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>%(title)s — Runtime Report</title>
<style>%(style)s</style>
</head><body><div class="wrap">
<div class="eyebrow">Halo Runtime Report</div>
<h1 id="r-h1">%(h1)s<!--/r-h1--></h1>
<div class="meta" id="r-meta">%(meta)s</div><div id="r-subject-note">%(subject_note)s</div>
%(review_window)s<div class="period" id="r-period">%(period)s<!--/r-period--></div>
<div id="verdict" class="verdict neutral">Not verified yet &mdash; this page verifies its records in your browser with JavaScript.</div>
<div id="completeness" class="verdict neutral">Checking completeness against the witness checkpoints&hellip;</div>
<form id="pin" class="filters" autocomplete="off">
  <label class="f-lab" for="pin-subject">Expected customer id</label>
  <input type="search" id="pin-subject" class="f-grow" value="%(pin_value)s" placeholder="the id you expect, e.g. from your contract" aria-label="Expected customer id">
  <button type="submit" class="f-btn">Check against witness</button>
</form>
<div class="note">Pin the id you expect: the page then requires every record to carry it and looks the witness up under it, rather than under the id the records carry (which the vendor writes).</div>
%(window_block)s
<div class="note">%(integrity_note)s</div>
%(policy_block)s
<div class="cards" id="r-cards">%(cards)s<!--/r-cards--></div>
<h2>Authorized scopes</h2>
<div class="scopes" id="r-scopes">%(scopes)s</div>
<div id="r-provenance">%(provenance)s</div>
<h2>Activity</h2>
<div class="filters" id="filters">
  <input type="search" id="f-q" class="f-grow" placeholder="Search time, tool, scope, summary, record id, hash&hellip;" aria-label="Search actions">
  <select id="f-tool" aria-label="Filter by tool"><option value="">All tools</option></select>
  <select id="f-type" aria-label="Filter by action type"><option value="">All types</option></select>
  <select id="f-sev" aria-label="Filter by severity">
    <option value="">Any severity</option>
    <option value="INFO">INFO</option><option value="LOW">LOW</option>
    <option value="MEDIUM">MEDIUM</option><option value="HIGH">HIGH</option>
    <option value="CRITICAL">CRITICAL</option>
  </select>
  <label class="f-lab">From <input type="datetime-local" id="f-from" step="1" aria-label="From time"></label>
  <label class="f-lab">To <input type="datetime-local" id="f-to" step="1" aria-label="To time"></label>
  <label class="f-check"><input type="checkbox" id="f-flags"> Flagged only</label>
  <button type="button" id="tz-toggle" class="f-btn">Show local time</button>
  <button type="button" id="f-reset" class="f-btn">Reset</button>
</div>
%(rowcount)s
%(noscript)s
<div class="tablewrap" id="tablewrap">
<table>
<thead><tr><th id="th-time" data-sort="data-ts" data-active="desc">Time (UTC)</th>%(agent_th)s<th data-sort="data-tool">Tool</th><th data-sort="data-type">Type</th><th>Source</th><th>Scope</th><th>Decision</th><th data-sort="data-status">Outcome</th><th data-sort="data-flags">Findings</th><th>Summary</th><th>Hash</th></tr></thead>
<tbody id="activity-body">
%(rows)s
</tbody></table>
<div id="more-sentinel"></div>
</div>
<template id="more-rows">%(more_rows)s</template>
<aside id="detail" class="detail" aria-hidden="true" aria-label="Record detail">
  <div class="detail-head">
    <div class="detail-title">Record</div>
    <button type="button" id="detail-close" class="f-btn" aria-label="Close record detail">Close</button>
  </div>
  <div id="detail-body"></div>
</aside>
<footer>Generated by <a href="https://github.com/bkuan001/halo-record">halo-record</a> &middot; format <a href="https://github.com/bkuan001/halo-record/blob/main/src/halo_record/halo-record.schema.json">Halo Runtime Record v0.1</a></footer>
</div>
<script id="records" type="application/json">%(records_json)s</script>
<script id="checkpoints" type="application/json">%(checkpoints_json)s</script>
<script id="halo-config" type="application/json">%(config_json)s</script>
<script id="halo-policy" type="application/json">%(policy_json)s</script>
<script>%(render_js)s</script>
<script>%(verify_js)s</script>
<script>%(paginate_js)s</script>
</body></html>""" % {
        "title": _esc(reg["title"]),
        "h1": reg["h1"],
        "meta": reg["meta"],
        "subject_note": reg["subject_note"],
        "review_window": review_window,
        "period": reg["period"],
        "cards": reg["cards"],
        "scopes": reg["scopes"],
        "provenance": reg["provenance"],
        "agent_th": agent_th,
        "style": _STYLE,
        "integrity_note": integrity_note,
        "policy_block": policy_block,
        "window_block": window_block,
        "pin_value": pin_value,
        "rows": rows,
        "more_rows": more_rows,
        "rowcount": rowcount,
        "noscript": noscript,
        "records_json": records_json,
        "checkpoints_json": checkpoints_json,
        "config_json": config_json,
        "policy_json": policy_json,
        "render_js": _view.render_js(with_policy=bool(policy)),
        "verify_js": verify_js,
        "paginate_js": _PAGINATE_JS,
    }


def write_report(log_path, out_path=None, witness_log=None, witness_url=None,
                 policy_path=None, start=None, end=None, expected_subject=None,
                 status=None):
    """Render ``log_path`` to HTML. ``witness_log`` embeds a local notary's
    checkpoints (offline fallback / static report). ``witness_url`` points the
    page at a hosted Halo witness it fetches live, so completeness is checked
    against a party the vendor doesn't control. If both are given, the embedded
    checkpoints seed the offline fallback while the live witness is authoritative.
    ``policy_path`` adds a deterministic policy-corroboration verdict to the report.

    ``start``/``end`` (aware datetimes, inclusive) render a **date-windowed
    report** — the disclosure shape for audit periods and review windows. The
    full chain is verified first (a windowed report is refused on a chain that
    fails verification), then only the records inside the window are embedded:
    the browser re-verifies the window against its anchor (the chain head
    immediately before the window), and records outside the window never enter
    the page.

    When a witness is named (``witness_log`` or ``witness_url``) the full
    chain's completeness is checked here, at generation, and an unreachable
    witness URL refuses the report (ValueError) rather than rendering an
    unchecked one. Pass a dict as ``status`` to receive ``completeness`` (the
    ``anchor.verify_completeness`` result, or None when no witness was named)
    and ``chain_records``."""
    if witness_log and not os.path.isfile(os.path.expanduser(str(witness_log))):
        from .anchor import WitnessFileError
        raise WitnessFileError("witness file %s does not exist; refusing to render a report "
                               "that would read as not anchored" % witness_log)
    records = _load(log_path)
    checkpoints = None
    if witness_log:
        from .anchor import Notary
        checkpoints = Notary(witness_log).checkpoints_for(records)
    elif witness_url:
        from .witness import fetch_checkpoints, fetch_failure, WitnessDamagedError
        subj = expected_subject if expected_subject is not None else _subject_id(records)
        try:
            checkpoints = fetch_checkpoints(
                witness_url, subject=subj,
                chain_root=(_chain_root(records) if subj is None and records else None))
        except WitnessDamagedError as e:
            raise ValueError("%s: %s; refusing to render a report whose completeness was "
                             "not checked" % (log_path, e))
        except Exception as e:
            raise ValueError(
                "%s: %s; refusing to render a report whose completeness was not checked"
                % (log_path, fetch_failure(witness_url, e)))
    policy = policy_text = None
    if policy_path:
        from .policy import read_policy
        policy, policy_text = read_policy(policy_path)
    if expected_subject is not None:
        found = sorted({json.dumps(_record_subject(r)) for r in records})
        if found != [json.dumps(expected_subject)]:
            raise ValueError("%s: chain subject id(s) %s are not exactly the expected %s; "
                             "refusing to render" % (log_path, ", ".join(found),
                                                     json.dumps(expected_subject)))
    from .verify import verify_records
    chain_ok = verify_records(records)
    full_records = records
    window = None
    completeness = None
    if witness_log or witness_url:
        from .anchor import verify_completeness
        completeness = verify_completeness(records, checkpoints or [],
                                           expected_subject=expected_subject)
    if status is not None:
        status["completeness"] = completeness
        status["chain_records"] = len(records)
    if start is None and end is None and not chain_ok:
        raise ValueError(
            "%s: the chain does not verify (run halo verify); refusing to render a report "
            "whose in-page check could read as passing" % log_path)
    if start is not None or end is not None:
        from .export import in_window
        total = len(records)
        chain_head = (records[-1].get("integrity") or {}).get("hash", "") if records else ""
        idx = [i for i, r in enumerate(records) if in_window(r, start=start, end=end)]
        if idx:
            first, last = idx[0], idx[-1]
            win_records = records[first:last + 1]
            anchor = (win_records[0].get("integrity") or {}).get("prev_hash", "")
        else:
            first, last, win_records, anchor = -1, -1, [], ""

        # What the window claims is what the window must prove. A break
        # elsewhere in the chain is disclosed on the report rather than
        # withholding the window: the reader can see both facts and judge.
        # A break *inside* the requested window is still a refusal — that
        # report would assert an integrity it does not have.
        win_breaks = chain_breaks(win_records)
        # The file's first record must link to genesis. A window that starts at
        # the first record would otherwise take a truncated head as its anchor.
        head_cut = bool(records) and (records[0].get("integrity") or {}).get("prev_hash") != GENESIS_PREV
        if head_cut and first == 0:
            win_breaks = [0] + win_breaks
        # A window that starts mid-chain must link to the record before it;
        # otherwise its anchor is whatever the window claims.
        if first > 0 and anchor != (records[first - 1].get("integrity") or {}).get("hash"):
            win_breaks = [0] + win_breaks
        # Records inside the window must pass the same per-record checks verify does.
        if win_records and not verify_records(win_records, out=None) and not win_breaks:
            from .canon import canon_issues
            from .verify import validate_record
            bad = [n for n, r in enumerate(win_records)
                   if canon_issues(r) or validate_record(r)]
            win_breaks = bad or win_breaks
        if win_breaks:
            raise ValueError(
                "%s: the requested window fails verification at record(s) %s; "
                "refusing to render a report that would claim otherwise"
                % (log_path, ", ".join(str(first + 1 + n) for n in win_breaks[:5])))
        all_breaks = chain_breaks(records)
        if head_cut and 0 not in all_breaks:
            all_breaks = [0] + all_breaks
        outside = [n for n in all_breaks if not (first <= n <= last)]

        window = {"first": first + 1, "last": last + 1, "total": total,
                  "anchor": anchor, "chain_head": chain_head,
                  "outside_breaks": len(outside),
                  "outside_first_ts": (records[outside[0]].get("ts") if outside else None),
                  "outside_last_ts": (records[outside[-1]].get("ts") if outside else None),
                  "chain_verified": chain_ok,
                  "from": start.isoformat() if start else None,
                  "to": end.isoformat() if end else None}
        # The page can only re-check checkpoints that fall inside the window, so
        # the full chain is checked against the witness here, at generation.
        if completeness is not None and completeness.get("ok") is False:
            raise ValueError(
                "%s: the chain conflicts with the witness (%s); refusing to render a "
                "windowed report that could not show it" % (log_path, completeness.get("why")))
        records = win_records
    html_doc = render(records, checkpoints, witness_url=witness_url, policy=policy,
                      window=window, expected_subject=expected_subject,
                      policy_text=policy_text)
    html_doc = _LONE_SURROGATE_RE.sub("\ufffd", html_doc)  # displayable and encodable
    if out_path:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(html_doc)
    return html_doc, len(records)
