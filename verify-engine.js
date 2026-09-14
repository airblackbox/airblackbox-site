"use strict";
/* AIR Blackbox evidence verifier - shared engine.
   Loaded by both /verify and the homepage panel. Kept in ONE file on purpose:
   canonicalJSON() below must reproduce Python's json.dumps byte-for-byte, and
   two copies of it would eventually drift - at which point one page would say
   VERIFIED and the other "tampered" for the same file. For a tool whose whole
   claim is that anyone can check the same thing and get the same answer, that
   divergence would be the worst bug available. */

/* ---------- tiny ZIP reader (central directory + raw deflate) ---------- */
async function readZip(buf){
  const dv = new DataView(buf), u8 = new Uint8Array(buf);
  // End of central directory: scan back for 0x06054b50
  let eocd = -1;
  for (let i = u8.length - 22; i >= Math.max(0, u8.length - 66000); i--){
    if (dv.getUint32(i, true) === 0x06054b50){ eocd = i; break; }
  }
  if (eocd < 0) throw new Error("not a ZIP file");
  const count = dv.getUint16(eocd + 10, true);
  let off = dv.getUint32(eocd + 16, true);
  const entries = [];
  for (let n = 0; n < count; n++){
    if (dv.getUint32(off, true) !== 0x02014b50) throw new Error("bad central directory");
    const method = dv.getUint16(off + 10, true);
    const compSize = dv.getUint32(off + 20, true);
    const rawSize  = dv.getUint32(off + 24, true);
    const nameLen  = dv.getUint16(off + 28, true);
    const extraLen = dv.getUint16(off + 30, true);
    const cmtLen   = dv.getUint16(off + 32, true);
    const localOff = dv.getUint32(off + 42, true);
    const name = new TextDecoder().decode(u8.subarray(off + 46, off + 46 + nameLen));
    entries.push({name, method, compSize, rawSize, localOff});
    off += 46 + nameLen + extraLen + cmtLen;
  }
  // Resolve data offsets from the local headers.
  for (const e of entries){
    if (dv.getUint32(e.localOff, true) !== 0x04034b50) throw new Error("bad local header for " + e.name);
    const nl = dv.getUint16(e.localOff + 26, true), el = dv.getUint16(e.localOff + 28, true);
    e.dataOff = e.localOff + 30 + nl + el;
  }
  return entries;
}

async function readMember(buf, e){
  const slice = new Uint8Array(buf, e.dataOff, e.compSize);
  if (e.method === 0) return slice.slice();
  if (e.method !== 8) throw new Error("unsupported compression in " + e.name);
  const ds = new DecompressionStream("deflate-raw");
  const stream = new Blob([slice]).stream().pipeThrough(ds);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/* ---------- helpers ---------- */
const hex = b => Array.from(b).map(x => x.toString(16).padStart(2,"0")).join("");
const unhex = s => new Uint8Array(s.match(/.{2}/g).map(h => parseInt(h,16)));
async function sha256(bytes){ return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)); }
const text = b => new TextDecoder().decode(b);

/* Byte-for-byte match for Python's
   json.dumps(obj, sort_keys=True, separators=(",",":"))  [ensure_ascii=True].
   JSON.stringify agrees except that Python escapes every non-ASCII character,
   so the output is post-processed to \uXXXX. Getting this wrong changes the
   digest and every signature check fails, so it is the load-bearing function
   on this page. */
function canonicalJSON(value){
  const enc = v => {
    if (v === null) return "null";
    const t = typeof v;
    if (t === "number") return Number.isInteger(v) ? String(v) : JSON.stringify(v);
    if (t === "boolean") return v ? "true" : "false";
    if (t === "string") return JSON.stringify(v);
    if (Array.isArray(v)) return "[" + v.map(enc).join(",") + "]";
    const keys = Object.keys(v).sort();
    return "{" + keys.map(k => JSON.stringify(k) + ":" + enc(v[k])).join(",") + "}";
  };
  return enc(value).replace(/[-￿]/g,
    c => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
}

function pemToDer(pem){
  const m = pem.match(/-----BEGIN PUBLIC KEY-----([\s\S]+?)-----END PUBLIC KEY-----/);
  if (!m) return null;                       // ML-DSA hex block, not SPKI PEM
  const b64 = m[1].replace(/\s+/g, "");
  const raw = atob(b64);
  return Uint8Array.from(raw, ch => ch.charCodeAt(0));
}

async function ed25519Verify(spkiDer, sig, msg){
  try{
    const key = await crypto.subtle.importKey("spki", spkiDer, {name:"Ed25519"}, false, ["verify"]);
    return await crypto.subtle.verify({name:"Ed25519"}, key, sig, msg);
  }catch(err){ return null; }               // null = this browser cannot check
}

/* ---------- the checks ---------- */
async function verify(buf, expectKey){
  const R = {checks: [], facts: {}, level: "ok", unchecked: false};
  /* unchecked = a signature check could not RUN here (browser lacks Ed25519,
     or the bundle uses an algorithm this page cannot verify). That is not the
     same as a check running and passing, and a caller must not render it as
     any kind of pass. */
  const add = (mark, t, d) => {
    R.checks.push({mark, t, d});
    if (mark === "bad") R.level = "bad";
    else if (mark === "warn" && R.level === "ok") R.level = "warn";
  };
  const fail = (t, d) => { add("bad", t, d); return R; };

  let entries;
  try { entries = await readZip(buf); }
  catch(e){ return fail("This is not a readable evidence file", e.message +
    ". An .air-evidence file is a signed archive; this file could not be opened as one."); }

  // 1. layout + duplicate names
  const names = entries.map(e => e.name);
  const dupes = [...new Set(names.filter((n,i) => names.indexOf(n) !== i))];
  if (dupes.length) return fail("Tampered: the file contains duplicated entries",
    "Different programs would show different content from the same file — a known forgery " +
    "technique. Duplicated: " + dupes.join(", "));
  const REQUIRED = ["manifest.json","records/actions.jsonl","verification/chain.json",
                    "verification/receipts.json","verification/public_key.pem"];
  const missing = REQUIRED.filter(n => !names.includes(n));
  if (missing.length) return fail("Incomplete: required parts are missing",
    "This file is missing " + missing.join(", ") + ", so it cannot be checked.");
  add("ok", "The file is a complete, well-formed evidence bundle",
      entries.length + " parts present, no duplicates.");

  const byName = Object.fromEntries(entries.map(e => [e.name, e]));
  const read = async n => readMember(buf, byName[n]);

  let manifest;
  try { manifest = JSON.parse(text(await read("manifest.json"))); }
  catch(e){ return fail("The summary sheet is unreadable", String(e)); }

  // 2. signature over the canonical manifest digest
  const sig = manifest.signature || {};
  const digest = await sha256(new TextEncoder().encode(canonicalJSON(
    Object.fromEntries(Object.entries(manifest).filter(([k]) => k !== "signature")))));
  if (hex(digest) !== sig.signed_digest)
    return fail("Tampered: the summary was changed after signing",
      "The recorded contents no longer match what was signed.");

  const pem = text(await read("verification/public_key.pem"));
  const der = pemToDer(pem);
  let fingerprint = sig.alg || "unknown";
  if (sig.public_key_hex) fingerprint = sig.alg + ":" + hex(await sha256(unhex(sig.public_key_hex))).slice(0,16);
  R.facts.fingerprint = fingerprint;

  if (sig.alg === "ed25519" && der){
    const okSig = await ed25519Verify(der, unhex(sig.value || ""), digest);
    if (okSig === false) return fail("Tampered: the signature does not match",
      "This file was altered after signing, or it was not signed by the key it carries.");
    if (okSig === null) { R.unchecked = true; add("warn", "Signature could not be checked in this browser",
      "Your browser does not support Ed25519 checking. Try a current Chrome, Edge, Firefox or " +
      "Safari, or run air-evidence verify."); }
    else add("ok", "The summary sheet is signed and unaltered",
      "Its contents match the signature exactly. Whether the underlying records match is the " +
      "next check.");
  } else {
    R.unchecked = true;
    add("warn", "Signed with a method this page cannot check",
      "Algorithm: " + (sig.alg || "unknown") + ". Run air-evidence verify for a full check.");
  }

  // per-file digests + nothing unsigned smuggled in
  let digestsOK = true;
  for (const [fname, want] of Object.entries(manifest.files || {})){
    if (!byName[fname]){ digestsOK = false;
      add("bad","A listed part is missing from the file", fname + " is listed but not present."); break; }
    if (hex(await sha256(await read(fname))) !== want){ digestsOK = false;
      add("bad","Tampered: a part was changed after signing",
        "The contents of " + fname + " no longer match the signature."); break; }
  }
  const listed = new Set(Object.keys(manifest.files || {}));
  const extra = names.filter(n => n !== "manifest.json" && !listed.has(n) && !n.endsWith("/"));
  if (extra.length) add("bad", "Tampered: unsigned content was added",
    "These were added after signing and are covered by nothing: " + extra.join(", "));
  else if (digestsOK) add("ok", "The records themselves are unaltered since signing",
    listed.size + " parts checked individually against the signature, and nothing unsigned " +
    "was added.");

  // 3-5. records, receipts, counts
  const lines = text(await read("records/actions.jsonl")).trim().split("\n").filter(Boolean);
  const records = lines.map(l => JSON.parse(l));
  R.facts.records = records.length;

  /* Actually verify each receipt, rather than counting that one is present.
     "carries a signature" and "carries a VALID signature" are different
     claims, and only the second is worth anything to an auditor. The signed
     payload is Python's json.dumps(fields, sort_keys=True) with its DEFAULT
     separators — ", " and ": " — not the compact form used for the manifest. */
  function receiptPayload(rc){
    const f = {
      receipt_id: rc.receipt_id || "", agent_id: rc.agent_id || "",
      action_name: rc.action_name || "", action_category: rc.action_category || "",
      payload_hash: rc.payload_hash || "", covenant_hash: rc.covenant_hash || "",
      decision: rc.decision || "", authorized: rc.authorized === true,
      parent_receipt_id: rc.parent_receipt_id === undefined ? null : rc.parent_receipt_id,
      created_at: rc.created_at || "",
    };
    const body = Object.keys(f).sort()
      .map(k => JSON.stringify(k) + ": " + JSON.stringify(f[k])).join(", ");
    return new TextEncoder().encode(("{" + body + "}")
      .replace(/[-￿]/g, c => "\\u" + c.charCodeAt(0).toString(16).padStart(4,"0")));
  }

  const withReceipt = records.filter(r => r.receipt);
  let good = 0, invalid = 0, foreign = 0, uncheckable = 0;
  for (const r of withReceipt){
    const rc = r.receipt;
    if (rc.signing_method !== "ed25519"){ uncheckable++; continue; }
    if (sig.public_key_hex && (rc.signing_public_key || "").toLowerCase() !== sig.public_key_hex.toLowerCase()){
      foreign++; continue;                    // signed by a key other than the bundle's own
    }
    const spki = pemToDer(pem);
    const ok = spki ? await ed25519Verify(spki, unhex(rc.authorization_sig || ""), receiptPayload(rc)) : null;
    if (ok === true) good++; else if (ok === false) invalid++; else uncheckable++;
  }
  if (withReceipt.length === 0)
    add("warn", "No individual decision signatures",
      "This file shows what happened, but not who authorised each decision. Nothing was checked here.");
  else if (invalid || foreign)
    add("bad", "Tampered: a decision signature does not hold",
      `${invalid} signature(s) invalid and ${foreign} signed by a key other than this file's own.`);
  else if (good)
    add("ok", "Each decision was individually signed, and every signature checks out",
      `${good} of ${records.length} records verified one by one` +
      (uncheckable ? `; ${uncheckable} used a method this page cannot check.` : "."));
  else {
    R.unchecked = true;
    add("warn", "Decision signatures could not be checked in this browser",
      `${uncheckable} receipt(s) use a method this page cannot verify. Run air-evidence verify.`);
  }

  const scr = records.filter(r => r.screening);
  const reviewer = r => (r.screening || {}).human_reviewer || "";
  const adverse = scr.filter(r => r.action === "reject_candidate" ||
                                  (r.screening || {}).decision_type === "reject");
  const gaps = adverse.filter(r => !reviewer(r)).length;
  R.facts.decisions = scr.length;
  R.facts.adverse = adverse.length;
  R.facts.gaps = gaps;

  const declared = manifest.counts || {};
  const actual = {actions: records.length, screening_decisions: scr.length,
    adverse_decisions: adverse.length, adverse_decisions_missing_reviewer: gaps};
  const bad = Object.entries(actual).filter(([k,v]) => k in declared && declared[k] !== v);
  if (bad.length) add("bad", "The summary does not match the records",
    "It claims " + bad.map(([k,v]) => k + " = " + declared[k] + " but the records show " + v).join("; ") + ".");
  else add("ok", "The summary matches the records underneath it",
    "Counts were recalculated from the decisions themselves, not taken on trust.");

  // 6. external witness
  const anchor = manifest.anchor || {};
  if (anchor.anchored && anchor.tsr_b64){
    add("ok", "An independent timestamp authority witnessed this history",
      "Countersigned " + (anchor.timestamp || "") + " by " + (anchor.tsa_url || "an external authority") +
      ". Full cryptographic checking of the timestamp requires air-evidence verify.");
    R.facts.witness = "Yes";
  } else {
    add("warn", "No independent timestamp",
      "Nothing outside the sender's control witnessed this history, so if they rewrote their own " +
      "records before signing, this check would not reveal it. Ask them for an anchored export.");
    R.facts.witness = "No";
  }

  // issuer pinning
  if (expectKey){
    const want = expectKey.trim().toLowerCase();
    const got = fingerprint.toLowerCase();
    if (want === got || want === got.split(":").pop())
      add("ok", "Sender identity matches what you expected", fingerprint);
    else return fail("This did not come from the sender you expected",
      "It is signed by " + fingerprint + ", but you expected " + expectKey + ".");
    R.facts.pinned = true;
  } else {
    add("warn", "Sender identity not confirmed",
      "The file is signed, but the key travels inside it — so anyone could produce a signed file. " +
      "Ask the sender for their fingerprint through a different channel and paste it below.");
  }
  return R;
}
