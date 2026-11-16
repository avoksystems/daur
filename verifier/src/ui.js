// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Avok Systems Inc.
// Browser user interface around the verification core. Works from file:// with no network access.

import { BUNDLED_TRUST, FAILED_STATEMENT_HEADING, FINGERPRINT_NOT_COMPARED_SENTENCE, VERIFIER_VERSION, codeInfo, loadBundledTrust, loadTrust, summaryText, verify } from "./verify.js";
import { displayText, jsonText } from "./display.js";

// Every string that came from a record, a certificate, a CRL, a token, a trust manifest, an evidence
// entry or a file name passes through displayText before it is shown (specification 11.8); it is only
// ever set as textContent, never as markup.
const STATEMENT_HEADING = "What the producer declared";

// Specification 10.6: a result obtained from a test trust list is never shown as a green PASS.

const state = { deliverable: null, envelope: null, evidence: [], trust: null, trustLabel: "", crls: [], generation: 0 };

const $ = (id) => document.getElementById(id);

function isEnvelopeName(name) {
  const lower = name.toLowerCase();
  return lower.endsWith(".daur.cose") || lower.endsWith(".daur.json") || lower.endsWith(".cose");
}

async function readFile(file) {
  return { name: file.name, bytes: new Uint8Array(await file.arrayBuffer()) };
}

// Any change of input makes the shown verdict stale: clear it at once (review A-4). The generation
// counter also discards a verification that finishes after the inputs changed.
function clearResult() {
  state.generation += 1;
  $("result-card").hidden = true;
  $("banner").textContent = "";
  $("banner").className = "banner";
  for (const id of ["issued-to", "timestamp-line", "revocation-line", "region-line"]) {
    $(id).textContent = "";
    $(id).hidden = true;
  }
  $("findings").textContent = "";
  $("evidence-list").textContent = "";
  $("evidence-section").hidden = true;
  $("details").textContent = "";
  $("statement").textContent = "";
  $("record").textContent = "";
  $("print-stamp").textContent = "";
}

function dropMessage(text) {
  const node = $("drop-message");
  node.textContent = displayText(text || "");
  node.hidden = !text;
}

function renderChosen() {
  const list = $("chosen");
  list.textContent = "";
  for (const [label, item] of [["Deliverable", state.deliverable], ["Envelope", state.envelope]]) {
    const li = document.createElement("li");
    li.textContent = displayText(item ? `${label}: ${item.name} (${item.bytes.length.toLocaleString()} bytes)` : `${label}: not chosen`);
    list.appendChild(li);
  }
  $("verify").disabled = !state.envelope;
  const ev = $("evidence-chosen");
  ev.textContent = "";
  for (const item of state.evidence) ev.appendChild(el("li", `Evidence: ${item.name} (${item.bytes.length.toLocaleString()} bytes)`));
}

async function assignEvidence(files) {
  clearResult();
  for (const file of files) {
    const item = await readFile(file);
    state.evidence = state.evidence.filter((e) => e.name !== item.name);
    state.evidence.push(item);
  }
  renderChosen();
}

async function assign(files) {
  clearResult();
  dropMessage("");
  const items = [];
  for (const file of files) items.push(await readFile(file));
  const envelopes = [];
  const deliverables = [];
  for (const item of items) {
    if (isEnvelopeName(item.name)) envelopes.push(item);
    else if (looksLikeEnvelope(item.bytes) && !envelopes.length) envelopes.push(item);
    else deliverables.push(item);
  }
  const problems = [];
  if (deliverables.length > 1) problems.push(`${deliverables.length} deliverables were dropped (${deliverables.map((d) => d.name).join(", ")}); a record describes one file. Drop one deliverable with its envelope, and evidence files in the evidence area below.`);
  if (envelopes.length > 1) problems.push(`${envelopes.length} envelopes were dropped (${envelopes.map((d) => d.name).join(", ")}); drop one envelope with its deliverable.`);
  if (problems.length) {
    dropMessage(problems.join(" "));
  } else {
    if (envelopes.length) state.envelope = envelopes[0];
    if (deliverables.length) state.deliverable = deliverables[0];
  }
  renderChosen();
}

function looksLikeEnvelope(bytes) {
  // CBOR tag 18 (0xd2) followed by an array of four (0x84), or a JSON wrapper.
  if (bytes.length > 2 && bytes[0] === 0xd2 && bytes[1] === 0x84) return true;
  let start = 0;
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) start = 3;
  if (bytes.length > start && bytes[start] === 0x7b) {
    try {
      const text = new TextDecoder().decode(bytes.slice(start, Math.min(bytes.length, 4096)));
      return /"cose_sign1_b64"/.test(text) || /"record"[ \t\r\n]*:/.test(text);
    } catch {
      return false;
    }
  }
  return false;
}

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = displayText(text);
  if (className) node.className = className;
  return node;
}

function meaning(code) {
  const info = codeInfo(code);
  return info ? info.meaning : "";
}

function failCaption(result) {
  // A wrong deliverable reads as "this is not the file the record describes", not as a bad record.
  if (result.failCodes.includes("HASH_MISMATCH")) return "This is not the file the record describes. Ask the producer for the file that was delivered with this record.";
  return "Do not rely on this record. The reasons are listed below.";
}

// Specification 10.4: the list used is named inside the verdict, by its fingerprint.
function trustLine(result) {
  return el("small", result.trustListLine(), "trust-line");
}

function renderBanner(result) {
  renderVerdict(result);
  $("banner").appendChild(trustLine(result));
  // Review V4 N3: the revocation data that decided, under the trust list line.
  if (result.revocationLine()) $("banner").appendChild(el("small", result.revocationLine(), "revocation-decided"));
  if (result.revocationNote()) $("banner").appendChild(el("small", result.revocationNote(), "revocation-note"));
  // Specification 10.4: whether the fingerprint was compared is part of the verdict.
  if (!result.trustFingerprintChecked) $("banner").appendChild(el("small", FINGERPRINT_NOT_COMPARED_SENTENCE, "fingerprint-note"));
  else if (result.trustFingerprintMatched) $("banner").appendChild(el("small", "Trust list fingerprint matches the expected one.", "fingerprint-note"));
}

function renderVerdict(result) {
  const banner = $("banner");
  banner.textContent = "";
  banner.className = "banner";
  const outcome = result.result;
  if (outcome === "UNSUPPORTED") {
    banner.classList.add("unsupported");
    banner.append(`${result.testTrustList ? "TEST " : ""}UNSUPPORTED: ${result.unsupportedCapabilities.join(", ")}`);
    banner.appendChild(el("small", "This page cannot check something the strict profile requires for this record, so it gives no verdict. Use the command-line verifier (daur verify), which checks it."));
    for (const line of result.preamble()) banner.appendChild(el("small", line));
    return;
  }
  if (result.testTrustList) {
    // Neutral treatment: TEST PASS or TEST FAIL, never the green pass colour.
    banner.classList.add("test");
    if (outcome === "FAIL") banner.append(`TEST FAIL: ${result.failCodes.join(", ")}`);
    else if (result.warnCodes.length) banner.append(`TEST PASS with warnings: ${result.warnCodes.join(", ")}`);
    else banner.append("TEST PASS");
    for (const line of result.preamble()) banner.appendChild(el("small", line));
    if (outcome === "FAIL") banner.appendChild(el("small", failCaption(result)));
    if (result.warnCodes.includes("FILE_NOT_CHECKED")) banner.appendChild(el("small", "No deliverable was supplied, so the file hash and regions were not checked: this result says nothing about any file."));
    return;
  }
  if (outcome === "FAIL") {
    banner.classList.add("fail");
    banner.append(`FAIL: ${result.failCodes.join(", ")}`);
    banner.appendChild(el("small", failCaption(result)));
  } else if (result.warnCodes.length) {
    banner.classList.add("warn");
    banner.append(`PASS with warnings: ${result.warnCodes.join(", ")}`);
    const caveat = result.warnCodes.includes("FILE_NOT_CHECKED")
      ? "The record is intact and signed. No deliverable was supplied, so the file hash and regions were not checked: this result says nothing about any file."
      : "The record is intact and signed, with the caveats listed below.";
    banner.appendChild(el("small", caveat));
  } else {
    banner.classList.add("pass");
    banner.append("PASS");
    banner.appendChild(el("small", "The record is intact, signed by a certificate the trust list below accepts, and bound to this file."));
  }
  if (result.profile === "pilot") for (const line of result.preamble()) banner.appendChild(el("small", line));
}

function showLine(id, text) {
  $(id).textContent = displayText(text || "");
  $(id).hidden = !text;
}

function regionLine(result) {
  const d = result.details;
  const notHere = d.regions_not_recomputed || [];
  if (!notHere.length) return "";
  if (!result.failCodes.includes("HASH_MISMATCH") && d.file_sha256) {
    return `The file is byte-identical to the one signed. ${notHere.length} region${notHere.length === 1 ? "" : "s"} (PDF pages or DOCX sections) ${notHere.length === 1 ? "was" : "were"} not recomputed here; byte identity covers ${notHere.length === 1 ? "it" : "them"}.`;
  }
  return `${notHere.length} region${notHere.length === 1 ? "" : "s"} (PDF pages or DOCX sections) could not be recomputed here; use the command-line verifier to see which parts changed.`;
}

// Text from a record or a report is untrusted: control and bidirectional control characters as visible
// escapes, whitespace collapsed, at most 200 characters. It is only ever set as textContent.
function plainText(value) {
  const text = displayText(String(value ?? ""));
  return text.split(/[ \t\n\r\f\v\u00a0\u2028\u2029]+/).filter(Boolean).join(" ").slice(0, 200);
}

const CRL_SOURCES = { stapled: "stapled at signing", trust_directory: "from the trust list", supplied: "supplied to this check" };

const EVIDENCE_STATUS = {
  matched: "supplied, SHA-256 matches",
  hash_mismatch: "supplied, SHA-256 DIFFERS",
  not_supplied: "not supplied, not checked",
};

// Specification 11.10: each entry with its type, description, file, short hash and stated summary.
function renderEvidence(result) {
  const listing = result.details.evidence || [];
  const unknown = result.details.evidence_unknown || [];
  const list = $("evidence-list");
  list.textContent = "";
  $("evidence-section").hidden = !listing.length && !unknown.length;
  for (const e of listing) {
    const li = el("li", undefined, e.status);
    li.appendChild(el("code", `${e.id} ${e.type}`));
    li.append(` ${plainText(e.description)}; file ${plainText(e.file_name)}, SHA-256 ${String(e.sha256 || "").slice(0, 12)}...: `);
    li.appendChild(el("strong", EVIDENCE_STATUS[e.status] || e.status));
    // Specification 11.10: the file's own counts when it was supplied and checked; otherwise the record's.
    const counts = (summary) => plainText(summaryText(summary)) || "nothing";
    if (e.summary_checked === "consistent") li.appendChild(el("small", `Checked against the supplied file: ${counts(e.file_summary)}`, "detail"));
    else if (e.summary_checked === "unreadable") li.appendChild(el("small", `The supplied file is not a readable citation check (${plainText(e.unreadable)}); the record states: ${counts(e.summary)}`, "detail"));
    else if (e.summary_checked === "inconsistent") li.appendChild(el("small", `The supplied file says: ${counts(e.file_summary)}; the record states: ${counts(e.summary)}`, "detail"));
    else if (e.summary) li.appendChild(el("small", `Stated by the producer; not checked: ${counts(e.summary)}`, "detail"));
    list.appendChild(li);
  }
  for (const name of unknown) {
    const li = el("li", undefined, "unknown");
    li.append(`${plainText(name)}: `);
    li.appendChild(el("strong", "supplied, matches no entry of the record"));
    list.appendChild(li);
  }
}

function renderResult(result) {
  $("result-card").hidden = false;
  renderBanner(result);
  const d = result.details;
  $("print-stamp").textContent = displayText(`Verified on ${new Date().toISOString().replace(/\.\d+Z$/, "Z")} with Avok Attest verifier ${VERIFIER_VERSION}; trust list ${d.trust_list_id || "(no manifest)"} ${d.trust_list_version || "(unversioned)"}, fingerprint ${d.trust_list_fingerprint || "(none)"}; ${result.profile} profile.`);
  // Specification 11.8: who the certificate names and where the time came from, before anything from the record.
  showLine("issued-to", result.certificateLine());
  showLine("timestamp-line", result.timestampLine());
  showLine("region-line", regionLine(result));
  const findings = $("findings");
  findings.textContent = "";
  const order = { FAIL: 0, UNSUPPORTED: 1, WARN: 2, INFO: 3 };
  for (const f of [...result.findings].sort((a, b) => order[a.severity] - order[b.severity])) {
    const li = el("li", undefined, f.severity);
    li.appendChild(el("code", `${f.severity} ${f.code}`));
    const sentence = meaning(f.code);
    if (sentence) li.appendChild(el("span", ` ${sentence}`, "meaning"));
    const info = codeInfo(f.code);
    if (info && f.severity !== "INFO") li.appendChild(el("span", ` Next: ${info.next}`, "next"));
    li.appendChild(el("small", f.message, "detail"));
    findings.appendChild(li);
  }
  renderEvidence(result);
  const details = $("details");
  details.textContent = "";
  const rows = [
    ["Profile", result.profile],
    ["Trust list", `${d.trust_list_name || "(no name)"}, ${d.trust_list_id || "(unnamed)"} ${d.trust_list_version || "(unversioned)"}`],
    ["Trust list fingerprint", d.trust_list_fingerprint || "none (no manifest)"],
    ["Algorithm", d.algorithm],
    ["Signer", d.signer ? `${d.signer.subject} (serial ${d.signer.serial})` : ""],
    ["Signer fingerprint", d.signer ? d.signer.sha256_fingerprint : ""],
    ["Certificate validity", d.signer ? `${d.signer.not_before} to ${d.signer.not_after}` : ""],
    ["Trust anchor", d.trust_anchor ? d.trust_anchor.subject : ""],
    ["Trust anchor fingerprint", d.trust_anchor ? d.trust_anchor.sha256_fingerprint : ""],
    ["Signing time", d.signing_time ? `${d.signing_time} (${d.signing_time_source})` : ""],
    ["Time-stamp", d.timestamp ? `${d.timestamp.gen_time} by ${d.timestamp.tsa} (serial ${d.timestamp.serial})` : "none"],
    ["Time-stamp anchor", d.timestamp && d.timestamp.anchor ? d.timestamp.anchor.subject : ""],
    ["Time-stamp anchor fingerprint", d.timestamp && d.timestamp.anchor ? d.timestamp.anchor.sha256_fingerprint : ""],
    ["Revocation", d.revocation ? `${d.revocation.status}: ${d.revocation.detail}` : ""],
    ["Revocation decided by", d.revocation && d.revocation.decided_by ? `${d.revocation.decided_by.evidence === "later_crl" ? "a later revocation list" : "data covering the signing time"}, thisUpdate ${d.revocation.decided_by.this_update}, SHA-256 ${d.revocation.decided_by.sha256}` : ""],
    ["Further revocation lists", state.crls.length ? state.crls.map((c) => c.name).join(", ") : "none loaded"],
    ...(d.crls_loaded || []).map((c) => [`Revocation list (${CRL_SOURCES[c.source] || c.source})`, `${c.issuer}, thisUpdate ${c.this_update}, nextUpdate ${c.next_update || "(none)"}, SHA-256 ${c.sha256}`]),
    ["Snapshot commitment", d.snapshot_commitment || ""],
    ["Trust-list pin", d.trust_pin ? `${d.trust_pin.trust_list_id} ${d.trust_pin.version}` : "none"],
    ["File SHA-256", d.file_sha256 || "not checked"],
    ["Regions", d.regions_checked !== undefined ? `${d.regions_checked} recomputed, ${d.regions_mismatched.length} mismatched, ${(d.regions_not_recomputed || []).length} not recomputed in browser` : ""],
  ];
  for (const [k, v] of rows) {
    if (!v) continue;
    details.appendChild(el("dt", k));
    details.appendChild(el("dd", v));
  }
  // Specification 11.8: after a FAIL the statement is headed as coming from a record that failed.
  $("statement-heading").textContent = result.result === "FAIL" ? FAILED_STATEMENT_HEADING : STATEMENT_HEADING;
  $("statement").textContent = result.statement || "(no record could be read)";
  $("record").textContent = result.record ? jsonText(result.record, null, 2) : "";
  // Accessibility (review A-18): the verdict is a live region; move focus to it and bring it into view.
  const banner = $("banner");
  banner.focus({ preventScroll: true });
  banner.scrollIntoView({ block: "start", behavior: "auto" });
}

async function runVerify() {
  const button = $("verify");
  button.disabled = true;
  button.textContent = "Verifying";
  const generation = state.generation;
  try {
    const result = await verify({
      envelope: state.envelope.bytes,
      deliverable: state.deliverable ? state.deliverable.bytes : null,
      fileName: state.deliverable ? state.deliverable.name : null,
      trust: state.trust,
      profile: $("profile").value,
      allowTestTrust: $("allow-test-trust").checked,
      crls: state.crls.map((c) => c.bytes),
      evidence: state.evidence.map((e) => ({ name: e.name, bytes: e.bytes })),
      trustFingerprint: $("trust-fingerprint").value.trim() || null,
      // One or more SHA-256 values, separated by commas or semicolons (review V4 N3).
      crlFingerprints: $("crl-fingerprint").value.split(/[,;]/).map((v) => v.trim()).filter(Boolean),
    });
    if (generation === state.generation) renderResult(result);
  } catch (err) {
    if (generation === state.generation) {
      $("result-card").hidden = false;
      const banner = $("banner");
      banner.className = "banner fail";
      banner.textContent = displayText(`Verifier error: ${err.message}`);
      banner.focus();
    }
  } finally {
    button.textContent = "Verify";
    button.disabled = !state.envelope;
  }
}

function renderTrust() {
  const trust = state.trust;
  $("test-bar").hidden = !trust.isTest;
  $("trust-summary").textContent = displayText(state.trustLabel);
  $("trust-version").textContent = displayText(state.trustLabel);
  const roots = $("trust-roots");
  roots.textContent = "";
  for (const anchor of trust.anchors) {
    const li = el("li");
    li.append(displayText(`${anchor.cert.subject} `));
    li.appendChild(el("code", anchor.fingerprint));
    li.append(` (${[...anchor.purposes].join(", ")})`);
    if (anchor.notBefore || anchor.notAfter) li.append(` (listed ${anchor.notBefore ? anchor.notBefore.toISOString().slice(0, 10) : "?"} to ${anchor.notAfter ? anchor.notAfter.toISOString().slice(0, 10) : "?"})`);
    roots.appendChild(li);
  }
  const invalid = trust.manifest && Array.isArray(trust.manifest.invalidity_dates) ? trust.manifest.invalidity_dates.length : 0;
  if (trust.manifestInvalid) {
    $("trust-note").textContent = displayText(`The manifest breaks the rules of specification 10.2 and was not read; every verification with this list fails TRUST_LIST_INVALID. ${trust.manifestProblems.slice(0, 3).join("; ")}`);
    return;
  }
  $("trust-note").textContent = trust.manifest
    ? displayText(`Manifest issued ${trust.manifest.issued || "(unknown)"}; ${trust.anchors.length} root(s); ${invalid} retroactive invalidity entr${invalid === 1 ? "y" : "ies"}.`)
    : `No manifest: every certificate in the PEM file is an anchor and the trust-list pin cannot be checked.`;
}

async function useBundledTrust() {
  clearResult();
  state.trust = await loadBundledTrust();
  state.trustLabel = `${BUNDLED_TRUST.id} ${BUNDLED_TRUST.version} (bundled)`;
  renderTrust();
}

async function loadCustomTrust() {
  const pemFile = $("trust-pem").files[0];
  if (!pemFile) {
    $("trust-note").textContent = "Choose a .pem file with the root certificates first.";
    return;
  }
  clearResult();
  const manifestFile = $("trust-manifest").files[0];
  try {
    const pem = await pemFile.text();
    const manifest = manifestFile ? await manifestFile.text() : null;
    state.trust = await loadTrust(pem, manifest);
    state.trustLabel = state.trust.manifest
      ? `${state.trust.id} ${state.trust.version} (loaded from ${pemFile.name})`
      : state.trust.manifestInvalid
        ? `${pemFile.name} (manifest invalid, not read)`
        : `${pemFile.name} (no manifest)`;
    renderTrust();
  } catch (err) {
    $("trust-note").textContent = displayText(`Could not load the trust list: ${err.message}`);
  }
}

async function loadCrls(files) {
  clearResult();
  state.crls = [];
  for (const file of files) state.crls.push(await readFile(file));
  $("crl-note").textContent = state.crls.length
    ? displayText(`${state.crls.length} revocation list${state.crls.length === 1 ? "" : "s"} loaded: ${state.crls.map((c) => c.name).join(", ")}. The result says which revocation data decided.`)
    : "No further revocation lists loaded.";
}

function wire() {
  const zone = $("dropzone");
  for (const type of ["dragenter", "dragover"]) {
    zone.addEventListener(type, (e) => {
      e.preventDefault();
      zone.classList.add("active");
    });
  }
  for (const type of ["dragleave", "drop"]) zone.addEventListener(type, () => zone.classList.remove("active"));
  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    assign(e.dataTransfer.files);
  });
  // The drop zone works from the keyboard: Enter or Space opens a chooser for both files.
  zone.addEventListener("keydown", (e) => {
    if (e.target !== zone) return;
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      const input = $("file-any");
      try {
        if (typeof input.showPicker === "function") input.showPicker();
        else input.click();
      } catch {
        input.click();
      }
    }
  });
  const evZone = $("evidence-zone");
  for (const type of ["dragenter", "dragover"]) {
    evZone.addEventListener(type, (e) => {
      e.preventDefault();
      evZone.classList.add("active");
    });
  }
  for (const type of ["dragleave", "drop"]) evZone.addEventListener(type, () => evZone.classList.remove("active"));
  evZone.addEventListener("drop", (e) => {
    e.preventDefault();
    e.stopPropagation();
    assignEvidence(e.dataTransfer.files);
  });
  evZone.addEventListener("keydown", (e) => {
    if (e.target !== evZone) return;
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      const input = $("file-evidence");
      try {
        if (typeof input.showPicker === "function") input.showPicker();
        else input.click();
      } catch {
        input.click();
      }
    }
  });
  $("file-evidence").addEventListener("change", (e) => {
    const files = [...e.target.files];
    e.target.value = "";
    if (files.length) assignEvidence(files);
  });
  $("file-any").addEventListener("change", (e) => {
    const files = [...e.target.files];
    e.target.value = "";
    if (files.length) assign(files);
  });
  $("file-deliverable").addEventListener("change", async (e) => {
    clearResult();
    dropMessage("");
    if (e.target.files[0]) state.deliverable = await readFile(e.target.files[0]);
    renderChosen();
  });
  $("file-envelope").addEventListener("change", async (e) => {
    clearResult();
    dropMessage("");
    if (e.target.files[0]) state.envelope = await readFile(e.target.files[0]);
    renderChosen();
  });
  for (const id of ["profile", "allow-test-trust", "trust-pem", "trust-manifest"]) $(id).addEventListener("change", clearResult);
  $("trust-fingerprint").addEventListener("input", clearResult);
  $("crl-fingerprint").addEventListener("input", clearResult);
  $("trust-crls").addEventListener("change", (e) => loadCrls(e.target.files));
  $("verify").addEventListener("click", runVerify);
  $("clear").addEventListener("click", () => {
    state.deliverable = null;
    state.envelope = null;
    state.evidence = [];
    $("file-deliverable").value = "";
    $("file-envelope").value = "";
    dropMessage("");
    clearResult();
    renderChosen();
  });
  $("trust-load").addEventListener("click", loadCustomTrust);
  $("trust-reset").addEventListener("click", useBundledTrust);
  // Printing expands every details block so that the printout carries the signer, time and file hash.
  window.addEventListener("beforeprint", () => {
    for (const d of document.querySelectorAll("details")) {
      d.dataset.wasOpen = d.open ? "1" : "";
      d.open = true;
    }
  });
  window.addEventListener("afterprint", () => {
    for (const d of document.querySelectorAll("details")) d.open = d.dataset.wasOpen === "1";
  });
  renderChosen();
  useBundledTrust().catch((err) => {
    $("trust-note").textContent = `Bundled trust list could not be loaded: ${err.message}`;
  });
}

// Expose the core for automated browser checks.
globalThis.avokAttest = { verify, loadTrust, loadBundledTrust, state };

if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", wire);
else wire();
