// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Avok Systems Inc.
// Plain-language statement generated from the signed record (mirrors daur/statement.py). Record text
// passes through displayText (specification 11.8); only the review statement and the declaration keep
// their line breaks, each followed by an indent.

import { displayText } from "./display.js";

export const CATEGORY_WORDS = {
  none: "no AI use",
  research: "research",
  drafting: "drafting",
  editing: "editing",
  translation: "translation",
  summarisation: "summarisation",
  analysis: "analysis",
  code_generation: "code generation",
  image_generation: "image generation",
  other: "other use",
};

export const EXTENT_WORDS = { none: "no", minor: "minor", substantial: "substantial", predominant: "predominant" };

// The methods that name a review. "other" is described by the producer and "none" says that no
// person reviewed the deliverable; neither is printed as "a review by" (specification 4.6).
export const REVIEW_WORDS = {
  full_read: "a full read",
  sampled: "a sampled review",
  citation_verification: "citation verification",
  technical_check: "a technical check",
};

export const NO_REVIEW = "Human review: none. No person reviewed the deliverable before this record was made.";

export function reviewSentence(review) {
  const r = review && typeof review === "object" && !Array.isArray(review) ? review : {};
  const statement = displayText(r.statement ? String(r.statement) : "", true);
  // Review V4 N7: what the producer adds is attributed to it, after the fixed sentence.
  if (r.method === "none") return statement ? `${NO_REVIEW} The producer adds: ${statement}` : NO_REVIEW;
  const role = displayText(r.reviewer_role || "reviewer");
  const date = displayText(r.date || "");
  if (Object.prototype.hasOwnProperty.call(REVIEW_WORDS, r.method)) return `Human review: ${REVIEW_WORDS[r.method]} by the ${role} on ${date}. ${statement}`.trim();
  return `Human review (described by the producer): the ${role} on ${date}. ${statement}`.trim();
}

function locusSummary(locus) {
  if (!locus || !locus.length) return "no specific regions recorded";
  const refs = locus.map((r) => String(r.ref || ""));
  if (refs.length <= 4) return refs.join(", ");
  return `${refs.slice(0, 3).join(", ")} and ${refs.length - 3} more regions`;
}

function formatPercent(value) {
  return Number.isInteger(value) ? String(value) : String(Number(value));
}

export function aiUseSentence(entry) {
  const category = CATEGORY_WORDS[entry.category] || entry.category || "other";
  const extent = EXTENT_WORDS[entry.extent] || entry.extent || "";
  const pct = typeof entry.extent_percent === "number" ? ` (about ${formatPercent(entry.extent_percent)} percent)` : "";
  const tool = `${entry.tool || "an AI tool"} (${entry.model || ""} ${entry.model_version || ""})`.replace("( ", "(").replace(" )", ")");
  const data = entry.data_exposed || {};
  let exposure;
  if (data.government_or_client_data) {
    exposure = "Government or client data was exposed to the tool";
    if (data.classes && data.classes.length) exposure += ` (classes: ${data.classes.join(", ")})`;
  } else {
    exposure = "No government or client data was exposed to the tool";
  }
  const opt = entry.training_opt_out;
  const optText = opt === true ? "the provider was instructed not to train on the data" : opt === false ? "no training opt-out was in place" : opt === "unknown" ? "the training opt-out status is unknown" : "";
  const dates = entry.dates || {};
  const when = dates.start ? ` between ${dates.start} and ${dates.end}` : "";
  return (
    `${tool}, provided by ${entry.provider || "an unnamed provider"} and hosted in ${entry.hosting_jurisdiction || "an unstated jurisdiction"}, was used for ${category} to a ` +
    `${extent} extent${pct}${when}; locus: ${locusSummary(entry.locus)}. ${exposure}; retention: ${entry.retention || "not stated"}; ${optText}.`
  ).replace("..", ".");
}

export function plainStatement(record, signingTime = null, tsa = null, personNote = "") {
  const d = record.deliverable || {};
  const p = record.producer || {};
  const org = p.organisation || {};
  const person = p.accountable_person || {};
  const review = record.human_review || {};
  const uses = record.ai_use || [];
  const lines = [];
  lines.push(
    `${org.legal_name || "The producer"} (${org.jurisdiction || ""}, business number ${org.business_number || ""}) declares how AI was used to produce "${d.title || ""}" ` +
      `(deliverable ${d.deliverable_id || ""}, version ${d.version || ""}, contract ${d.contract_reference || ""}; file ${d.file_name || ""}, SHA-256 ${d.file_sha256 || ""}).`,
  );
  if (!uses.length || uses.every((u) => u.extent === "none")) {
    lines.push("The producer declares that no AI tool was used in producing this deliverable.");
  } else {
    for (const entry of uses) lines.push(aiUseSentence(entry));
  }
  const safe = lines.map((line) => displayText(line));
  safe.push(reviewSentence(review));
  safe.push(displayText(`Accountable person: ${person.name || ""}, ${person.role || ""}${personNote}.`));
  const created = record.created || "";
  if (signingTime) safe.push(displayText(`Record created ${created}; signature time-stamped at ${signingTime}${tsa ? ` by ${tsa}` : ""}.`));
  else safe.push(displayText(`Record created ${created}; no independent time-stamp.`));
  safe.push(displayText((record.declaration || {}).text || "", true));
  return safe.filter(Boolean).join("\n");
}
