// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Avok Systems Inc.
// A small JSON Schema (draft 2020-12 subset) validator covering the keywords used by the DAUR schema:
// type, enum, const, required, properties, additionalProperties, items, pattern, minLength, maxLength,
// minimum, maximum, oneOf, allOf, if/then, dependentRequired, propertyNames and local $ref.

function typeOf(value) {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  if (typeof value === "number") return Number.isInteger(value) ? "integer" : "number";
  return typeof value;
}

function matchesType(value, type) {
  const t = typeOf(value);
  if (type === "number") return t === "number" || t === "integer";
  if (type === "integer") return t === "integer";
  return t === type;
}

function resolveRef(root, ref) {
  if (!ref.startsWith("#/")) throw new Error(`unsupported $ref ${ref}`);
  let node = root;
  for (const part of ref.slice(2).split("/")) node = node[part.replace(/~1/g, "/").replace(/~0/g, "~")];
  if (node === undefined) throw new Error(`unresolved $ref ${ref}`);
  return node;
}

function deepEqual(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

export function validate(value, schema, root = schema, path = "", errors = []) {
  if (schema === true) return errors;
  if (schema === false) {
    errors.push(`${path || "(root)"}: not allowed`);
    return errors;
  }
  if (schema.$ref) {
    validate(value, resolveRef(root, schema.$ref), root, path, errors);
    return errors;
  }
  const where = path || "(root)";
  if (schema.const !== undefined && !deepEqual(value, schema.const)) errors.push(`${where}: must be ${JSON.stringify(schema.const)}`);
  if (schema.enum && !schema.enum.some((e) => deepEqual(e, value))) errors.push(`${where}: ${JSON.stringify(value)} is not one of ${JSON.stringify(schema.enum)}`);
  if (schema.type) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!types.some((t) => matchesType(value, t))) {
      errors.push(`${where}: ${JSON.stringify(value)} is not of type ${types.join(", ")}`);
      return errors;
    }
  }
  if (typeof value === "string") {
    if (schema.minLength !== undefined && [...value].length < schema.minLength) errors.push(`${where}: shorter than ${schema.minLength}`);
    if (schema.maxLength !== undefined && [...value].length > schema.maxLength) errors.push(`${where}: longer than ${schema.maxLength}`);
    if (schema.pattern !== undefined && !new RegExp(schema.pattern, "u").test(value)) errors.push(`${where}: ${JSON.stringify(value)} does not match ${schema.pattern}`);
  }
  if (typeof value === "number") {
    if (schema.minimum !== undefined && value < schema.minimum) errors.push(`${where}: ${value} is less than the minimum of ${schema.minimum}`);
    if (schema.maximum !== undefined && value > schema.maximum) errors.push(`${where}: ${value} is greater than the maximum of ${schema.maximum}`);
  }
  if (Array.isArray(value) && schema.items) {
    value.forEach((item, i) => validate(item, schema.items, root, `${path}/${i}`, errors));
  }
  if (value && typeof value === "object" && !Array.isArray(value)) {
    const props = schema.properties || {};
    for (const key of schema.required || []) {
      if (!(key in value)) errors.push(`${where}: ${JSON.stringify(key)} is a required property`);
    }
    for (const [key, sub] of Object.entries(props)) {
      if (key in value) validate(value[key], sub, root, `${path}/${key}`, errors);
    }
    for (const key of Object.keys(value)) {
      if (schema.propertyNames) validate(key, schema.propertyNames, root, `${path}/${key}`, errors);
      if (!(key in props)) {
        if (schema.additionalProperties === false) errors.push(`${where}: additional property ${JSON.stringify(key)} is not allowed`);
        else if (schema.additionalProperties && typeof schema.additionalProperties === "object") validate(value[key], schema.additionalProperties, root, `${path}/${key}`, errors);
      }
    }
    if (schema.dependentRequired) {
      for (const [key, deps] of Object.entries(schema.dependentRequired)) {
        if (key in value) for (const dep of deps) if (!(dep in value)) errors.push(`${where}: ${JSON.stringify(dep)} is required when ${JSON.stringify(key)} is present`);
      }
    }
  }
  if (schema.allOf) for (const sub of schema.allOf) validate(value, sub, root, path, errors);
  if (schema.oneOf) {
    const matches = schema.oneOf.filter((sub) => validate(value, sub, root, path, []).length === 0).length;
    if (matches !== 1) errors.push(`${where}: ${JSON.stringify(value)} is not valid under exactly one of the given schemas`);
  }
  if (schema.if) {
    const holds = validate(value, schema.if, root, path, []).length === 0;
    if (holds && schema.then) validate(value, schema.then, root, path, errors);
    if (!holds && schema.else) validate(value, schema.else, root, path, errors);
  }
  return errors;
}

// Specification 4.9: evidence ids are unique and every evidence reference names an entry. The schema
// cannot express either rule; both verifiers check them and report them as SCHEMA_INVALID.
export function evidenceErrors(record) {
  if (!record || typeof record !== "object" || Array.isArray(record)) return [];
  const ids = [];
  const errors = [];
  if (record.daur_version === "0.1") {
    const members = "evidence" in record ? ["evidence"] : [];
    if (Array.isArray(record.ai_use)) record.ai_use.forEach((u, i) => u && typeof u === "object" && !Array.isArray(u) && "evidence_refs" in u && members.push(`ai_use/${i}/evidence_refs`));
    if (record.human_review && typeof record.human_review === "object" && !Array.isArray(record.human_review) && "evidence_refs" in record.human_review) members.push("human_review/evidence_refs");
    for (const m of members) errors.push(`${m}: not allowed in a record of daur_version 0.1 (evidence exists from record version 0.2)`);
  }
  if (Array.isArray(record.evidence)) {
    record.evidence.forEach((entry, i) => {
      if (entry && typeof entry === "object" && typeof entry.id === "string") {
        if (ids.includes(entry.id)) errors.push(`evidence/${i}/id: evidence id ${JSON.stringify(entry.id)} is not unique`);
        ids.push(entry.id);
      }
    });
  }
  const places = [];
  if (Array.isArray(record.ai_use)) {
    record.ai_use.forEach((u, i) => {
      if (u && typeof u === "object" && !Array.isArray(u)) places.push([`ai_use/${i}/evidence_refs`, u.evidence_refs]);
    });
  }
  const review = record.human_review;
  if (review && typeof review === "object" && !Array.isArray(review)) places.push(["human_review/evidence_refs", review.evidence_refs]);
  for (const [path, refs] of places) {
    if (!Array.isArray(refs)) continue;
    refs.forEach((ref, j) => {
      if (typeof ref === "string" && !ids.includes(ref)) errors.push(`${path}/${j}: evidence reference ${JSON.stringify(ref)} names no entry of evidence`);
    });
  }
  return errors;
}
