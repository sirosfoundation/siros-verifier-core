import test from "node:test";
import assert from "node:assert/strict";
import {
  assertBackendOrigin,
  claimLabel,
  cloneDcql,
  PresentationFlow,
  normalizeInvocations,
  normalizeSchemes,
  setClaimEnabled,
  setSelectedClaims,
} from "./presentation-flow.js";

test("invocations are required, deduplicated, and closed", () => {
  assert.deepEqual(normalizeInvocations(["qr", "dc-api", "qr", "link"]), ["qr", "dc-api", "link"]);
  assert.throws(() => normalizeInvocations([]), RangeError);
  assert.throws(() => normalizeInvocations(["metaverse"]), RangeError);
});

test("schemes preserve the recognized native wallet choices", () => {
  assert.deepEqual(normalizeSchemes(["openid4vp", "haip", "haip-vp", "mdoc-openid4vp"]),
    ["openid4vp", "haip", "haip-vp", "mdoc-openid4vp"]);
  assert.throws(() => normalizeSchemes(["javascript"]), RangeError);
});

test("claim edits do not mutate the preset", () => {
  const original = {credentials: [{id: "pid", claims: [{path: ["given_name"]}, {path: ["birthdate"]}]}]};
  const givenName = original.credentials[0].claims[0];
  const birthdate = original.credentials[0].claims[1];
  const next = setClaimEnabled(original, 0, givenName, false);
  assert.equal(original.credentials[0].claims.length, 2);
  assert.deepEqual(next.credentials[0].claims, [{path: ["birthdate"]}]);
  const empty = setClaimEnabled(next, 0, birthdate, false);
  // An explicit empty array: the deliberate "only the mandatory claims" ask
  // (OpenID4VP 1.0 §6.4.1) — the verifier's DCQL validation rejects the
  // absent member, so the member always stays.
  assert.deepEqual(empty.credentials[0].claims, []);
  const restored = setClaimEnabled(empty, 0, birthdate, true);
  assert.equal(restored.credentials[0].claims.length, 1);
  const copy = cloneDcql(original);
  assert.notEqual(copy, original);
  assert.deepEqual(copy, original);
});

test("the full registry catalog is selectable without changing the requested credential identity", () => {
  const requested = {credentials: [{id: "eudi_pid", format: "dc+sd-jwt", meta: {vct_values: ["urn:pid"]}, claims: [{path: ["given_name"]}]}]};
  const available = [{id: "registry-uuid", claims: [{path: ["given_name"]}, {path: ["birthdate"]}, {path: ["personal_administrative_number"]}]}];
  const all = setSelectedClaims(requested, available, ["0:0", "0:1", "0:2"]);
  assert.equal(all.credentials[0].id, "eudi_pid");
  assert.deepEqual(all.credentials[0].meta, {vct_values: ["urn:pid"]});
  assert.equal(all.credentials[0].claims.length, 3);
  const subset = setSelectedClaims(all, available, ["0:2"]);
  assert.deepEqual(subset.credentials[0].claims, [{path: ["personal_administrative_number"]}]);
  assert.equal(requested.credentials[0].claims.length, 1, "selection does not mutate the preset");
});

test("backend responses cannot cross the configured tenant origin", () => {
  assert.equal(assertBackendOrigin("/vp/status", ["https://verifier.example"]), "https://verifier.example/vp/status");
  assert.equal(assertBackendOrigin("https://verifier.example/vp/status", ["https://verifier.example"]), "https://verifier.example/vp/status");
  assert.throws(() => assertBackendOrigin("https://other.example/vp/status", ["https://verifier.example"]));
});

test("claim labels prefer ids and otherwise use the final path segment", () => {
  assert.equal(claimLabel({id: "Given name", path: ["given_name"]}), "Given name");
  assert.equal(claimLabel({path: ["address", "street_address"]}), "street_address");
});

test("claim labels skip trailing language-map keys and keep short claim names", () => {
  // Language-map paths from the diploma's registry DCQL: the tag is the key
  // of the JSON-LD language map, not the claim type.
  assert.equal(claimLabel({path: ["credentialSubject", "givenName", "und"]}), "givenName");
  assert.equal(claimLabel({path: ["credentialSubject", "familyName", "und"]}), "familyName");
  assert.equal(claimLabel({path: ["credentialSubject", "hasClaim", "title", "nl"]}), "title");
  assert.equal(
    claimLabel({path: ["credentialSubject", "hasClaim", "awardedBy", "awardingBody", "legalName", "nl"]}),
    "legalName",
  );
  // Regional and script variants split at the first hyphen.
  assert.equal(claimLabel({path: ["credentialSubject", "givenName", "en-US"]}), "givenName");
  assert.equal(claimLabel({path: ["credentialSubject", "hasClaim", "title", "nl-BE"]}), "title");
  assert.equal(claimLabel({path: ["credentialSubject", "prefLabel", "en-Latn"]}), "prefLabel");
  // Consecutive tags all skip.
  assert.equal(claimLabel({path: ["credentialSubject", "givenName", "und", "nl"]}), "givenName");
  // Short claim names are NOT language tags and must render.
  assert.equal(claimLabel({path: ["org.iso.18013.5.1", "sex"]}), "sex");
  assert.equal(claimLabel({path: ["org.iso.18013.5.1", "age"]}), "age");
  assert.equal(claimLabel({path: ["credentialSubject", "birthDate"]}), "birthDate");
  // The full ISO 639-1 registry — non-EU codes — skip too.
  assert.equal(claimLabel({path: ["credentialSubject", "familyName", "nb"]}), "familyName");
  assert.equal(claimLabel({path: ["credentialSubject", "familyName", "nn"]}), "familyName");
  assert.equal(claimLabel({path: ["credentialSubject", "name", "zh-Hant"]}), "name");
  assert.equal(claimLabel({path: ["credentialSubject", "name", "ar"]}), "name");
  assert.equal(claimLabel({path: ["credentialSubject", "name", "ru"]}), "name");
  // An explicit id on a language-map path still wins.
  assert.equal(claimLabel({id: "Title", path: ["credentialSubject", "hasClaim", "title", "nl"]}), "Title");
  // Singleton and empty paths never collapse past the first segment.
  assert.equal(claimLabel({path: ["en"]}), "en");
  assert.equal(claimLabel({path: []}), "claim");
  assert.equal(claimLabel({}), "claim");
  // Scalar claims whose name collides with a language code render intact:
  // a language map descends under a claim name, never sits directly under
  // the payload root — "id" (Indonesian in ISO 639-1) is a claim here.
  assert.equal(claimLabel({path: ["credentialSubject", "id"]}), "id");
  assert.equal(claimLabel({path: ["credentialSubject", "en"]}), "en");
});

class FakeElement {
  constructor(tagName) {
    this.tagName = tagName;
    this.children = [];
    this.open = false;
  }
  append(...nodes) {
    for (const node of nodes) node.parentNode = this;
    this.children.push(...nodes);
  }
  replaceChildren() {
    for (const node of this.children) node.parentNode = null;
    this.children = [];
  }
  remove() {
    if (!this.parentNode) return;
    this.parentNode.children = this.parentNode.children.filter((node) => node !== this);
    this.parentNode = null;
  }
  setAttribute(name, value) { this[name] = value; }
  addEventListener() {}
  showModal() { this.open = true; }
  close() { this.open = false; }
}

// The DOM/window env the render tests need — one installer, so the per-test
// fixture is a single call.
function withFakeDom(test) {
  const previousDocument = globalThis.document;
  const previousWindow = globalThis.window;
  globalThis.document = {createElement: (tagName) => new FakeElement(tagName)};
  globalThis.window = {location: {assign(uri) { this.href = uri; }}};
  try {
    return test();
  } finally {
    globalThis.document = previousDocument;
    globalThis.window = previousWindow;
  }
}

test("the poll polls through transient errors and stops on a terminal status with its reason", async () => {
  const previousFetch = globalThis.fetch;
  const previousWindow = globalThis.window;
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    if (calls === 1) throw new TypeError("network down"); // transient: poll on
    return {
      ok: true,
      json: async () => ({
        status: "failed",
        description: "the credential's status list could not be verified: status list token carries no x5c chain",
      }),
    };
  };
  globalThis.window = {setTimeout: (resolve) => resolve()};
  try {
    const flow = Object.create(PresentationFlow.prototype);
    flow.runId = 0;
    flow.pollMs = 0;
    await assert.rejects(
      flow.poll("/status", 0),
      /status list token carries no x5c chain/,
      "the verifier's reason surfaces, not a generic message",
    );
    assert.equal(calls, 2, "one transient error polled through; the terminal status stopped the poll");
  } finally {
    globalThis.fetch = previousFetch;
    globalThis.window = previousWindow;
  }
});

test("QR launches reuse one modal and completion uses the complete page", () => {
  withFakeDom(() => {
    const root = new FakeElement("div");
    const flow = Object.create(PresentationFlow.prototype);
    flow.root = root;
    flow.backendOrigins = ["https://verifier.example"];
    flow.setStatus = () => {};
    flow.setBusy(true);
    const payload = {authorization_request: "openid4vp://one", qr_code: "<svg>one</svg>"};
    flow.renderLaunch("qr", payload);
    const dialog = flow.launchDialog;
    const childCount = dialog.children.length;
    flow.renderLaunch("qr", {authorization_request: "openid4vp://two", qr_code: "<svg>two</svg>"});
    assert.equal(flow.launchDialog, dialog);
    assert.equal(root.children.filter((child) => child === dialog).length, 1);
    assert.equal(dialog.children.length, childCount);
    assert.equal(dialog.open, true);
    assert.equal(dialog.children.some((child) => child.className === "siros-spinner"), false);
    assert.equal(flow.busySpinner.children.length, 0);
    dialog.close();
    flow.setBusy(false);
    flow.renderResult({redirect_uri: "https://verifier.example/vp/complete?response_code=code"});
    assert.equal(dialog.open, false);
    assert.equal(window.location.href, "https://verifier.example/vp/complete?response_code=code");
    flow.renderError(new Error("no matching credential"));
    assert.equal(dialog.open, false);
    assert.equal(flow.outcome.children[0].textContent, "Presentation failed");
    assert.equal(flow.outcome.children.at(-1).href, "/");
  });
});

test("the root busy spinner is removed after every run", () => {
  const previousDocument = globalThis.document;
  const previousWindow = globalThis.window;
  globalThis.document = {createElement: (tagName) => new FakeElement(tagName)};
  globalThis.window = {location: {assign() {}}};
  try {
    const root = new FakeElement("div");
    const flow = Object.create(PresentationFlow.prototype);
    flow.root = root;
    flow.backendOrigins = ["https://verifier.example"];
    flow.setStatus = () => {};
    for (const id of ["one", "two"]) {
      flow.setBusy(true);
      flow.renderLaunch("qr", {authorization_request: `openid4vp://${id}`, qr_code: `<svg>${id}</svg>`});
      flow.setBusy(false);
      assert.equal(flow.busySpinner, null);
      assert.equal(root.children.some((child) => child.className === "siros-spinner"), false);
      flow.renderResult({redirect_uri: "https://verifier.example/vp/complete?response_code=code"});
    }
  } finally {
    globalThis.document = previousDocument;
    globalThis.window = previousWindow;
  }
});

test("direct links do not open the QR modal", () => {
  withFakeDom(() => {
    const root = new FakeElement("div");
    const flow = Object.create(PresentationFlow.prototype);
    flow.root = root;
    flow.backendOrigins = ["https://verifier.example"];
    flow.setStatus = () => {};
    flow.renderLaunch("link", {authorization_request: "openid4vp://direct"});
    assert.equal(flow.launchDialog, undefined);
    assert.equal(flow.directLink.href, "openid4vp://direct");
    flow.renderResult({redirect_uri: "https://verifier.example/vp/complete?response_code=code"});
    assert.equal(flow.launchDialog, undefined);
    assert.equal(window.location.href, "https://verifier.example/vp/complete?response_code=code");
    flow.renderError(new Error("no matching credential"));
    assert.equal(flow.outcome.children[0].textContent, "Presentation failed");
    assert.equal(flow.outcome.children.at(-1).href, "/");
  });
});

test("a preset starts with nothing preselected", () => {
  const requested = {credentials: [{id: "eudi_pid", format: "dc+sd-jwt", claims: [{path: ["given_name"]}, {path: ["family_name"]}]}]};
  const available = [{id: "eudi_pid", claims: [{path: ["given_name"]}, {path: ["family_name"]}]}];
  const none = setSelectedClaims(requested, available, []);
  assert.deepEqual(none.credentials[0].claims, [], "the preset's claims are not the selection, but the member stays explicit");
});

test("applyPreset clears the claims and renderClaims draws unchecked checkboxes", () => {
  const previousDocument = globalThis.document;
  globalThis.document = {createElement: (tagName) => new FakeElement(tagName)};
  try {
    const preset = {
      label: "PID",
      dcql: {credentials: [{id: "eudi_pid", format: "dc+sd-jwt", claims: [{path: ["given_name"]}, {path: ["family_name"]}]}]},
    };
    const flow = Object.create(PresentationFlow.prototype);
    flow.claims = new FakeElement("fieldset");
    flow.claimsList = new FakeElement("div");
    flow.editor = new FakeElement("textarea");
    flow.setStatus = () => {};
    flow.presets = [preset];
    flow.applyPreset(0);
    assert.deepEqual(flow.currentDcql.credentials[0].claims, [], "nothing is preselected, the claims member stays explicit");
    const group = flow.claimsList.children[0];
    assert.equal(group.className, "claim-group");
    // A single-credential preset shows no per-credential heading (the
    // fieldset legend suffices), so every child is a checkbox label.
    const boxes = group.children.filter((child) => child.tagName === "label");
    assert.equal(boxes.length, 2, "one checkbox per available claim");
    assert.ok(boxes.every((label) => label.children[0].checked === false), "all boxes start unchecked");
    assert.equal(flow.claims.disabled, false, "claims exist, so the fieldset is enabled");
  } finally {
    globalThis.document = previousDocument;
  }
});

test("an empty claim list disables the fieldset", () => {
  const previousDocument = globalThis.document;
  globalThis.document = {createElement: (tagName) => new FakeElement(tagName)};
  try {
    const flow = Object.create(PresentationFlow.prototype);
    flow.claims = new FakeElement("fieldset");
    flow.claimsList = new FakeElement("div");
    flow.currentDcql = {credentials: []};
    flow.availableClaims = [];
    flow.renderClaims();
    assert.equal(flow.claimsList.children.length, 0);
    assert.equal(flow.claims.disabled, true);
  } finally {
    globalThis.document = previousDocument;
  }
});

test("an incomplete catalog never leaves hidden preset claims requested", () => {
  // The preset asks for given_name and birthdate; the available catalog
  // lists only given_name. A selection that checks nothing must still
  // clear birthdate — a stale catalog must never silently keep a hidden
  // preset claim in the request.
  const preset = {credentials: [{id: "eudi_pid", format: "dc+sd-jwt", claims: [{path: ["given_name"]}, {path: ["birthdate"]}]}]};
  const available = [{id: "eudi_pid", claims: [{path: ["given_name"]}]}];
  const none = setSelectedClaims(preset, available, []);
  assert.deepEqual(none.credentials[0].claims, [], "the unlisted birthdate is cleared too");
  const onlyGiven = setSelectedClaims(preset, available, ["0:0"]);
  assert.deepEqual(onlyGiven.credentials[0].claims, [{path: ["given_name"]}]);
});

test("a zkp_req preset keeps its _req shape through the claim clearing", () => {
  const preset = {credentials: [{id: "nym_attestation", format: "zkp_req", _req: [{fn_id: "pseudonym"}]}]};
  const cleared = setSelectedClaims(preset, [{id: "nym_attestation", claims: []}], []);
  assert.equal("claims" in cleared.credentials[0], false, "a zkp_req credential never gains a claims member");
  assert.deepEqual(cleared.credentials[0]._req, [{fn_id: "pseudonym"}], "the _req shape is untouched");
});

test("a single-credential preset shows no per-credential heading", () => {
  const previousDocument = globalThis.document;
  globalThis.document = {createElement: (tagName) => new FakeElement(tagName)};
  try {
    const flow = Object.create(PresentationFlow.prototype);
    flow.claims = new FakeElement("fieldset");
    flow.claimsList = new FakeElement("div");
    flow.editor = new FakeElement("textarea");
    flow.setStatus = () => {};
    flow.presets = [{label: "PID", dcql: {credentials: [{id: "eudi_pid", format: "dc+sd-jwt", claims: [{path: ["given_name"]}]}]}}];
    flow.applyPreset(0);
    const group = flow.claimsList.children[0];
    // The only child with a heading class would be the claim-group-name:
    // absent, because one credential means the fieldset legend suffices.
    const headings = group.children.filter((child) => child.className === "claim-group-name");
    assert.equal(headings.length, 0, "no per-credential heading for a single query");
  } finally {
    globalThis.document = previousDocument;
  }
});

test("a multi-credential preset shows per-credential headings", () => {
  const previousDocument = globalThis.document;
  globalThis.document = {createElement: (tagName) => new FakeElement(tagName)};
  try {
    const flow = Object.create(PresentationFlow.prototype);
    flow.claims = new FakeElement("fieldset");
    flow.claimsList = new FakeElement("div");
    flow.editor = new FakeElement("textarea");
    flow.setStatus = () => {};
    flow.currentDcql = {credentials: [{id: "pid"}, {id: "photo"}]};
    flow.availableClaims = [
      {id: "pid", claims: [{path: ["given_name"]}]},
      {id: "photo", claims: [{path: ["portrait"]}]},
    ];
    flow.renderClaims();
    const groups = flow.claimsList.children;
    assert.equal(groups.length, 2);
    const heading0 = groups[0].children[0];
    const heading1 = groups[1].children[0];
    assert.equal(heading0.className, "claim-group-name");
    assert.equal(heading0.textContent, "pid");
    assert.equal(heading1.textContent, "photo");
  } finally {
    globalThis.document = previousDocument;
  }
});

test("nested claims group under their parent path, top-level claims stay bare", () => {
  const previousDocument = globalThis.document;
  globalThis.document = {createElement: (tagName) => new FakeElement(tagName)};
  try {
    const flow = Object.create(PresentationFlow.prototype);
    flow.claims = new FakeElement("fieldset");
    flow.claimsList = new FakeElement("div");
    flow.currentDcql = {credentials: [{id: "vat"}]};
    flow.availableClaims = [{id: "vat", claims: [
      {path: ["name"]},
      {path: ["trust_anchor"]},
      {path: ["issuer", "location_status"]},
      {path: ["issuer", "vat_id_authentic_source"]},
      {path: ["administrative_unit", "name"]},
      {path: ["administrative_unit", "vat_id"]},
    ]}];
    flow.renderClaims();
    const group = flow.claimsList.children[0];
    // First: the top-level claims (no parent heading)
    const firstChild = group.children[0];
    assert.equal(firstChild.tagName, "label", "top-level claims render before parent groups");
    // Then: the "issuer" parent heading
    const issuerHeading = group.children.find((child) => child.className === "claim-parent-name" && child.textContent === "issuer");
    assert.ok(issuerHeading, "the issuer sub-heading exists");
    const adminHeading = group.children.find((child) => child.className === "claim-parent-name" && child.textContent === "administrative_unit");
    assert.ok(adminHeading, "the administrative_unit sub-heading exists");
    // The parents appear in the order they first occur in the claim list
    const parents = group.children.filter((child) => child.className === "claim-parent-name");
    assert.deepEqual(parents.map((p) => p.textContent), ["issuer", "administrative_unit"]);
  } finally {
    globalThis.document = previousDocument;
  }
});

test("mdoc namespaced claims group under the doctype path", () => {
  const previousDocument = globalThis.document;
  globalThis.document = {createElement: (tagName) => new FakeElement(tagName)};
  try {
    const flow = Object.create(PresentationFlow.prototype);
    flow.claims = new FakeElement("fieldset");
    flow.claimsList = new FakeElement("div");
    flow.currentDcql = {credentials: [{id: "pid"}]};
    flow.availableClaims = [{id: "pid", claims: [
      {path: ["eu.europa.ec.eudi.pid.1", "given_name"]},
      {path: ["eu.europa.ec.eudi.pid.1", "family_name"]},
    ]}];
    flow.renderClaims();
    const group = flow.claimsList.children[0];
    const parent = group.children.find((child) => child.className === "claim-parent-name");
    assert.equal(parent.textContent, "eu.europa.ec.eudi.pid.1");
  } finally {
    globalThis.document = previousDocument;
  }
});

test("top-level claims render before nested groups regardless of input order", () => {
  const previousDocument = globalThis.document;
  globalThis.document = {createElement: (tagName) => new FakeElement(tagName)};
  try {
    const flow = Object.create(PresentationFlow.prototype);
    flow.claims = new FakeElement("fieldset");
    flow.claimsList = new FakeElement("div");
    flow.currentDcql = {credentials: [{id: "vat"}]};
    // A nested claim FIRST, then a top-level claim: the top-level one must
    // not visually appear under the nested heading.
    flow.availableClaims = [{id: "vat", claims: [
      {path: ["issuer", "location_status"]},
      {path: ["trust_anchor"]},
      {path: ["administrative_unit", "name"]},
    ]}];
    flow.renderClaims();
    const group = flow.claimsList.children[0];
    // The first element must be the top-level claim (a label), not a
    // claim-parent-name heading: the empty-parent group sorts first.
    assert.equal(group.children[0].tagName, "label", "the top-level claim renders before the issuer heading");
    const parents = group.children.filter((child) => child.className === "claim-parent-name");
    assert.deepEqual(parents.map((p) => p.textContent), ["issuer", "administrative_unit"]);
  } finally {
    globalThis.document = previousDocument;
  }
});
