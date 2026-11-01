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
  assert.equal("claims" in empty.credentials[0], false);
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

test("QR launches reuse one modal and replace its contents", () => {
  const previous = globalThis.document;
  globalThis.document = {createElement: (tagName) => new FakeElement(tagName)};
  try {
    const root = new FakeElement("div");
    const flow = Object.create(PresentationFlow.prototype);
    flow.root = root;
    flow.activeMechanism = "qr";
    flow.setStatus = () => {};
    const payload = {authorization_request: "openid4vp://one", qr_code: "<svg>one</svg>"};
    flow.renderLaunch("qr", payload);
    const dialog = flow.launchDialog;
    const childCount = dialog.children.length;
    flow.renderLaunch("qr", {authorization_request: "openid4vp://two", qr_code: "<svg>two</svg>"});
    assert.equal(flow.launchDialog, dialog);
    assert.equal(root.children.filter((child) => child === dialog).length, 1);
    assert.equal(dialog.children.length, childCount);
    assert.equal(dialog.open, true);
    assert.equal(dialog.children.some((child) => child.className === "siros-spinner"), true);
    dialog.close();
    flow.renderResult({complete_uri: "https://verifier.example/vp/complete"});
    assert.equal(dialog.open, true);
    assert.equal(dialog.children[0].textContent, "Credential verified");
    assert.equal(dialog.children.at(-1).href, "https://verifier.example/vp/complete");
    flow.renderError(new Error("no matching credential"));
    assert.equal(dialog.children[0].textContent, "Presentation failed");
    assert.equal(dialog.children.at(-1).href, "/");
  } finally {
    globalThis.document = previous;
  }
});

test("the root busy spinner is removed after every run", () => {
  const previous = globalThis.document;
  globalThis.document = {createElement: (tagName) => new FakeElement(tagName)};
  try {
    const root = new FakeElement("div");
    const flow = Object.create(PresentationFlow.prototype);
    flow.root = root;
    flow.activeMechanism = "qr";
    flow.setStatus = () => {};
    for (const id of ["one", "two"]) {
      flow.setBusy(true);
      flow.renderLaunch("qr", {authorization_request: `openid4vp://${id}`, qr_code: `<svg>${id}</svg>`});
      flow.setBusy(false);
      assert.equal(flow.busySpinner, null);
      assert.equal(root.children.some((child) => child.className === "siros-spinner"), false);
      flow.renderResult({complete_uri: "https://verifier.example/vp/complete"});
    }
  } finally {
    globalThis.document = previous;
  }
});

test("direct links do not open the QR modal", () => {
  const previous = globalThis.document;
  globalThis.document = {createElement: (tagName) => new FakeElement(tagName)};
  try {
    const root = new FakeElement("div");
    const flow = Object.create(PresentationFlow.prototype);
    flow.root = root;
    flow.activeMechanism = "link";
    flow.setStatus = () => {};
    flow.renderLaunch("link", {authorization_request: "openid4vp://direct"});
    assert.equal(flow.launchDialog, undefined);
    assert.equal(flow.directLink.href, "openid4vp://direct");
    flow.renderResult({complete_uri: "https://verifier.example/vp/complete"});
    assert.equal(flow.launchDialog, undefined);
    assert.equal(flow.outcome.children[0].textContent, "Credential verified");
    assert.equal(flow.outcome.children.at(-1).href, "https://verifier.example/vp/complete");
    flow.renderError(new Error("no matching credential"));
    assert.equal(flow.outcome.children[0].textContent, "Presentation failed");
    assert.equal(flow.outcome.children.at(-1).href, "/");
  } finally {
    globalThis.document = previous;
  }
});
