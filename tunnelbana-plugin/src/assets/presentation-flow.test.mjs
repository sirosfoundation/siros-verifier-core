import test from "node:test";
import assert from "node:assert/strict";
import {
  assertBackendOrigin,
  claimLabel,
  cloneDcql,
  normalizeInvocations,
  normalizeSchemes,
  setClaimEnabled,
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

test("backend responses cannot cross the configured tenant origin", () => {
  assert.equal(assertBackendOrigin("/vp/status", ["https://verifier.example"]), "https://verifier.example/vp/status");
  assert.equal(assertBackendOrigin("https://verifier.example/vp/status", ["https://verifier.example"]), "https://verifier.example/vp/status");
  assert.throws(() => assertBackendOrigin("https://other.example/vp/status", ["https://verifier.example"]));
});

test("claim labels prefer ids and otherwise use the final path segment", () => {
  assert.equal(claimLabel({id: "Given name", path: ["given_name"]}), "Given name");
  assert.equal(claimLabel({path: ["address", "street_address"]}), "street_address");
});
