// Reusable, framework-free OpenID4VP presentation flow.
// The host supplies registry-derived presets and the invocation mechanisms it
// wants to offer. The verifier remains the authority for DCQL validation.

export const SUPPORTED_INVOCATIONS = Object.freeze(["qr", "dc-api", "link"]);
export const SUPPORTED_SCHEMES = Object.freeze([
  "openid4vp",
  "haip",
  "haip-vp",
  "mdoc-openid4vp",
]);

export function normalizeInvocations(values) {
  if (!Array.isArray(values)) throw new TypeError("invocations must be an array");
  const result = [...new Set(values)];
  if (!result.length || result.some((v) => !SUPPORTED_INVOCATIONS.includes(v))) {
    throw new RangeError(`invocations must contain only ${SUPPORTED_INVOCATIONS.join(", ")}`);
  }
  return result;
}

export function normalizeSchemes(values) {
  if (!Array.isArray(values)) throw new TypeError("schemes must be an array");
  const result = [...new Set(values)];
  if (!result.length || result.some((v) => !SUPPORTED_SCHEMES.includes(v))) {
    throw new RangeError(`schemes must contain only ${SUPPORTED_SCHEMES.join(", ")}`);
  }
  return result;
}

export function cloneDcql(value) {
  return JSON.parse(JSON.stringify(value));
}

export function assertBackendOrigin(value, allowedOrigins, base = "https://verifier.example") {
  const url = new URL(value, base);
  if (!allowedOrigins.includes(url.origin)) {
    throw new Error(`Refusing a response endpoint outside the verifier backend: ${url.origin}`);
  }
  return url.href;
}

export function claimSelected(dcql, credentialIndex, claim) {
  const claims = dcql.credentials?.[credentialIndex]?.claims ?? [];
  return claims.some((candidate) => JSON.stringify(candidate.path) === JSON.stringify(claim.path));
}

export function setClaimEnabled(dcql, credentialIndex, claim, enabled) {
  const next = cloneDcql(dcql);
  const credential = next.credentials?.[credentialIndex];
  if (!credential) throw new RangeError("unknown credential");
  const claims = credential.claims ?? [];
  const index = claims.findIndex((candidate) => JSON.stringify(candidate.path) === JSON.stringify(claim.path));
  if (enabled && index < 0) claims.push(cloneDcql(claim));
  if (!enabled && index >= 0) claims.splice(index, 1);
  if (claims.length) credential.claims = claims;
  else delete credential.claims;
  return next;
}

export function setSelectedClaims(dcql, availableCredentials, selectedValues) {
  let next = cloneDcql(dcql);
  const selected = new Set(selectedValues);
  for (const [credentialIndex, credential] of availableCredentials.entries()) {
    for (const [claimIndex, claim] of (credential.claims ?? []).entries()) {
      if (!next.credentials?.[credentialIndex]) continue;
      next = setClaimEnabled(next, credentialIndex, claim, selected.has(`${credentialIndex}:${claimIndex}`));
    }
  }
  return next;
}

// A trailing BCP-47 language tag is a JSON-LD language-map key, not a claim
// type: the diploma's paths descend into language maps
// (["credentialSubject","givenName","und"], ["credentialSubject","hasClaim","title","nl"],
// ...,"countryCode","prefLabel","en-US"]). Skip them when deriving a fallback
// label so the selection list shows the claim type, never the language tag.
//
// The primary subtag is checked against the full ISO 639-1 registry (the
// 184 two-letter codes) plus "und" — the finite, stable set of 2-letter
// language primaries — rather than a spelling heuristic, because a pattern
// like /^[a-z]{2,3}$/ also strips real claim names (mdoc's "sex", "age",
// neither of which is a registered 639-1 code). Norwegian Bokmål/Nynorsk
// ("nb"/"nn") are registered 639-1 codes and are covered. Three-letter
// 639-2/3 primaries ("nob", "nno") are NOT in this set: no EU-credential
// claim name collides with the 2-letter registry, and adding the 7,000+
// 639-3 codes would reintroduce the collision risk the curated approach
// exists to avoid. Regional and script variants ("nl-BE", "zh-Hant",
// "en-Latn") split at the first hyphen: the primary must be in the set and
// the remainder must be subtag-shaped (alphanumeric segments).
const ISO_639_1 = "aa ab ae af ak am an ar as av ay az ba be bg bh bi bm bn bo br bs ca ce ch co cr cs cu cv cy da de dv dz ee el en eo es et eu fa ff fi fj fo fr fy ga gd gl gn gu gv ha he hi ho hr ht hu hy hz ia id ie ig ii ik io is it iu ja jv ka kg ki kj kk kl km kn ko kr ks ku kv kw ky la lb lg li ln lo lt lu lv mg mh mi mk ml mn mr ms mt my na nb ne ng nl nn no nr nv ny oc oj om or os pa pi pl ps pt qu rm rn ro ru rw sa sc sd se sg si sk sl sm sn so sq sr ss st su sv sw ta te tg th ti tk tl tn to tr ts tt tw ty ug uk ur uz ve vi vo wa wo xh yi yo za zh zu".split(" ");
const languageTagPrimaries = new Set(["und", ...ISO_639_1]);

function isLanguageTag(segment) {
  if (typeof segment !== "string") return false;
  const [primary, ...subtags] = segment.split("-");
  return languageTagPrimaries.has(primary)
    && subtags.every((subtag) => /^[a-zA-Z0-9]+$/.test(subtag));
}

export function claimLabel(claim) {
  if (claim.id) return claim.id;
  const path = claim.path ?? [];
  // A strippable tag needs at least a payload root AND a claim name before it
  // (root → claimName → tag): a language map always descends under a claim
  // name, never sits directly under the root. A two-segment path
  // (["credentialSubject","id"], ["org.iso.18013.5.1","sex"]) is a scalar
  // claim whose last segment IS the claim name — and some claim names are
  // registered language codes ("id" is Indonesian in ISO 639-1), so they
  // must not be stripped at this depth.
  let last = path.length - 1;
  while (last > 1 && isLanguageTag(path[last])) last -= 1;
  return path[last] ?? "claim";
}

function createSirosSpinner() {
  const spinner = document.createElement("div");
  spinner.className = "siros-spinner";
  spinner.setAttribute("role", "status");
  spinner.setAttribute("aria-label", "Verification in progress");
  return spinner;
}

export class PresentationFlow {
  constructor({root, presets, invocations, schemes = ["openid4vp"], startPath = "/ui/start", tenant = "", backendOrigins = [window.location.origin], dcApiAdapter = null, pollMs = 2000, onResult = null, onError = null}) {
    if (!(root instanceof HTMLElement)) throw new TypeError("root must be an HTMLElement");
    if (!Array.isArray(presets) || !presets.length) throw new TypeError("at least one preset is required");
    this.root = root;
    this.presets = presets;
    this.invocations = normalizeInvocations(invocations);
    this.schemes = normalizeSchemes(schemes);
    this.startPath = startPath.replace(/\/$/, "");
    this.tenant = tenant;
    this.backendOrigins = new Set(backendOrigins);
    this.dcApiAdapter = dcApiAdapter;
    this.pollMs = pollMs;
    this.runId = 0;
    this.onResult = onResult;
    this.onError = onError;
    this.currentDcql = cloneDcql(presets[0].dcql);
    this.render();
  }

  render() {
    this.stopPolling();
    this.root.replaceChildren();
    const form = document.createElement("form");
    form.className = "presentation-flow";
    form.addEventListener("submit", (event) => event.preventDefault());

    const presetLabel = document.createElement("label");
    presetLabel.textContent = "Request preset";
    const preset = document.createElement("select");
    preset.name = "preset";
    for (const [index, item] of this.presets.entries()) {
      preset.add(new Option(item.label ?? item.id, String(index)));
    }
    preset.addEventListener("change", () => this.applyPreset(Number(preset.value)));
    presetLabel.append(preset);
    form.append(presetLabel);

    this.claims = document.createElement("label");
    this.claims.className = "claim-options";
    this.claims.textContent = "Requested attributes (select one or more)";
    this.claimSelect = document.createElement("select");
    this.claimSelect.name = "claims";
    this.claimSelect.multiple = true;
    this.claimSelect.addEventListener("change", () => {
      const selected = Array.from(this.claimSelect.selectedOptions, (option) => option.value);
      this.currentDcql = setSelectedClaims(this.currentDcql, this.availableClaims ?? [], selected);
      this.editor.value = JSON.stringify(this.currentDcql, null, 2);
      this.setStatus("");
    });
    this.claims.append(this.claimSelect);
    form.append(this.claims);

    const editorLabel = document.createElement("label");
    editorLabel.textContent = "DCQL (editable)";
    this.editor = document.createElement("textarea");
    this.editor.name = "dcql";
    this.editor.rows = 18;
    this.editor.spellcheck = false;
    this.editor.addEventListener("input", () => {
      try {
        this.currentDcql = JSON.parse(this.editor.value);
        this.renderClaims();
        this.setStatus("");
      } catch {
        this.setStatus("DCQL is not valid JSON yet; fix it before launching.");
      }
    });
    editorLabel.append(this.editor);
    form.append(editorLabel);

    if (this.invocations.some((v) => v === "qr" || v === "link")) {
      const schemeLabel = document.createElement("label");
      schemeLabel.textContent = "Wallet URI scheme";
      this.scheme = document.createElement("select");
      this.scheme.name = "scheme";
      for (const value of this.schemes) this.scheme.add(new Option(value, value));
      schemeLabel.append(this.scheme);
      form.append(schemeLabel);
    }

    const actions = document.createElement("div");
    actions.className = "flow-actions";
    const labels = {qr: "QR code", "dc-api": "DC API", link: "Direct link"};
    for (const mechanism of this.invocations) {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = labels[mechanism];
      button.addEventListener("click", async () => {
        try {
          const result = await this.start(mechanism);
          if (this.onResult) this.onResult(result);
          else this.renderResult(result);
        } catch (error) {
          this.renderError(error);
          if (this.onError) this.onError(error);
          else this.setStatus(error.message || String(error));
        }
      });
      actions.append(button);
    }
    form.append(actions);
    this.status = document.createElement("p");
    this.status.setAttribute("role", "status");
    this.status.className = "flow-status";
    form.append(this.status);
    this.root.append(form);
    this.applyPreset(0);
  }

  applyPreset(index) {
    const preset = this.presets[index];
    if (!preset) throw new RangeError("unknown preset");
    this.currentDcql = cloneDcql(preset.dcql);
    this.availableClaims = cloneDcql((preset.available_dcql ?? preset.dcql).credentials ?? []);
    this.editor.value = JSON.stringify(this.currentDcql, null, 2);
    this.renderClaims();
    this.setStatus("");
  }

  renderClaims() {
    this.claimSelect.replaceChildren();
    let count = 0;
    for (const [credentialIndex, credential] of (this.availableClaims ?? []).entries()) {
      const group = document.createElement("optgroup");
      group.label = this.currentDcql.credentials?.[credentialIndex]?.id ?? credential.id ?? `Credential ${credentialIndex + 1}`;
      for (const [claimIndex, claim] of (credential.claims ?? []).entries()) {
        const option = document.createElement("option");
        option.value = `${credentialIndex}:${claimIndex}`;
        option.textContent = claimLabel(claim);
        option.selected = claimSelected(this.currentDcql, credentialIndex, claim);
        group.append(option);
        count += 1;
      }
      if (group.children.length) this.claimSelect.append(group);
    }
    this.claimSelect.size = Math.min(6, Math.max(2, count));
    this.claimSelect.disabled = count === 0;
  }

  setStatus(text) {
    if (this.status) this.status.textContent = text;
  }

  assertBackendUrl(value) {
    return assertBackendOrigin(value, [...this.backendOrigins], window.location.href);
  }

  request() {
    try {
      this.currentDcql = JSON.parse(this.editor.value);
    } catch {
      throw new Error("DCQL is not valid JSON");
    }
    return {
      dcql: JSON.stringify(this.currentDcql),
      scheme: this.scheme?.value ?? "openid4vp",
    };
  }

  async start(mechanism) {
    const run = ++this.runId;
    if (mechanism !== "qr" && this.launchDialog?.open) this.launchDialog.close();
    this.setBusy(true);
    this.setStatus("Creating the presentation request…");
    try {
      const {dcql, scheme} = this.request();
      const form = new URLSearchParams();
      form.set("dcql", dcql);
      form.set("scheme", scheme);
      if (this.tenant) form.set("tenant", this.tenant);
      const response = await fetch(`${this.startPath}/${mechanism === "dc-api" ? "dc-api" : "qr"}`, {
        method: "POST",
        headers: {"Content-Type": "application/x-www-form-urlencoded"},
        body: form,
        credentials: "same-origin",
      });
      if (!response.ok) throw new Error(`The verifier rejected the request (HTTP ${response.status})`);
      const payload = await response.json();
      if (mechanism === "dc-api") return await this.startDcApi(payload);
      this.renderLaunch(mechanism, payload);
      return await this.poll(this.assertBackendUrl(payload.status_uri), run);
    } finally {
      if (run === this.runId) this.setBusy(false);
    }
  }

  async startDcApi(payload) {
    if (!this.dcApiAdapter && (!window.DigitalCredential || !navigator.credentials)) {
      throw new Error("This browser does not support the Digital Credentials API. Use QR or a direct link.");
    }
    const protocol = "openid4vp-v1-signed";
    if (!this.dcApiAdapter && typeof DigitalCredential.userAgentAllowsProtocol === "function" &&
        !DigitalCredential.userAgentAllowsProtocol(protocol)) {
      throw new Error("This browser does not allow signed OpenID4VP requests. Use QR or a direct link.");
    }
    this.setStatus("Waiting for your wallet…");
    const options = {digital: {requests: [{protocol, data: {request: payload.request}}]}};
    const credential = this.dcApiAdapter
      ? await this.dcApiAdapter(options)
      : await navigator.credentials.get(options);
    const data = credential.data ?? credential;
    if (data.error) throw new Error(data.error_description || data.error);
    if (typeof data.response !== "string" || !data.response) {
      throw new Error("The wallet returned no encrypted response");
    }
    const form = new URLSearchParams();
    form.set("response", data.response);
    const response = await fetch(this.assertBackendUrl(payload.response_uri), {
      method: "POST",
      headers: {"Content-Type": "application/x-www-form-urlencoded"},
      body: form,
      credentials: "same-origin",
    });
    if (!response.ok) throw new Error(`The verifier rejected the presentation (HTTP ${response.status})`);
    return {status: "done", complete_uri: this.assertBackendUrl(payload.complete_uri)};
  }

  renderLaunch(mechanism, payload) {
    if (mechanism !== "qr") {
      if (!this.directLink) {
        this.directLink = document.createElement("a");
        this.root.append(this.directLink);
      }
      this.directLink.href = payload.authorization_request;
      this.directLink.textContent = "Open the presentation request in your wallet";
      this.setStatus("Waiting for the wallet response…");
      return;
    }
    if (!this.launchDialog) {
      this.launchDialog = document.createElement("dialog");
      this.launchDialog.className = "wallet-launch wallet-launch-dialog";
      this.root.append(this.launchDialog);
    }
    const dialog = this.launchDialog;
    dialog.replaceChildren();
    const heading = document.createElement("h2");
    heading.textContent = "Scan with your wallet";
    dialog.append(heading);
    const container = document.createElement("div");
    container.className = "qr-code";
    container.innerHTML = payload.qr_code;
    dialog.append(container);
    const anchor = document.createElement("a");
    anchor.href = payload.authorization_request;
    anchor.textContent = "Open the presentation request in your wallet";
    dialog.append(anchor);
    const details = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = "Authorization request URI";
    const code = document.createElement("code");
    code.textContent = payload.authorization_request;
    details.append(summary, code);
    dialog.append(details);
    const close = document.createElement("button");
    close.type = "button";
    close.textContent = "Close";
    close.addEventListener("click", () => dialog.close());
    dialog.append(close);
    if (dialog.open) dialog.close();
    if (typeof dialog.showModal === "function") dialog.showModal();
    else dialog.setAttribute("open", "");
    this.setStatus("Waiting for the wallet response…");
  }

  renderResult(result) {
    window.location.assign(result.complete_uri);
  }

  renderError(error) {
    if (this.launchDialog?.open) this.launchDialog.close();
    if (!this.outcome) {
      this.outcome = document.createElement("section");
      this.outcome.className = "presentation-outcome";
      this.root.append(this.outcome);
    }
    this.outcome.replaceChildren();
    const heading = document.createElement("h2");
    heading.textContent = "Presentation failed";
    this.outcome.append(heading);
    const message = document.createElement("p");
    message.textContent = error.message || String(error);
    this.outcome.append(message);
    const back = document.createElement("a");
    back.href = "/";
    back.textContent = "Back to the verifier";
    this.outcome.append(back);
    this.setStatus(error.message || String(error));
  }

  async poll(statusUri, run) {
    while (run === this.runId) {
      try {
        const response = await fetch(statusUri, {credentials: "same-origin"});
        if (response.ok) {
          const result = await response.json();
          if (result.status === "done") {
            result.complete_uri = this.assertBackendUrl(result.complete_uri);
            return result;
          }
          if (["failed", "expired", "unknown"].includes(result.status)) {
            // The verifier's bounded, human-readable reason when it has one —
            // e.g. why a status list was refused — otherwise the bare state.
            throw new Error(result.description || `Presentation ${result.status}; start a new request`);
          }
        }
      } catch (error) {
        if (error.message.startsWith("Presentation ")) throw error;
        // Keep polling through transient network errors; request expiry is authoritative.
      }
      await new Promise((resolve) => window.setTimeout(resolve, this.pollMs));
    }
    throw new Error("Presentation was superseded by a new request");
  }

  setBusy(busy) {
    this.busySpinner?.remove();
    this.busySpinner = null;
    if (!busy) return;
    this.busySpinner = createSirosSpinner();
    this.root.append(this.busySpinner);
  }

  stopPolling() {
    this.runId += 1;
    this.setBusy(false);
  }
}
