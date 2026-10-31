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

export function claimLabel(claim) {
  if (claim.id) return claim.id;
  return claim.path?.[claim.path.length - 1] ?? "claim";
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
          else window.location.assign(result.complete_uri);
        } catch (error) {
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
    const section = document.createElement("section");
    section.className = "wallet-launch";
    const heading = document.createElement("h2");
    heading.textContent = mechanism === "qr" ? "Scan with your wallet" : "Open your wallet";
    section.append(heading);
    const anchor = document.createElement("a");
    anchor.href = payload.authorization_request;
    anchor.textContent = "Open the presentation request in your wallet";
    section.append(anchor);
    if (mechanism === "qr") {
      const container = document.createElement("div");
      container.className = "qr-code";
      container.innerHTML = payload.qr_code;
      section.append(container);
    }
    const details = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = "Authorization request URI";
    const code = document.createElement("code");
    code.textContent = payload.authorization_request;
    details.append(summary, code);
    section.append(details);
    this.root.append(section);
    this.setStatus("Waiting for the wallet response…");
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
            throw new Error(`Presentation ${result.status}; start a new request`);
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
    this.root.querySelector(".siros-spinner")?.remove();
    if (!busy) return;
    const spinner = document.createElement("div");
    spinner.className = "siros-spinner";
    spinner.setAttribute("role", "status");
    spinner.setAttribute("aria-label", "Verification in progress");
    for (const letter of "SIROS") {
      const span = document.createElement("span");
      span.textContent = letter;
      spinner.append(span);
    }
    this.root.append(spinner);
  }

  stopPolling() {
    this.runId += 1;
    this.setBusy(false);
  }
}
