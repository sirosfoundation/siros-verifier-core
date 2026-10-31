import {PresentationFlow} from "./presentation-flow.js";

const catalog = JSON.parse(document.getElementById("presentation-catalog").textContent);
const root = document.getElementById("presentation-app");

// The host can narrow both lists. The TS11-backed demo exposes all three
// mechanisms and the native schemes recognized by the SIROS sample wallet.
new PresentationFlow({
  root,
  presets: catalog.presets,
  invocations: catalog.invocations ?? ["qr", "dc-api", "link"],
  schemes: catalog.schemes ?? ["openid4vp"],
  startPath: catalog.startPath ?? "/ui/start",
});
