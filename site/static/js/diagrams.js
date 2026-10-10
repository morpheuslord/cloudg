/* Mermaid diagrams. The library is only fetched on pages that have a
   pre.mermaid block; diagrams take their colours from the site's CSS
   variables and are drawn again when the theme changes. */
import { $$, doc } from "./util.js";

const FONT = "Archivo, system-ui, sans-serif";

let mermaid = null;

function cssVar(name) {
  return getComputedStyle(doc).getPropertyValue(name).trim();
}

function palette() {
  return {
    bg: cssVar("--color-bg"),
    surface: cssVar("--color-surface"),
    text: cssVar("--color-text"),
    muted: cssVar("--color-neutral-700"),
    accent: cssVar("--color-accent"),
    note: cssVar("--color-accent-100")
  };
}

function flowVars(c) {
  return {
    fontSize: "14px",
    background: c.bg,
    primaryColor: c.bg,
    primaryTextColor: c.text,
    primaryBorderColor: c.text,
    secondaryColor: c.surface,
    secondaryTextColor: c.text,
    secondaryBorderColor: c.muted,
    tertiaryColor: c.surface,
    tertiaryTextColor: c.text,
    tertiaryBorderColor: c.muted,
    lineColor: c.muted,
    textColor: c.text,
    mainBkg: c.bg,
    nodeBorder: c.text,
    clusterBkg: c.surface,
    clusterBorder: c.muted,
    edgeLabelBackground: c.bg,
    titleColor: c.text
  };
}

function sequenceVars(c) {
  return {
    actorBkg: c.bg,
    actorBorder: c.text,
    actorTextColor: c.text,
    actorLineColor: c.muted,
    signalColor: c.text,
    signalTextColor: c.text,
    labelBoxBkgColor: c.surface,
    labelBoxBorderColor: c.muted,
    labelTextColor: c.text,
    loopTextColor: c.text,
    noteBkgColor: c.note,
    noteBorderColor: c.accent,
    noteTextColor: c.text,
    activationBkgColor: c.surface,
    activationBorderColor: c.text,
    sequenceNumberColor: c.bg
  };
}

function stateVars(c) {
  return {
    stateBkg: c.bg,
    stateBorder: c.text,
    transitionColor: c.muted,
    specialStateColor: c.accent,
    altBackground: c.surface,
    compositeBackground: c.surface,
    compositeTitleBackground: c.surface,
    innerEndBackground: c.text,
    errorBkgColor: c.accent,
    errorTextColor: "#fff"
  };
}

function themeCss(bg) {
  return [
    ".node rect, .node polygon, .cluster rect, rect.actor, .note, .labelBox, rect.stateGroup, .statediagram-state rect { rx: 0 !important; ry: 0 !important; }",
    ".node rect, .node polygon, .node circle, rect.actor { stroke-width: 2px; }",
    ".edgeLabel, .edgeLabel p, .edgeLabel span { font-family: 'JetBrains Mono', monospace; font-size: 12px; }",
    ".edgeLabel rect, .labelBkg { fill: " + bg + " !important; background: " + bg + " !important; }",
    ".flowchart-link, .messageLine0, .messageLine1, .transition { stroke-width: 1.5px; }",
    ".messageText, .noteText, .labelText, .loopText { font-family: " + FONT + "; }"
  ].join("");
}

function mermaidConfig() {
  const c = palette();
  return {
    startOnLoad: false,
    securityLevel: "strict",
    theme: "base",
    darkMode: doc.getAttribute("data-theme") === "dark",
    fontFamily: FONT,
    flowchart: { curve: "linear", padding: 14, nodeSpacing: 38, rankSpacing: 46, htmlLabels: true, useMaxWidth: true },
    sequence: { useMaxWidth: true, mirrorActors: false, actorMargin: 40, boxMargin: 8 },
    themeVariables: Object.assign(flowVars(c), sequenceVars(c), stateVars(c)),
    themeCSS: themeCss(c.bg)
  };
}

/* Put the diagram source back so mermaid draws it again. */
function resetBlock(pre, force) {
  if (!pre._src) pre._src = pre.textContent;
  if (force || !pre.getAttribute("data-processed")) {
    pre.removeAttribute("data-processed");
    pre.textContent = pre._src;
  }
}

export function renderDiagrams(force) {
  const blocks = $$("pre.mermaid");
  if (!mermaid || !blocks.length) return;
  mermaid.initialize(mermaidConfig());
  blocks.forEach((pre) => resetBlock(pre, force));
  mermaid.run({ nodes: blocks, suppressErrors: true }).catch((err) => {
    console.debug("cloudg: diagram render failed", err);
  });
}

export function initDiagrams() {
  if (!document.querySelector("pre.mermaid")) return;
  import("https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs")
    .then((mod) => {
      mermaid = mod.default;
      renderDiagrams(false);
    })
    .catch((err) => console.debug("cloudg: mermaid failed to load", err));
}
