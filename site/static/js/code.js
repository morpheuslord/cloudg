/* Code blocks: language tabs kept in sync across the page, and copy buttons. */
import { $, $$, announce, store, wrap } from "./util.js";

const TAB_KEY = "cloudg-docs-tab";

/* How far each key moves the selection from tab `i` of `count`. */
const TAB_STEPS = new Map([
  ["ArrowRight", () => 1],
  ["ArrowLeft", () => -1],
  ["Home", (i) => -i],
  ["End", (i, count) => count - 1 - i]
]);

function selectTab(group, label) {
  const tabs = $$(".code-tab", group);
  if (!tabs.some((t) => t.getAttribute("data-tab") === label)) return;
  tabs.forEach((t) => {
    const on = t.getAttribute("data-tab") === label;
    t.setAttribute("aria-selected", on ? "true" : "false");
    t.tabIndex = on ? 0 : -1;
  });
  $$(".code-pane", group).forEach((p) => { p.hidden = p.getAttribute("data-tab") !== label; });
}

function onTabClick(tab, groups) {
  const label = tab.getAttribute("data-tab");
  const before = tab.getBoundingClientRect().top;
  groups.forEach((g) => selectTab(g, label));
  store(TAB_KEY, label);
  // keep the clicked block where it was while blocks above change height
  const after = tab.getBoundingClientRect().top;
  if (Math.abs(after - before) > 1) window.scrollBy(0, after - before);
}

function onTabKey(e, tabs, i) {
  const step = TAB_STEPS.get(e.key);
  const dir = step ? step(i, tabs.length) : 0;
  if (!dir) return;
  e.preventDefault();
  const next = tabs.at(wrap(i, dir, tabs.length));
  next.click();
  next.focus();
}

function wireGroup(group, gi, groups) {
  const tabs = $$(".code-tab", group);
  const panes = $$(".code-pane", group);
  tabs.forEach((tab, i) => {
    tab.id = "ct-" + gi + "-" + i;
    const pane = panes.at(i);
    if (pane) pane.setAttribute("aria-labelledby", tab.id);
    tab.addEventListener("click", () => onTabClick(tab, groups));
    tab.addEventListener("keydown", (e) => onTabKey(e, tabs, i));
  });
}

export function initCodeTabs() {
  const groups = $$(".code--tabs");
  groups.forEach((group, gi) => wireGroup(group, gi, groups));
  const saved = store(TAB_KEY);
  if (saved) groups.forEach((g) => selectTab(g, saved));
}

/* Terminal blocks drop comment lines, and in a session (commands mixed with
   their output) only the commands and their continuation lines are copied. */
function keepLine(line, terminal, session) {
  if (!terminal) return true;
  const cls = line.classList;
  if (cls.contains("cmt")) return false;
  return !session || cls.contains("cmd") || cls.contains("cont");
}

function codeText(scope) {
  const pre = $(".code-pre", scope);
  if (!pre) return "";
  const terminal = scope.classList.contains("code--terminal") || Boolean(scope.closest(".code--terminal"));
  const lines = $$(".line", pre);
  const session = lines.some((l) => l.classList.contains("out")) && lines.some((l) => l.classList.contains("cmd"));
  const out = lines
    .filter((l) => keepLine(l, terminal, session))
    .map((l) => l.textContent.replace(/\u00a0/g, " ").replace(/\s+$/, ""));
  let text = out.join("\n").replace(/^\n+|\n+$/g, "");
  if (terminal) text = text.replace(/\n{3,}/g, "\n\n");
  return text + "\n";
}

function legacyCopy(text, resolve, reject) {
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  try {
    if (document.execCommand("copy")) resolve();
    else reject(new Error("copy command was refused"));
  } catch (e) {
    reject(e);
  }
  document.body.removeChild(ta);
}

function writeClipboard(text) {
  if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
  return new Promise((resolve, reject) => legacyCopy(text, resolve, reject));
}

function flash(btn) {
  const label = $(".code-copy-label", btn);
  btn.classList.add("is-copied");
  if (label) label.textContent = "Copied";
  announce("Copied to clipboard");
  clearTimeout(btn._t);
  btn._t = setTimeout(() => {
    btn.classList.remove("is-copied");
    if (label) label.textContent = "Copy";
  }, 2000);
}

function copyBlock(btn) {
  const fig = btn.closest(".code");
  const scope = fig.classList.contains("code--tabs") ? $(".code-pane:not([hidden])", fig) : fig;
  writeClipboard(codeText(scope)).then(() => flash(btn), () => announce("Copy failed"));
}

function copyText(btn) {
  writeClipboard(btn.getAttribute("data-copy-text") + "\n").then(
    () => flash(btn),
    (err) => console.debug("cloudg: copy failed", err)
  );
}

export function initCopy() {
  document.addEventListener("click", (e) => {
    const block = e.target.closest("[data-copy]");
    if (block) {
      copyBlock(block);
      return;
    }
    const inline = e.target.closest("[data-copy-text]");
    if (inline) copyText(inline);
  });
}
