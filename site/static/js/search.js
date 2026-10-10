/* Search modal: Ctrl/Cmd K or "/" opens it, Tab cycles the filters, arrow
   keys move through hits, Enter opens one and Escape closes the modal. */
import { $, $$, wrap } from "./util.js";
import { loadIndex, loadedIndex, rank } from "./search-rank.js";
import { emptyNode, promptNode, renderHits } from "./search-view.js";

function isTyping(target) {
  return /INPUT|TEXTAREA|SELECT/.test(target.tagName || "") || target.isContentEditable;
}

function isToggleKey(e) {
  return (e.key === "k" || e.key === "K") && (e.metaKey || e.ctrlKey);
}

class SearchModal {
  constructor(modal) {
    this.modal = modal;
    this.ui = {
      input: $("[data-search-input]", modal),
      results: $("[data-search-results]", modal),
      filterBar: $("[data-search-filters]", modal)
    };
    this.filters = $$("button", this.ui.filterBar);
    this.state = { filter: "All", selected: 0, opener: null };
    this.base = document.body.getAttribute("data-base") || "/";
    this.run = this.run.bind(this);
    this.open = this.open.bind(this);
    this.close = this.close.bind(this);
  }

  hitEls() {
    return $$(".search-hit", this.ui.results);
  }

  select(i) {
    const els = this.hitEls();
    if (!els.length) {
      this.ui.input.removeAttribute("aria-activedescendant");
      return;
    }
    const selected = wrap(i, 0, els.length);
    this.state.selected = selected;
    els.forEach((el, j) => {
      el.classList.toggle("is-selected", j === selected);
      el.setAttribute("aria-selected", j === selected ? "true" : "false");
    });
    const current = els.at(selected);
    this.ui.input.setAttribute("aria-activedescendant", current.id);
    current.scrollIntoView({ block: "nearest" });
  }

  run() {
    const index = loadedIndex();
    const q = this.ui.input.value.trim().toLowerCase();
    if (!index) return;
    const results = this.ui.results;
    if (!q) {
      results.replaceChildren(promptNode());
      return;
    }
    const terms = q.split(/\s+/).filter(Boolean);
    const { nodes } = renderHits(rank(index, terms, q, this.state.filter), terms);
    if (nodes.length) results.replaceChildren(...nodes);
    else results.replaceChildren(emptyNode(q, this.state.filter, () => this.pickFilter("All")));
    this.select(0);
  }

  setFilter(name) {
    this.state.filter = name;
    this.filters.forEach((b) => b.setAttribute("aria-selected", b.getAttribute("data-filter") === name ? "true" : "false"));
    this.run();
  }

  /* Filter change from a click: the input keeps focus for typing. */
  pickFilter(name) {
    this.setFilter(name);
    this.ui.input.focus();
  }

  open() {
    this.state.opener = document.activeElement;
    this.modal.hidden = false;
    document.body.style.overflow = "hidden";
    this.ui.input.focus();
    this.ui.input.select();
    loadIndex(this.base).then(this.run);
  }

  close() {
    const opener = this.state.opener;
    this.modal.hidden = true;
    document.body.style.overflow = "";
    if (opener && opener.focus) opener.focus();
  }
}

function cycleFilter(s, e) {
  const active = document.activeElement;
  if (active !== s.ui.input && !s.ui.filterBar.contains(active)) return;
  e.preventDefault();
  const names = s.filters.map((b) => b.getAttribute("data-filter"));
  const step = e.shiftKey ? -1 : 1;
  s.pickFilter(names.at(wrap(names.indexOf(s.state.filter), step, names.length)));
}

function openSelected(s, e) {
  if (document.activeElement !== s.ui.input) return;
  const el = s.hitEls().at(s.state.selected);
  if (!el) return;
  e.preventDefault();
  // a real click on the link, so the results click handler closes the modal
  el.click();
}

function modalKeys(s) {
  const moveBy = (step) => (e) => {
    e.preventDefault();
    s.select(s.state.selected + step);
  };
  return new Map([
    ["ArrowDown", moveBy(1)],
    ["ArrowUp", moveBy(-1)],
    ["Enter", (e) => openSelected(s, e)],
    ["Tab", (e) => cycleFilter(s, e)]
  ]);
}

function onGlobalKey(s, e, onEscape) {
  if (isToggleKey(e)) {
    e.preventDefault();
    if (s.modal.hidden) s.open();
    else s.close();
  } else if (e.key === "/" && s.modal.hidden && !isTyping(e.target)) {
    e.preventDefault();
    s.open();
  } else if (e.key === "Escape") {
    if (s.modal.hidden) onEscape();
    else s.close();
  }
}

function wire(s, onEscape) {
  const { input, results } = s.ui;
  $$("[data-search-open]").forEach((b) => b.addEventListener("click", s.open));
  $$("[data-search-close]", s.modal).forEach((b) => b.addEventListener("click", s.close));
  s.filters.forEach((b) => b.addEventListener("click", () => s.pickFilter(b.getAttribute("data-filter"))));
  document.addEventListener("keydown", (e) => onGlobalKey(s, e, onEscape));
  input.addEventListener("input", s.run);
  results.addEventListener("mousemove", (e) => {
    const a = e.target.closest(".search-hit");
    const i = a ? parseInt(a.getAttribute("data-i"), 10) : s.state.selected;
    if (i !== s.state.selected) s.select(i);
  });
  results.addEventListener("click", (e) => { if (e.target.closest(".search-hit")) s.close(); });
  const keys = modalKeys(s);
  s.modal.addEventListener("keydown", (e) => {
    const handler = keys.get(e.key);
    if (handler) handler(e);
  });
}

/* `onEscape` runs when Escape is pressed while the modal is closed. */
export function initSearch(onEscape) {
  const modal = $("[data-search-modal]");
  if (!modal) return;
  const isMac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
  $$("[data-mod]").forEach((k) => { k.textContent = isMac ? "\u2318" : "Ctrl"; });
  wire(new SearchModal(modal), onEscape);
}
