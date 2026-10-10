/* Page chrome: TOC scroll spy, mobile sidebar drawer, version menu and the
   feedback box. */
import { $, $$, announce, wrap } from "./util.js";

/* Scroll `box` so `item` sits about a third of the way down when it is near
   or past either edge. */
function keepInView(item, box) {
  const r = item.getBoundingClientRect();
  const b = box.getBoundingClientRect();
  if (r.top < b.top + 40 || r.bottom > b.bottom - 40) box.scrollTop += r.top - b.top - b.height / 3;
}

function tocTarget(link) {
  try {
    return document.getElementById(decodeURIComponent(link.getAttribute("href").slice(1)));
  } catch (e) {
    return null;
  }
}

function activeIndex(targets) {
  let idx = 0;
  targets.forEach((t, i) => {
    if (t && t.getBoundingClientRect().top < 160) idx = i;
  });
  return idx;
}

function makeSpy(links, targets) {
  return function setActive() {
    const idx = activeIndex(targets);
    links.forEach((a, i) => a.classList.toggle("is-active", i === idx));
    const active = links.at(idx);
    const box = active && active.closest(".toc");
    if (box) keepInView(active, box);
  };
}

export function initToc() {
  const links = $$("[data-toc] a");
  if (!links.length || !("IntersectionObserver" in window)) return;
  const targets = links.map(tocTarget);
  const setActive = makeSpy(links, targets);
  const io = new IntersectionObserver(setActive, { rootMargin: "-100px 0px -60% 0px" });
  targets.forEach((t) => { if (t) io.observe(t); });
  let ticking = false;
  window.addEventListener("scroll", () => {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(() => { setActive(); ticking = false; });
  }, { passive: true });
  setActive();
}

function scrollActiveIntoSidebar(sidebar) {
  const link = $(".is-active", sidebar);
  if (!link) return;
  const r = link.getBoundingClientRect();
  const s = sidebar.getBoundingClientRect();
  if (r.bottom > s.bottom - 40) sidebar.scrollTop = r.top - s.top - s.height / 3;
}

/* Returns a function that closes the drawer if it is open, for Escape. */
export function initDrawer() {
  const sidebar = $("[data-sidebar]");
  const scrim = $("[data-scrim]");
  const menuBtn = $("[data-menu]");
  if (!sidebar) return () => false;
  const setDrawer = (open) => {
    sidebar.classList.toggle("is-open", open);
    if (scrim) scrim.hidden = !open;
    if (menuBtn) menuBtn.setAttribute("aria-expanded", open ? "true" : "false");
    const first = open && ($(".is-active", sidebar) || $("a", sidebar));
    if (first) first.focus();
  };
  if (menuBtn) menuBtn.addEventListener("click", () => setDrawer(!sidebar.classList.contains("is-open")));
  if (scrim) scrim.addEventListener("click", () => setDrawer(false));
  sidebar.addEventListener("click", (e) => { if (e.target.closest("a")) setDrawer(false); });
  scrollActiveIntoSidebar(sidebar);
  return () => {
    if (sidebar.classList.contains("is-open")) setDrawer(false);
  };
}

const MENU_STEPS = new Map([["ArrowDown", 1], ["ArrowUp", -1]]);

function onMenuKey(e, menu, close) {
  if (e.key === "Escape") {
    close();
    return;
  }
  const step = MENU_STEPS.get(e.key);
  if (!step) return;
  e.preventDefault();
  const items = $$("a", menu);
  items.at(wrap(items.indexOf(document.activeElement), step, items.length)).focus();
}

export function initVersionMenu() {
  const button = $("[data-version-toggle]");
  const menu = $("[data-version-menu]");
  if (!button || !menu) return;
  const setOpen = (open) => {
    menu.hidden = !open;
    button.setAttribute("aria-expanded", open ? "true" : "false");
    const first = open && $("a", menu);
    if (first) first.focus();
  };
  button.addEventListener("click", (e) => { e.stopPropagation(); setOpen(menu.hidden); });
  document.addEventListener("click", (e) => { if (!e.target.closest(".ver")) setOpen(false); });
  menu.addEventListener("keydown", (e) => onMenuKey(e, menu, () => { setOpen(false); button.focus(); }));
}

export function initFeedback() {
  const yes = $("[data-feedback-yes]");
  if (!yes) return;
  yes.addEventListener("click", () => {
    const box = yes.closest("[data-feedback]");
    $$(".btn, .feedback-q", box).forEach((el) => { el.hidden = true; });
    $(".feedback-thanks", box).hidden = false;
    announce("Thanks for the feedback");
  });
}
