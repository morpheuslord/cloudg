/* Builds the search result list as DOM nodes. Text from the index is only
   ever inserted as text nodes. */
import { h, svg } from "./util.js";
import { snippet } from "./search-rank.js";

const ORDER = ["Guides", "CLI", "Python API", "Config", "MCP", "Reference", "Changelog"];
const PER_GROUP = 8;

/* Character ranges of `text` matched by any term, merged where they overlap. */
function matchRanges(text, terms) {
  const low = text.toLowerCase();
  const ranges = [];
  terms.filter((t) => t.length >= 2).forEach((t) => {
    for (let p = low.indexOf(t); p >= 0; p = low.indexOf(t, p + t.length)) ranges.push({ start: p, end: p + t.length });
  });
  ranges.sort((a, b) => a.start - b.start);
  const merged = [];
  for (const r of ranges) {
    const last = merged.at(-1);
    if (last && r.start < last.end) last.end = Math.max(last.end, r.end);
    else merged.push({ start: r.start, end: r.end });
  }
  return merged;
}

/* `text` as text nodes with each match wrapped in <mark>. */
export function highlight(text, terms) {
  // lower-casing can change the length of some characters; skip marks then
  if (text.toLowerCase().length !== text.length) return [text];
  const parts = [];
  let pos = 0;
  for (const { start, end } of matchRanges(text, terms)) {
    if (start > pos) parts.push(text.slice(pos, start));
    parts.push(h("mark", null, text.slice(start, end)));
    pos = end;
  }
  if (pos < text.length) parts.push(text.slice(pos));
  return parts;
}

function enterIcon() {
  return svg("svg", {
    class: "enter", width: "16", height: "16", viewBox: "0 0 24 24", fill: "none",
    stroke: "currentColor", "stroke-width": "2", "aria-hidden": "true"
  },
  svg("polyline", { points: "9 10 4 15 9 20" }),
  svg("path", { d: "M20 4v7a4 4 0 0 1-4 4H4" }));
}

function hitTitle(d, terms) {
  const title = h("span", { class: "search-hit-title" + (d.m ? " mono" : "") });
  if (d.h) title.append(d.t, " ", h("span", { class: "sub" }, "› ", ...highlight(d.h, terms)));
  else title.append(...highlight(d.t, terms));
  return title;
}

function hitText(d, terms) {
  const text = h("span", { class: "search-hit-text" });
  if (d.g) text.append(d.g + " · ");
  text.append(...highlight(snippet(d.x || "", terms), terms));
  return text;
}

function hitLink(d, i, terms) {
  return h("a", { class: "search-hit", role: "option", id: "sh-" + i, "data-i": String(i), href: d.u },
    h("span", { class: "search-hit-main" }, hitTitle(d, terms), hitText(d, terms)),
    enterIcon());
}

/* Nodes for every group in ORDER, and the entries in display order. */
export function renderHits(grouped, terms) {
  const nodes = [];
  const hits = [];
  ORDER.filter((k) => grouped.has(k)).forEach((k) => {
    nodes.push(h("div", { class: "search-group", role: "presentation" }, k));
    grouped.get(k).slice(0, PER_GROUP).forEach((d) => {
      nodes.push(hitLink(d, hits.length, terms));
      hits.push(d);
    });
  });
  return { nodes, hits };
}

export function promptNode() {
  return h("p", { class: "search-empty" },
    "Type to search. Try ", h("code", null, "rate limit"), ", ", h("code", null, "--org"),
    " or ", h("code", null, "CloudGEngine"), ".");
}

/* "No results" message; inside a filter it offers to search everything. */
export function emptyNode(query, filter, onSearchAll) {
  const p = h("p", { class: "search-empty" }, "No results for ", h("b", null, query));
  if (filter === "All") {
    p.append(".");
    return p;
  }
  const all = h("button", { type: "button", class: "kbd-btn", "data-all": "" }, "Search everything");
  all.addEventListener("click", onSearchAll);
  p.append(" in " + filter + ". ", all);
  return p;
}
