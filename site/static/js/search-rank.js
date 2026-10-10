/* Search index loading and ranking. Entries are {t: title, h: heading,
   x: text, u: url, k: kind, g: group, m: mono title}. */

const MAX_HITS = 40;
const PER_PAGE = 3;

let index = null;
let loading = null;

function prepare(data) {
  data.forEach((d) => {
    d._t = (d.t || "").toLowerCase();
    d._h = (d.h || "").toLowerCase();
    d._x = (d.x || "").toLowerCase();
  });
  index = data;
  return data;
}

export function loadIndex(base) {
  if (index) return Promise.resolve(index);
  if (!loading) loading = fetch(base + "search-index.json").then((r) => r.json()).then(prepare);
  return loading;
}

export function loadedIndex() {
  return index;
}

/* Points for a match at the start of a field, or anywhere else in it. */
function at(pos, start, inside) {
  if (pos === 0) return start;
  return pos > 0 ? inside : 0;
}

/* Score one term against an entry, or -1 when the entry lacks it. */
function termScore(d, term) {
  const inT = d._t.indexOf(term);
  const inH = d._h.indexOf(term);
  const inX = d._x.indexOf(term);
  if (inT < 0 && inH < 0 && inX < 0) return -1;
  return at(inT, 30, 14) + at(inH, 18, 9) + (inX >= 0 ? 2 : 0);
}

function phraseScore(d, phrase) {
  let s = 0;
  if (d._t === phrase) s += 60;
  if (d._h === phrase) s += 30;
  if (d._t.includes(phrase) || d._h.includes(phrase)) s += 12;
  if (!d.h) s += 3;
  return s;
}

function score(d, terms, phrase) {
  let s = 0;
  for (const term of terms) {
    const ts = termScore(d, term);
    if (ts < 0) return 0;
    s += ts;
  }
  return s + phraseScore(d, phrase);
}

/* Best hits first, at most PER_PAGE from any one page. */
function topHits(scored) {
  const perPage = new Map();
  const top = [];
  for (const { d } of scored) {
    if (top.length >= MAX_HITS) break;
    const page = d.u.split("#")[0];
    const seen = (perPage.get(page) || 0) + 1;
    perPage.set(page, seen);
    if (seen <= PER_PAGE) top.push(d);
  }
  return top;
}

/* Returns a Map of kind to its hits, best first. */
export function rank(entries, terms, phrase, filter) {
  const scored = [];
  entries.forEach((d) => {
    if (filter !== "All" && d.k !== filter) return;
    const s = score(d, terms, phrase);
    if (s > 0) scored.push({ s, d });
  });
  scored.sort((a, b) => b.s - a.s);
  const grouped = new Map();
  topHits(scored).forEach((d) => {
    if (!grouped.has(d.k)) grouped.set(d.k, []);
    grouped.get(d.k).push(d);
  });
  return grouped;
}

/* A slice of `text` around the first matching term. */
export function snippet(text, terms) {
  const low = text.toLowerCase();
  let pos = -1;
  terms.forEach((t) => {
    const p = low.indexOf(t);
    if (p >= 0 && (pos < 0 || p < pos)) pos = p;
  });
  if (pos < 60) return text.slice(0, 160);
  return "…" + text.slice(pos - 50, pos + 120);
}
