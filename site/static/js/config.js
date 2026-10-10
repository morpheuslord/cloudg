/* Config reference page: hovering a key row highlights its YAML line and
   hovering a YAML line highlights its key row. */
import { $, $$ } from "./util.js";

function lineOf(row) {
  return parseInt(row.getAttribute("data-line"), 10);
}

function revealLine(line) {
  const pre = line.closest(".code-pre");
  const lr = line.getBoundingClientRect();
  const pr = pre.getBoundingClientRect();
  if (lr.top < pr.top || lr.bottom > pr.bottom) pre.scrollTop += lr.top - pr.top - pr.height / 2;
}

function wire(cfg, rows, lines) {
  const clear = () => $$(".is-hot", cfg).forEach((el) => el.classList.remove("is-hot"));
  const hot = (row) => {
    clear();
    row.classList.add("is-hot");
    const n = lineOf(row);
    const line = n >= 0 ? lines.at(n) : null;
    if (!line) return;
    line.classList.add("is-hot");
    revealLine(line);
  };
  rows.forEach((row) => {
    row.addEventListener("mouseenter", () => hot(row));
    row.addEventListener("focusin", () => hot(row));
  });
  lines.forEach((line, i) => {
    line.addEventListener("mouseenter", () => {
      const row = rows.find((r) => lineOf(r) === i);
      clear();
      line.classList.add("is-hot");
      if (row) row.classList.add("is-hot");
    });
  });
  cfg.addEventListener("mouseleave", clear);
  return hot;
}

export function initConfigHighlight() {
  const cfg = $("[data-cfg]");
  if (!cfg) return;
  const hot = wire(cfg, $$(".cfg-row[data-line]", cfg), $$(".cfg-yaml .line", cfg));
  if (!location.hash) return;
  const target = document.getElementById(decodeURIComponent(location.hash.slice(1)));
  if (target && target.classList.contains("cfg-row")) hot(target);
}
