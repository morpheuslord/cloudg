/* Light and dark theme: the toggle button wins, otherwise follow the OS. */
import { $, doc, store } from "./util.js";

const THEME_KEY = "cloudg-docs-theme";

export function initTheme(onChange) {
  const button = $("[data-theme-toggle]");
  if (button) {
    button.addEventListener("click", () => {
      const next = doc.getAttribute("data-theme") === "dark" ? "light" : "dark";
      doc.setAttribute("data-theme", next);
      store(THEME_KEY, next);
      onChange();
    });
  }
  const mq = window.matchMedia ? matchMedia("(prefers-color-scheme: dark)") : null;
  if (!mq || !mq.addEventListener) return;
  mq.addEventListener("change", (e) => {
    if (store(THEME_KEY)) return;
    doc.setAttribute("data-theme", e.matches ? "dark" : "light");
    onChange();
  });
}
