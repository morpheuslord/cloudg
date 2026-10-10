/* Small DOM and storage helpers shared by the docs modules. */

export const doc = document.documentElement;

export function store(key, value) {
  try {
    if (value === undefined) return localStorage.getItem(key);
    localStorage.setItem(key, value);
  } catch (e) {
    return null;
  }
  return null;
}

export function $(sel, root) {
  return (root || document).querySelector(sel);
}

export function $$(sel, root) {
  return Array.from((root || document).querySelectorAll(sel));
}

const live = $("[data-live]");

export function announce(msg) {
  if (!live) return;
  live.textContent = "";
  setTimeout(() => { live.textContent = msg; }, 30);
}

function build(node, attrs, children) {
  for (const [name, value] of Object.entries(attrs || {})) node.setAttribute(name, value);
  node.append(...children);
  return node;
}

/* Create an HTML element with attributes and children (nodes or strings,
   strings become text nodes). */
export function h(tag, attrs, ...children) {
  return build(document.createElement(tag), attrs, children);
}

export function svg(tag, attrs, ...children) {
  return build(document.createElementNS("http://www.w3.org/2000/svg", tag), attrs, children);
}

/* Move `index` by `step` places in a list of `length` items, wrapping at both ends. */
export function wrap(index, step, length) {
  return (index + step + length) % length;
}
