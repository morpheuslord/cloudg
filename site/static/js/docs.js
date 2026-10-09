/* cloudg docs: theme, code tabs and copy, TOC scroll spy, sidebar drawer,
   version menu, search and diagrams. No dependencies; everything degrades
   to plain HTML when this file doesn't run. */
(function () {
  "use strict";

  var doc = document.documentElement;
  var body = document.body;
  var BASE = body.getAttribute("data-base") || "/";
  var TAB_KEY = "cloudg-docs-tab";
  var THEME_KEY = "cloudg-docs-theme";

  function store(key, value) {
    try {
      if (value === undefined) return localStorage.getItem(key);
      localStorage.setItem(key, value);
    } catch (e) { return null; }
    return null;
  }
  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
  var live = $("[data-live]");
  function announce(msg) { if (live) { live.textContent = ""; setTimeout(function () { live.textContent = msg; }, 30); } }

  /* ── theme ─────────────────────────────────────────────────────────── */
  var themeBtn = $("[data-theme-toggle]");
  if (themeBtn) {
    themeBtn.addEventListener("click", function () {
      var next = doc.getAttribute("data-theme") === "dark" ? "light" : "dark";
      doc.setAttribute("data-theme", next);
      store(THEME_KEY, next);
      renderDiagrams(true);
    });
  }
  var mq = window.matchMedia ? matchMedia("(prefers-color-scheme: dark)") : null;
  if (mq && mq.addEventListener) {
    mq.addEventListener("change", function (e) {
      if (store(THEME_KEY)) return;
      doc.setAttribute("data-theme", e.matches ? "dark" : "light");
      renderDiagrams(true);
    });
  }

  /* ── code tabs ─────────────────────────────────────────────────────── */
  function selectTab(group, label, focus) {
    var tabs = $$(".code-tab", group);
    var found = tabs.some(function (t) { return t.getAttribute("data-tab") === label; });
    if (!found) return false;
    tabs.forEach(function (t) {
      var on = t.getAttribute("data-tab") === label;
      t.setAttribute("aria-selected", on ? "true" : "false");
      t.tabIndex = on ? 0 : -1;
      if (on && focus) t.focus();
    });
    $$(".code-pane", group).forEach(function (p) { p.hidden = p.getAttribute("data-tab") !== label; });
    return true;
  }
  var groups = $$(".code--tabs");
  groups.forEach(function (group, gi) {
    var tabs = $$(".code-tab", group);
    var panes = $$(".code-pane", group);
    tabs.forEach(function (t, i) {
      var id = "ct-" + gi + "-" + i;
      t.id = id;
      if (panes[i]) { panes[i].setAttribute("aria-labelledby", id); }
      t.addEventListener("click", function () {
        var label = t.getAttribute("data-tab");
        var before = t.getBoundingClientRect().top;
        groups.forEach(function (g) { selectTab(g, label, false); });
        store(TAB_KEY, label);
        // keep the clicked block where it was while blocks above change height
        var after = t.getBoundingClientRect().top;
        if (Math.abs(after - before) > 1) window.scrollBy(0, after - before);
      });
      t.addEventListener("keydown", function (e) {
        var dir = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
        if (e.key === "Home") dir = -i;
        if (e.key === "End") dir = tabs.length - 1 - i;
        if (!dir) return;
        e.preventDefault();
        var next = tabs[(i + dir + tabs.length) % tabs.length];
        next.click();
        next.focus();
      });
    });
  });
  var savedTab = store(TAB_KEY);
  if (savedTab) groups.forEach(function (g) { selectTab(g, savedTab, false); });

  /* ── copy ──────────────────────────────────────────────────────────── */
  function codeText(scope) {
    var pre = $(".code-pre", scope);
    if (!pre) return "";
    var terminal = scope.classList.contains("code--terminal") || !!scope.closest(".code--terminal");
    var lines = $$(".line", pre);
    var session = lines.some(function (l) { return l.classList.contains("out"); }) &&
      lines.some(function (l) { return l.classList.contains("cmd"); });
    var out = [];
    lines.forEach(function (l) {
      if (terminal) {
        if (l.classList.contains("cmt")) return;
        if (session && !(l.classList.contains("cmd") || l.classList.contains("cont"))) return;
      }
      out.push(l.textContent.replace(/\u00a0/g, " ").replace(/\s+$/, ""));
    });
    var text = out.join("\n").replace(/^\n+|\n+$/g, "");
    if (terminal) text = text.replace(/\n{3,}/g, "\n\n");
    return text + "\n";
  }
  function writeClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
    return new Promise(function (resolve, reject) {
      var ta = document.createElement("textarea");
      ta.value = text; ta.setAttribute("readonly", ""); ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy") ? resolve() : reject(); } catch (e) { reject(e); }
      document.body.removeChild(ta);
    });
  }
  function flash(btn) {
    var label = $(".code-copy-label", btn);
    btn.classList.add("is-copied");
    if (label) label.textContent = "Copied";
    announce("Copied to clipboard");
    clearTimeout(btn._t);
    btn._t = setTimeout(function () {
      btn.classList.remove("is-copied");
      if (label) label.textContent = "Copy";
    }, 2000);
  }
  document.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-copy]");
    if (btn) {
      var fig = btn.closest(".code");
      var scope = fig.classList.contains("code--tabs") ? $(".code-pane:not([hidden])", fig) : fig;
      writeClipboard(codeText(scope)).then(function () { flash(btn); }, function () { announce("Copy failed"); });
      return;
    }
    var btn2 = e.target.closest("[data-copy-text]");
    if (btn2) {
      writeClipboard(btn2.getAttribute("data-copy-text") + "\n").then(function () { flash(btn2); });
    }
  });

  /* ── TOC scroll spy ────────────────────────────────────────────────── */
  var tocLinks = $$("[data-toc] a");
  if (tocLinks.length && "IntersectionObserver" in window) {
    var targets = tocLinks.map(function (a) {
      try { return document.getElementById(decodeURIComponent(a.getAttribute("href").slice(1))); } catch (e) { return null; }
    });
    var visible = new Set();
    var setActive = function () {
      var idx = -1;
      for (var i = 0; i < targets.length; i++) {
        if (targets[i] && targets[i].getBoundingClientRect().top < 160) idx = i;
      }
      if (idx < 0) idx = 0;
      tocLinks.forEach(function (a, i) { a.classList.toggle("is-active", i === idx); });
      var active = tocLinks[idx];
      var box = active && active.closest(".toc");
      if (box && active) {
        var r = active.getBoundingClientRect(), b = box.getBoundingClientRect();
        if (r.top < b.top + 40 || r.bottom > b.bottom - 40) box.scrollTop += r.top - b.top - b.height / 3;
      }
    };
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) { en.isIntersecting ? visible.add(en.target) : visible.delete(en.target); });
      setActive();
    }, { rootMargin: "-100px 0px -60% 0px" });
    targets.forEach(function (t) { if (t) io.observe(t); });
    var ticking = false;
    window.addEventListener("scroll", function () {
      if (ticking) return;
      ticking = true;
      requestAnimationFrame(function () { setActive(); ticking = false; });
    }, { passive: true });
    setActive();
  }

  /* ── sidebar drawer ────────────────────────────────────────────────── */
  var sidebar = $("[data-sidebar]");
  var scrim = $("[data-scrim]");
  var menuBtn = $("[data-menu]");
  function setDrawer(open) {
    if (!sidebar) return;
    sidebar.classList.toggle("is-open", open);
    if (scrim) scrim.hidden = !open;
    if (menuBtn) menuBtn.setAttribute("aria-expanded", open ? "true" : "false");
    if (open) { var a = $(".is-active", sidebar) || $("a", sidebar); if (a) a.focus(); }
  }
  if (menuBtn) menuBtn.addEventListener("click", function () { setDrawer(!sidebar.classList.contains("is-open")); });
  if (scrim) scrim.addEventListener("click", function () { setDrawer(false); });
  if (sidebar) {
    sidebar.addEventListener("click", function (e) { if (e.target.closest("a")) setDrawer(false); });
    var activeLink = $(".is-active", sidebar);
    if (activeLink) {
      var r = activeLink.getBoundingClientRect(), s = sidebar.getBoundingClientRect();
      if (r.bottom > s.bottom - 40) sidebar.scrollTop = r.top - s.top - s.height / 3;
    }
  }

  /* ── version menu ──────────────────────────────────────────────────── */
  var verBtn = $("[data-version-toggle]");
  var verMenu = $("[data-version-menu]");
  function setVer(open) {
    if (!verMenu) return;
    verMenu.hidden = !open;
    verBtn.setAttribute("aria-expanded", open ? "true" : "false");
    if (open) { var f = $("a", verMenu); if (f) f.focus(); }
  }
  if (verBtn) {
    verBtn.addEventListener("click", function (e) { e.stopPropagation(); setVer(verMenu.hidden); });
    document.addEventListener("click", function (e) { if (!e.target.closest(".ver")) setVer(false); });
    verMenu.addEventListener("keydown", function (e) {
      var items = $$("a", verMenu), i = items.indexOf(document.activeElement);
      if (e.key === "ArrowDown") { e.preventDefault(); items[(i + 1) % items.length].focus(); }
      if (e.key === "ArrowUp") { e.preventDefault(); items[(i - 1 + items.length) % items.length].focus(); }
      if (e.key === "Escape") { setVer(false); verBtn.focus(); }
    });
  }

  /* ── feedback ──────────────────────────────────────────────────────── */
  var yes = $("[data-feedback-yes]");
  if (yes) yes.addEventListener("click", function () {
    var box = yes.closest("[data-feedback]");
    $$(".btn, .feedback-q", box).forEach(function (el) { el.hidden = true; });
    $(".feedback-thanks", box).hidden = false;
    announce("Thanks for the feedback");
  });

  /* ── config page: key rows and YAML lines highlight each other ─────── */
  var cfg = $("[data-cfg]");
  if (cfg) {
    var rows = $$(".cfg-row[data-line]", cfg);
    var lines = $$(".cfg-yaml .line", cfg);
    var clear = function () {
      $$(".is-hot", cfg).forEach(function (el) { el.classList.remove("is-hot"); });
    };
    var hot = function (row) {
      clear();
      var n = parseInt(row.getAttribute("data-line"), 10);
      row.classList.add("is-hot");
      if (n >= 0 && lines[n]) {
        lines[n].classList.add("is-hot");
        var pre = lines[n].closest(".code-pre");
        var lr = lines[n].getBoundingClientRect(), pr = pre.getBoundingClientRect();
        if (lr.top < pr.top || lr.bottom > pr.bottom) pre.scrollTop += lr.top - pr.top - pr.height / 2;
      }
    };
    rows.forEach(function (row) {
      row.addEventListener("mouseenter", function () { hot(row); });
      row.addEventListener("focusin", function () { hot(row); });
    });
    lines.forEach(function (line, i) {
      line.addEventListener("mouseenter", function () {
        var row = rows.filter(function (r) { return parseInt(r.getAttribute("data-line"), 10) === i; })[0];
        clear();
        line.classList.add("is-hot");
        if (row) row.classList.add("is-hot");
      });
    });
    cfg.addEventListener("mouseleave", clear);
    if (location.hash) {
      var target = document.getElementById(decodeURIComponent(location.hash.slice(1)));
      if (target && target.classList.contains("cfg-row")) hot(target);
    }
  }

  /* ── diagrams ──────────────────────────────────────────────────────── */
  function cssVar(name) { return getComputedStyle(doc).getPropertyValue(name).trim(); }
  function renderDiagrams(force) {
    var mermaid = window.__cloudgMermaid;
    var blocks = $$("pre.mermaid");
    if (!mermaid || !blocks.length) return;
    var dark = doc.getAttribute("data-theme") === "dark";
    var bg = cssVar("--color-bg"), surface = cssVar("--color-surface"), text = cssVar("--color-text");
    var muted = cssVar("--color-neutral-700"), accent = cssVar("--color-accent");
    mermaid.initialize({
      startOnLoad: false,
      securityLevel: "strict",
      theme: "base",
      darkMode: dark,
      fontFamily: "Archivo, system-ui, sans-serif",
      flowchart: { curve: "linear", padding: 14, nodeSpacing: 38, rankSpacing: 46, htmlLabels: true, useMaxWidth: true },
      sequence: { useMaxWidth: true, mirrorActors: false, actorMargin: 40, boxMargin: 8 },
      themeVariables: {
        fontSize: "14px",
        background: bg,
        primaryColor: bg,
        primaryTextColor: text,
        primaryBorderColor: text,
        secondaryColor: surface,
        secondaryTextColor: text,
        secondaryBorderColor: muted,
        tertiaryColor: surface,
        tertiaryTextColor: text,
        tertiaryBorderColor: muted,
        lineColor: muted,
        textColor: text,
        mainBkg: bg,
        nodeBorder: text,
        clusterBkg: surface,
        clusterBorder: muted,
        edgeLabelBackground: bg,
        titleColor: text,
        actorBkg: bg,
        actorBorder: text,
        actorTextColor: text,
        actorLineColor: muted,
        signalColor: text,
        signalTextColor: text,
        labelBoxBkgColor: surface,
        labelBoxBorderColor: muted,
        labelTextColor: text,
        loopTextColor: text,
        noteBkgColor: cssVar("--color-accent-100"),
        noteBorderColor: accent,
        noteTextColor: text,
        activationBkgColor: surface,
        activationBorderColor: text,
        sequenceNumberColor: bg,
        stateBkg: bg,
        stateBorder: text,
        transitionColor: muted,
        specialStateColor: accent,
        altBackground: surface,
        compositeBackground: surface,
        compositeTitleBackground: surface,
        innerEndBackground: text,
        errorBkgColor: accent,
        errorTextColor: "#fff"
      },
      themeCSS:
        ".node rect, .node polygon, .cluster rect, rect.actor, .note, .labelBox, rect.stateGroup, .statediagram-state rect { rx: 0 !important; ry: 0 !important; }" +
        ".node rect, .node polygon, .node circle, rect.actor { stroke-width: 2px; }" +
        ".edgeLabel, .edgeLabel p, .edgeLabel span { font-family: 'JetBrains Mono', monospace; font-size: 12px; }" +
        ".edgeLabel rect, .labelBkg { fill: " + bg + " !important; background: " + bg + " !important; }" +
        ".flowchart-link, .messageLine0, .messageLine1, .transition { stroke-width: 1.5px; }" +
        ".messageText, .noteText, .labelText, .loopText { font-family: Archivo, system-ui, sans-serif; }"
    });
    blocks.forEach(function (pre, i) {
      if (!pre._src) pre._src = pre.textContent;
      if (force || !pre.getAttribute("data-processed")) {
        pre.removeAttribute("data-processed");
        pre.innerHTML = "";
        pre.textContent = pre._src;
      }
    });
    mermaid.run({ nodes: blocks, suppressErrors: true }).catch(function () {});
  }
  window.addEventListener("cloudg:mermaid", function () { renderDiagrams(false); });
  if (window.__cloudgMermaid) renderDiagrams(false);

  /* ── search ────────────────────────────────────────────────────────── */
  var modal = $("[data-search-modal]");
  if (!modal) return;
  var input = $("[data-search-input]", modal);
  var results = $("[data-search-results]", modal);
  var filterBar = $("[data-search-filters]", modal);
  var filters = $$("button", filterBar);
  var index = null, loading = null, filter = "All", selected = 0, hits = [], opener = null;
  var ORDER = ["Guides", "CLI", "Python API", "Config", "MCP", "Reference", "Changelog"];
  var isMac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
  $$("[data-mod]").forEach(function (k) { k.textContent = isMac ? "⌘" : "Ctrl"; });

  function loadIndex() {
    if (index) return Promise.resolve(index);
    if (!loading) {
      loading = fetch(BASE + "search-index.json").then(function (r) { return r.json(); }).then(function (data) {
        data.forEach(function (d) {
          d._t = (d.t || "").toLowerCase();
          d._h = (d.h || "").toLowerCase();
          d._x = (d.x || "").toLowerCase();
        });
        index = data;
        return data;
      });
    }
    return loading;
  }
  function openSearch() {
    opener = document.activeElement;
    modal.hidden = false;
    body.style.overflow = "hidden";
    input.focus();
    input.select();
    loadIndex().then(run);
  }
  function closeSearch() {
    modal.hidden = true;
    body.style.overflow = "";
    if (opener && opener.focus) opener.focus();
  }
  $$("[data-search-open]").forEach(function (b) { b.addEventListener("click", openSearch); });
  $$("[data-search-close]", modal).forEach(function (b) { b.addEventListener("click", closeSearch); });
  document.addEventListener("keydown", function (e) {
    var typing = /INPUT|TEXTAREA|SELECT/.test((e.target.tagName || "")) || e.target.isContentEditable;
    if ((e.key === "k" || e.key === "K") && (e.metaKey || e.ctrlKey)) { e.preventDefault(); modal.hidden ? openSearch() : closeSearch(); return; }
    if (e.key === "/" && !typing && modal.hidden) { e.preventDefault(); openSearch(); return; }
    if (e.key === "Escape") {
      if (!modal.hidden) closeSearch();
      else if (sidebar && sidebar.classList.contains("is-open")) setDrawer(false);
    }
  });

  function setFilter(name) {
    filter = name;
    filters.forEach(function (b) { b.setAttribute("aria-selected", b.getAttribute("data-filter") === name ? "true" : "false"); });
    run();
  }
  filters.forEach(function (b) { b.addEventListener("click", function () { setFilter(b.getAttribute("data-filter")); input.focus(); }); });

  function esc(s) { return String(s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }
  function mark(text, terms) {
    var out = esc(text);
    terms.forEach(function (t) {
      if (t.length < 2) return;
      var re = new RegExp("(" + t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + ")", "ig");
      out = out.replace(re, "<mark>$1</mark>");
    });
    return out;
  }
  function snippet(text, terms) {
    var low = text.toLowerCase(), pos = -1;
    terms.forEach(function (t) { var p = low.indexOf(t); if (p >= 0 && (pos < 0 || p < pos)) pos = p; });
    if (pos < 60) return text.slice(0, 160);
    return "…" + text.slice(pos - 50, pos + 120);
  }
  function score(d, terms, phrase) {
    var s = 0;
    for (var i = 0; i < terms.length; i++) {
      var t = terms[i];
      var inT = d._t.indexOf(t), inH = d._h.indexOf(t), inX = d._x.indexOf(t);
      if (inT < 0 && inH < 0 && inX < 0) return 0;
      if (inT === 0) s += 30; else if (inT > 0) s += 14;
      if (inH === 0) s += 18; else if (inH > 0) s += 9;
      if (inX >= 0) s += 2;
    }
    if (d._t === phrase) s += 60;
    if (d._h === phrase) s += 30;
    if (d._t.indexOf(phrase) >= 0 || d._h.indexOf(phrase) >= 0) s += 12;
    if (!d.h) s += 3;
    return s;
  }
  function run() {
    var q = input.value.trim().toLowerCase();
    if (!index) return;
    if (!q) {
      results.innerHTML = '<p class="search-empty">Type to search. Try <code>rate limit</code>, <code>--org</code> or <code>CloudGEngine</code>.</p>';
      hits = [];
      return;
    }
    var terms = q.split(/\s+/).filter(Boolean);
    var scored = [];
    index.forEach(function (d) {
      if (filter !== "All" && d.k !== filter) return;
      var s = score(d, terms, q);
      if (s > 0) scored.push([s, d]);
    });
    scored.sort(function (a, b) { return b[0] - a[0]; });
    var perPage = {};
    var top = [];
    for (var si = 0; si < scored.length && top.length < 40; si++) {
      var d0 = scored[si][1], pageUrl = d0.u.split("#")[0];
      perPage[pageUrl] = (perPage[pageUrl] || 0) + 1;
      if (perPage[pageUrl] <= 3) top.push(d0);
    }
    var grouped = {};
    top.forEach(function (d) { (grouped[d.k] = grouped[d.k] || []).push(d); });
    hits = [];
    var html = "";
    ORDER.forEach(function (k) {
      var list = grouped[k];
      if (!list) return;
      html += '<div class="search-group" role="presentation">' + esc(k) + "</div>";
      list.slice(0, 8).forEach(function (d) {
        var i = hits.length;
        hits.push(d);
        var title = d.h ? esc(d.t) + ' <span class="sub">› ' + mark(d.h, terms) + "</span>" : mark(d.t, terms);
        html += '<a class="search-hit" role="option" id="sh-' + i + '" data-i="' + i + '" href="' + esc(d.u) + '">' +
          '<span class="search-hit-main"><span class="search-hit-title' + (d.m ? " mono" : "") + '">' + title + "</span>" +
          '<span class="search-hit-text">' + (d.g ? esc(d.g) + " · " : "") + mark(snippet(d.x || "", terms), terms) + "</span></span>" +
          '<svg class="enter" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><polyline points="9 10 4 15 9 20"/><path d="M20 4v7a4 4 0 0 1-4 4H4"/></svg></a>';
      });
    });
    results.innerHTML = html || '<p class="search-empty">No results for <b>' + esc(q) + "</b>" + (filter !== "All" ? " in " + esc(filter) + '. <button type="button" class="kbd-btn" data-all>Search everything</button>' : ".") + "</p>";
    var all = $("[data-all]", results);
    if (all) all.addEventListener("click", function () { setFilter("All"); input.focus(); });
    select(0);
  }
  function select(i) {
    var els = $$(".search-hit", results);
    if (!els.length) { input.removeAttribute("aria-activedescendant"); return; }
    selected = (i + els.length) % els.length;
    els.forEach(function (el, j) { el.classList.toggle("is-selected", j === selected); el.setAttribute("aria-selected", j === selected ? "true" : "false"); });
    input.setAttribute("aria-activedescendant", els[selected].id);
    els[selected].scrollIntoView({ block: "nearest" });
  }
  input.addEventListener("input", run);
  results.addEventListener("mousemove", function (e) {
    var a = e.target.closest(".search-hit");
    if (a) { var i = parseInt(a.getAttribute("data-i"), 10); if (i !== selected) select(i); }
  });
  results.addEventListener("click", function (e) { if (e.target.closest(".search-hit")) closeSearch(); });
  modal.addEventListener("keydown", function (e) {
    if (e.key === "ArrowDown") { e.preventDefault(); select(selected + 1); }
    else if (e.key === "ArrowUp") { e.preventDefault(); select(selected - 1); }
    else if (e.key === "Enter" && document.activeElement === input) {
      var el = $$(".search-hit", results)[selected];
      if (el) { e.preventDefault(); closeSearch(); location.href = el.getAttribute("href"); }
    } else if (e.key === "Tab") {
      if (document.activeElement === input || filterBar.contains(document.activeElement)) {
        e.preventDefault();
        var names = filters.map(function (b) { return b.getAttribute("data-filter"); });
        var i = names.indexOf(filter);
        setFilter(names[(i + (e.shiftKey ? -1 : 1) + names.length) % names.length]);
        input.focus();
      }
    }
  });
})();
