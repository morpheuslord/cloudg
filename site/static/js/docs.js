/* cloudg docs: theme, code tabs and copy, TOC scroll spy, sidebar drawer,
   version menu, search and diagrams. Loaded as a module, so it runs after
   the page is parsed; without it the pages still work as plain HTML. */
import { initTheme } from "./theme.js";
import { initCodeTabs, initCopy } from "./code.js";
import { initDrawer, initFeedback, initToc, initVersionMenu } from "./nav.js";
import { initConfigHighlight } from "./config.js";
import { initDiagrams, renderDiagrams } from "./diagrams.js";
import { initSearch } from "./search.js";

initTheme(() => renderDiagrams(true));
initCodeTabs();
initCopy();
initToc();
const closeDrawer = initDrawer();
initVersionMenu();
initFeedback();
initConfigHighlight();
initDiagrams();
initSearch(closeDrawer);
