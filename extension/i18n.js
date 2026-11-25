/* ElfSec Ortak Yerelleştirme ve Tema Yardımcısı */
(function (root) {
  "use strict";

  function t(key, fallback, substitutions) {
    try {
      if (typeof chrome !== "undefined" && chrome.i18n && chrome.i18n.getMessage) {
        const msg = chrome.i18n.getMessage(key, substitutions);
        if (msg) return msg;
      }
    } catch (_e) {
      /* Test/tarayıcı dışı ortam */
    }
    return fallback !== undefined ? fallback : key;
  }

  function applyI18n(scope) {
    const rootEl = scope || document;
    rootEl.querySelectorAll("[data-i18n]").forEach((el) => {
      const key = el.getAttribute("data-i18n");
      if (!key) return;
      const val = t(key, el.textContent);
      if (val) el.textContent = val;
    });
    rootEl.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
      const key = el.getAttribute("data-i18n-placeholder");
      if (!key) return;
      const val = t(key, el.getAttribute("placeholder") || "");
      if (val) el.setAttribute("placeholder", val);
    });
    rootEl.querySelectorAll("[data-i18n-title]").forEach((el) => {
      const key = el.getAttribute("data-i18n-title");
      if (!key) return;
      const val = t(key, el.getAttribute("title") || "");
      if (val) el.setAttribute("title", val);
    });
    rootEl.querySelectorAll("[data-i18n-aria]").forEach((el) => {
      const key = el.getAttribute("data-i18n-aria");
      if (!key) return;
      const val = t(key, el.getAttribute("aria-label") || "");
      if (val) el.setAttribute("aria-label", val);
    });
  }

  function applyTheme(theme) {
    const doc = document.documentElement;
    if (!doc) return;
    if (theme === "dark" || theme === "light") {
      doc.dataset.theme = theme;
    } else {
      delete doc.dataset.theme;
    }
  }

  root.ElfSecI18n = { t, applyI18n, applyTheme };
})(typeof globalThis !== "undefined" ? globalThis : window);
