/* ElfSec Webmail İçerik Betiği: Banner + Doğrulama Rozeti + Takip Pikseli + Hover Önizleme + Modern Modal */
(function () {
  "use strict";

  const EMAIL_RE = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i;
  const TRACKING_HINTS = ["track", "open", "click", "pixel", "beacon", "utm_", "mailtrack", "sendgrid", "mailgun"];
  const SVG_NS = "http://www.w3.org/2000/svg";
  const LEVEL_LABELS = { LOW: "Düşük", MEDIUM: "Orta", HIGH: "Yüksek", CRITICAL: "Kritik" };
  const EXT_RE = /\.[a-z0-9]{2,6}$/i;
  const BARE_HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/i;
  const FILE_LIKE_TLDS = new Set([
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", "zip", "rar",
    "exe", "msi", "png", "jpg", "jpeg", "gif", "svg", "html", "htm", "js", "json", "xml"
  ]);

  let lastFingerprint = "";
  let debounceTimer = null;
  let currentTheme = "auto";
  const linkMetaMap = new WeakMap();

  function safeSendMessage(payload, cb) {
    try {
      if (typeof chrome === "undefined" || !chrome.runtime || !chrome.runtime.id) return;
      chrome.runtime.sendMessage(payload, (res) => {
        if (chrome.runtime.lastError) return;
        if (typeof cb === "function") cb(res);
      });
    } catch (_e) {
      /* Eklenti yenilenmiş veya bağlam geçersiz olabilir */
    }
  }

  function msg(key, fallback) {
    try {
      if (typeof chrome !== "undefined" && chrome.i18n && chrome.i18n.getMessage) {
        const val = chrome.i18n.getMessage(key);
        if (val) return val;
      }
    } catch (_e) { /* yoksay */ }
    return fallback;
  }

  function levelLabel(raw) {
    const lvl = String(raw || "LOW").toUpperCase();
    return LEVEL_LABELS[lvl] || LEVEL_LABELS.LOW;
  }

  function textEl(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function applyThemeAttr(el, theme) {
    if (!el) return;
    if (theme === "dark" || theme === "light") {
      el.setAttribute("data-elfsec-theme", theme);
    } else {
      el.removeAttribute("data-elfsec-theme");
    }
  }

  function applyThemeEverywhere(theme) {
    currentTheme = theme || "auto";
    [
      document.getElementById("elfsec-mail-banner"),
      document.getElementById("elfsec-link-tooltip"),
      document.getElementById("elfsec-link-modal"),
      document.getElementById("elfsec-floating-toast")
    ].forEach((el) => applyThemeAttr(el, currentTheme));
  }

  /* Keskin SVG ikon üreticisi (sıfır dış kaynak, sıfır emoji) */
  function makeSvg(paths, viewBox) {
    const svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("viewBox", viewBox || "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("focusable", "false");
    paths.forEach((def) => {
      const el = document.createElementNS(SVG_NS, def.tag || "path");
      Object.keys(def).forEach((k) => {
        if (k !== "tag") el.setAttribute(k, def[k]);
      });
      svg.appendChild(el);
    });
    return svg;
  }

  function shieldIcon() {
    return makeSvg([
      { d: "M12 2.6 4.8 5.4v5.9c0 4.5 3.1 8.3 7.2 9.4 4.1-1.1 7.2-4.9 7.2-9.4V5.4L12 2.6Z", fill: "none", stroke: "currentColor", "stroke-width": "1.8", "stroke-linejoin": "round" },
      { d: "m8.8 11.8 2.2 2.2 4.2-4.4", fill: "none", stroke: "currentColor", "stroke-width": "2", "stroke-linecap": "round", "stroke-linejoin": "round" }
    ]);
  }

  function alertIcon() {
    return makeSvg([
      { d: "M10.3 3.9 2.4 17.5a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z", fill: "none", stroke: "currentColor", "stroke-width": "1.8", "stroke-linejoin": "round" },
      { d: "M12 9.2v4.3", fill: "none", stroke: "currentColor", "stroke-width": "2", "stroke-linecap": "round" },
      { tag: "circle", cx: "12", cy: "16.8", r: "1", fill: "currentColor" }
    ]);
  }

  function checkCircleIcon() {
    return makeSvg([
      { tag: "circle", cx: "12", cy: "12", r: "9", fill: "none", stroke: "currentColor", "stroke-width": "1.8" },
      { d: "m8.7 12.1 2.2 2.2 4.4-4.5", fill: "none", stroke: "currentColor", "stroke-width": "2", "stroke-linecap": "round", "stroke-linejoin": "round" }
    ]);
  }

  function eyeIcon() {
    return makeSvg([
      { d: "M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z", fill: "none", stroke: "currentColor", "stroke-width": "1.8", "stroke-linejoin": "round" },
      { tag: "circle", cx: "12", cy: "12", r: "2.6", fill: "none", stroke: "currentColor", "stroke-width": "1.8" }
    ]);
  }

  function refreshIcon() {
    return makeSvg([
      { d: "M20 11a8 8 0 0 0-14.4-4.6L4 8m0-4v4h4", fill: "none", stroke: "currentColor", "stroke-width": "1.8", "stroke-linecap": "round", "stroke-linejoin": "round" },
      { d: "M4 13a8 8 0 0 0 14.4 4.6L20 16m0 4v-4h-4", fill: "none", stroke: "currentColor", "stroke-width": "1.8", "stroke-linecap": "round", "stroke-linejoin": "round" }
    ]);
  }

  function chevronIcon() {
    return makeSvg([
      { d: "m6 9 6 6 6-6", fill: "none", stroke: "currentColor", "stroke-width": "2", "stroke-linecap": "round", "stroke-linejoin": "round" }
    ]);
  }

  function detectProvider() {
    const h = window.location.hostname.toLowerCase();
    if (h.includes("mail.google.com")) return "gmail";
    if (h.includes("outlook.")) return "outlook";
    if (h.includes("yahoo.")) return "yahoo";
    if (h.includes("yandex.")) return "yandex";
    if (h.includes("icloud.")) return "icloud";
    if (h.includes("proton.me")) return "proton";
    return "webmail";
  }

  function pickText(selectors, root) {
    const scope = root || document;
    for (const sel of selectors) {
      const el = scope.querySelector(sel);
      if (el && el.innerText && el.innerText.trim()) {
        return el.innerText.trim();
      }
    }
    return "";
  }

  function pickLastVisible(selectors) {
    for (const sel of selectors) {
      const nodes = Array.from(document.querySelectorAll(sel));
      for (let i = nodes.length - 1; i >= 0; i--) {
        const el = nodes[i];
        if (el && (el.offsetParent !== null || el.getClientRects().length > 0)) {
          return el;
        }
      }
      if (nodes.length) return nodes[nodes.length - 1];
    }
    return null;
  }

  function countTrackingPixels(bodyEl) {
    if (!bodyEl) return 0;
    let count = 0;
    bodyEl.querySelectorAll("img").forEach((img) => {
      const w = img.getAttribute("width") || "";
      const h = img.getAttribute("height") || "";
      const src = (img.getAttribute("src") || "").toLowerCase();
      const style = (img.getAttribute("style") || "").replace(/\s+/g, "").toLowerCase();
      const is1px = (w === "1" && h === "1") || style.includes("1px");
      const hasHint = TRACKING_HINTS.some((hint) => src.includes(hint));
      if (is1px || hasHint) count += 1;
    });
    return count;
  }

  function extractEmailFromDom() {
    const provider = detectProvider();
    let subject = "";
    let sender = "";
    let bodyEl = null;
    const attachments = [];

    if (provider === "gmail") {
      subject = pickText(["h2.hP", "div.ha h2"]);
      bodyEl = pickLastVisible([".a3s.aiL", ".a3s"]);
      const msgBox = bodyEl ? (bodyEl.closest(".adn, .gs, [data-message-id]") || document) : document;
      const senderEl = msgBox.querySelector("span.gD[email], span[email]") || document.querySelector("span.gD[email], span[email]");
      if (senderEl) {
        const name = (senderEl.getAttribute("name") || senderEl.innerText || "").trim();
        const addr = (senderEl.getAttribute("email") || "").trim();
        sender = addr ? (name && name !== addr ? `${name} <${addr}>` : addr) : name;
      }
      msgBox.querySelectorAll(".aV3, .aZo, [download_url]").forEach((el) => {
        const fn = (el.innerText || el.getAttribute("download_url") || "").trim();
        if (fn && fn.length < 180) attachments.push({ filename: fn, size: 0, content_type: "" });
      });
    } else if (provider === "outlook") {
      subject = pickText(["[role='heading'][aria-level='2']", "span[title][class*='subject']", "div[role='main'] h1"]);
      const headerScope = document.querySelector("[aria-label*='From'], [data-testid='MessageHeader'], div[role='main']");
      if (headerScope) {
        const m = (headerScope.innerText || "").match(EMAIL_RE);
        if (m) sender = m[0];
      }
      bodyEl = pickLastVisible(["[aria-label='Message body']", "[aria-label='İleti gövdesi']", "div[role='document']"]);
      document.querySelectorAll("[data-testid*='attachment'], [aria-label*='Attachment'], [aria-label*='Ek'], .attachment").forEach((el) => {
        const fn = (el.getAttribute("title") || el.innerText || "").trim();
        if (fn && EXT_RE.test(fn) && fn.length < 160) {
          attachments.push({ filename: fn, size: 0, content_type: "" });
        }
      });
    } else {
      subject = pickText(["h1", "h2", "[data-test-id='message-view-subject']", ".message-subject"]);
      bodyEl = pickLastVisible([
        "[data-test-id='message-view-body-content']",
        ".mail-Message-Body-Content",
        "div[role='document']",
        "article"
      ]);
      const headerSender = pickText([
        "[data-testid='message-header:from-address']",
        "[data-test-id='message-from']",
        ".mail-Message-Sender-Email",
        "[data-testid='recipient-address']"
      ]);
      if (headerSender) {
        const hm = headerSender.match(EMAIL_RE);
        if (hm) sender = hm[0];
      }
      if (!sender) {
        /* GÜVENLİK: Gönderici adresini e-posta GÖVDESİNDEN toplama. */
        const pageText = document.body ? document.body.innerText : "";
        const bodyText = bodyEl ? (bodyEl.innerText || "") : "";
        const headerText = bodyText ? pageText.replace(bodyText, " ") : pageText;
        const m = headerText.slice(0, 2000).match(EMAIL_RE);
        if (m) sender = m[0];
      }
    }

    if (!bodyEl) return null;
    const bodyText = (bodyEl.innerText || "").trim();
    if (!bodyText && !subject) return null;

    const urls = [];
    bodyEl.querySelectorAll("a[href]").forEach((a) => {
      const href = a.getAttribute("href") || "";
      if (/^https?:\/\//i.test(href) && urls.indexOf(href) === -1) {
        urls.push(href);
      }
    });

    return {
      provider,
      subject: subject.slice(0, 500),
      sender: sender.slice(0, 250),
      body: bodyText.slice(0, 25000),
      urls: urls.slice(0, 100),
      attachments: attachments.slice(0, 25),
      trackingPixels: countTrackingPixels(bodyEl),
      bodyEl
    };
  }

  function extractEmailDomain(sender) {
    const m = String(sender || "").match(/@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/);
    return m ? m[1].toLowerCase() : "";
  }

  function ensureHoverTooltip() {
    let tip = document.getElementById("elfsec-link-tooltip");
    if (!tip) {
      tip = document.createElement("div");
      tip.id = "elfsec-link-tooltip";
      tip.style.display = "none";
      document.body.appendChild(tip);
    }
    applyThemeAttr(tip, currentTheme);
    return tip;
  }

  function getProtocolSafe(url) {
    try {
      return new URL(url).protocol.replace(":", "").toUpperCase();
    } catch (_e) {
      return "";
    }
  }

  function getHostSafe(url) {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch (_e) {
      return "";
    }
  }

  function normalizeHost(host) {
    return String(host || "").toLowerCase().replace(/^www\./, "").replace(/\.$/, "");
  }

  function hostFromLinkText(text) {
    const raw = String(text || "").trim();
    const full = raw.match(/https?:\/\/([A-Za-z0-9.-]+)/i);
    if (full) return normalizeHost(full[1]);
    const compact = raw.replace(/\s+/g, "").replace(/[)\].,;:!?]+$/, "");
    if (!BARE_HOST_RE.test(compact)) return "";
    const lastLabel = compact.split(".").pop().toLowerCase();
    if (FILE_LIKE_TLDS.has(lastLabel)) return "";
    return normalizeHost(compact);
  }

  function isHostMismatch(textHost, actualHost) {
    const a = normalizeHost(actualHost);
    const t = normalizeHost(textHost);
    if (!a || !t || a === t) return false;
    return !a.endsWith("." + t) && !t.endsWith("." + a);
  }

  function showLinkWarningModal(href, report, mismatchHost, textHost, triggerEl) {
    const old = document.getElementById("elfsec-link-modal");
    if (old) old.remove();

    const lvl = String((report && report.risk_level) || "HIGH").toUpperCase();
    const score = Number(report && report.risk_score) || 0;
    const actualHost = getHostSafe(href) || "Bilinmeyen hedef";
    const previousFocus = triggerEl || document.activeElement;

    const overlay = document.createElement("div");
    overlay.id = "elfsec-link-modal";
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.setAttribute("aria-labelledby", "elfsec-modal-title");
    overlay.setAttribute("aria-describedby", "elfsec-modal-sub");
    overlay.tabIndex = -1;
    applyThemeAttr(overlay, currentTheme);

    const card = textEl("div", `elfsec-modal-card elfsec-lvl-${lvl.toLowerCase()}`);

    const head = textEl("div", "elfsec-modal-head");
    const icon = textEl("span", "elfsec-modal-icon");
    icon.appendChild(alertIcon());
    head.appendChild(icon);
    const chipWrap = textEl("div", "elfsec-modal-head-copy");
    chipWrap.appendChild(textEl("span", "elfsec-modal-chip", `${levelLabel(lvl)} risk · ${score}/100`));
    const meter = textEl("div", "elfsec-modal-meter");
    const meterFill = textEl("div", "elfsec-modal-meter-fill");
    meterFill.style.width = `${Math.max(8, Math.min(100, score))}%`;
    meter.appendChild(meterFill);
    chipWrap.appendChild(meter);
    head.appendChild(chipWrap);

    const title = textEl("h2", "elfsec-modal-title", mismatchHost
      ? "Hedef adres uyuşmuyor"
      : "Bu bağlantı riskli görünüyor");
    title.id = "elfsec-modal-title";

    const sub = textEl("p", "elfsec-modal-sub", mismatchHost
      ? "Bağlantıda görünen alan adı ile yönlendirilen gerçek hedef farklı. Bu bir oltalama tuzağı olabilir."
      : "Bağlantı güvenlik kurallarımız tarafından şüpheli olarak işaretlendi. Devam etmeden önce doğrulayın.");
    sub.id = "elfsec-modal-sub";

    card.append(head, title, sub);

    if (mismatchHost && textHost) {
      const cmp = textEl("div", "elfsec-modal-compare");
      const left = textEl("div", "elfsec-cmp-col");
      left.append(textEl("span", "elfsec-cmp-lbl", "Görünen"), textEl("strong", "elfsec-cmp-val", textHost));
      const right = textEl("div", "elfsec-cmp-col elfsec-cmp-bad");
      right.append(textEl("span", "elfsec-cmp-lbl", "Gerçek Hedef"), textEl("strong", "elfsec-cmp-val", actualHost));
      cmp.append(left, right);
      card.appendChild(cmp);
    }

    const urlBox = textEl("div", "elfsec-modal-url");
    urlBox.appendChild(textEl("span", "elfsec-modal-host", actualHost));
    urlBox.appendChild(textEl("span", "elfsec-modal-full", href));

    const ul = textEl("ul", "elfsec-modal-reasons");
    const reasons = Array.isArray(report && report.reasons) && report.reasons.length
      ? report.reasons
      : ["Bağlantı hedefi güvenilir olarak doğrulanamadı."];
    reasons.slice(0, 5).forEach((r) => ul.appendChild(textEl("li", "", r)));

    const actions = textEl("div", "elfsec-modal-actions");
    const safeBtn = textEl("button", "elfsec-btn-safe", "Güvenli Geri Dön");
    safeBtn.type = "button";
    const openBtn = textEl("button", "elfsec-btn-risk", "Riski biliyorum, yine de aç");
    openBtn.type = "button";
    actions.append(safeBtn, openBtn);

    const hint = textEl("div", "elfsec-modal-hint", "Kapatmak için ESC · Güvenli seçenek varsayılandır");

    card.append(urlBox, ul, actions, hint);
    overlay.appendChild(card);

    let closed = false;
    function closeModal() {
      if (closed) return;
      closed = true;
      overlay.remove();
      if (previousFocus && typeof previousFocus.focus === "function") {
        try { previousFocus.focus(); } catch (_e) { /* öğe kaldırılmış olabilir */ }
      }
    }

    safeBtn.addEventListener("click", closeModal);
    openBtn.addEventListener("click", () => {
      closeModal();
      window.open(href, "_blank", "noopener,noreferrer");
    });

    overlay.addEventListener("click", (ev) => {
      if (ev.target === overlay) closeModal();
    });

    overlay.addEventListener("keydown", (ev) => {
      if (ev.key === "Escape") {
        ev.preventDefault();
        closeModal();
        return;
      }
      if (ev.key !== "Tab") return;
      const focusables = [safeBtn, openBtn];
      const idx = focusables.indexOf(document.activeElement);
      if (ev.shiftKey && idx <= 0) {
        ev.preventDefault();
        openBtn.focus();
      } else if (!ev.shiftKey && idx === focusables.length - 1) {
        ev.preventDefault();
        safeBtn.focus();
      }
    });

    document.body.appendChild(overlay);
    safeBtn.focus();
  }

  function clearBodyGuards() {
    document.querySelectorAll("a.elfsec-sus-link").forEach((a) => a.classList.remove("elfsec-sus-link"));
    const banner = document.getElementById("elfsec-mail-banner");
    if (banner) banner.remove();
    const tip = document.getElementById("elfsec-link-tooltip");
    if (tip) tip.style.display = "none";
    const modal = document.getElementById("elfsec-link-modal");
    if (modal) modal.remove();
  }

  function wireBodyLinks(bodyEl, report, lvl) {
    const tip = ensureHoverTooltip();
    const highRiskUrls = new Set(Array.isArray(report.suspicious_urls) ? report.suspicious_urls : []);
    const reasons = Array.isArray(report.reasons) ? report.reasons : [];

    bodyEl.querySelectorAll("a[href]").forEach((a) => {
      const href = a.getAttribute("href") || "";
      if (!/^https?:\/\//i.test(href)) return;

      const actualHost = getHostSafe(href);
      const proto = getProtocolSafe(href);
      const textHost = hostFromLinkText(a.innerText);
      const mismatchHost = isHostMismatch(textHost, actualHost);
      const isSus = highRiskUrls.has(href) || mismatchHost;
      const urlReason = reasons.find((r) => String(r).includes(href)) || "";

      if (isSus) a.classList.add("elfsec-sus-link");
      else a.classList.remove("elfsec-sus-link");

      linkMetaMap.set(a, { href, actualHost, proto, textHost, mismatchHost, isSus, urlReason, report, lvl });

      if (!a.dataset.elfsecWired) {
        a.dataset.elfsecWired = "1";
        a.addEventListener("mouseenter", (ev) => {
          const meta = linkMetaMap.get(a);
          if (!meta) return;
          applyThemeAttr(tip, currentTheme);
          tip.className = meta.isSus ? "elfsec-tip-bad" : "elfsec-tip-ok";
          tip.replaceChildren();

          const tipHead = textEl("div", "elfsec-tip-head");
          tipHead.appendChild(meta.isSus ? alertIcon() : shieldIcon());
          tipHead.appendChild(textEl("span", "", meta.mismatchHost
            ? "Hedef uyuşmazlığı"
            : meta.isSus ? "Şüpheli bağlantı" : "Doğrulanabilir hedef"));
          if (meta.proto) {
            tipHead.appendChild(textEl("span", `elfsec-tip-proto ${meta.proto === "HTTP" ? "is-http" : ""}`, meta.proto));
          }
          tip.appendChild(tipHead);
          tip.appendChild(textEl("div", "elfsec-tip-host", meta.actualHost || "bilinmeyen alan adı"));

          if (meta.mismatchHost && meta.textHost) {
            tip.appendChild(textEl("div", "elfsec-tip-mismatch", `Görünen: ${meta.textHost} → Gerçek: ${meta.actualHost}`));
          }
          if (meta.urlReason) {
            tip.appendChild(textEl("div", "elfsec-tip-reason", meta.urlReason));
          }
          tip.appendChild(textEl("span", "elfsec-tip-url", meta.href));

          tip.style.display = "block";
          tip.style.left = "0px";
          tip.style.top = "0px";
          const box = tip.getBoundingClientRect();
          let x = ev.clientX + 14;
          let y = ev.clientY + 18;
          if (x + box.width > window.innerWidth - 10) x = Math.max(10, ev.clientX - box.width - 14);
          if (y + box.height > window.innerHeight - 10) y = Math.max(10, ev.clientY - box.height - 14);
          tip.style.left = `${x}px`;
          tip.style.top = `${y}px`;
        });
        a.addEventListener("mouseleave", () => {
          tip.style.display = "none";
        });
        a.addEventListener("click", (ev) => {
          const meta = linkMetaMap.get(a);
          if (!meta || meta.report.linkModal === false) return;
          const shouldGuard = meta.isSus && (meta.lvl === "HIGH" || meta.lvl === "CRITICAL" || meta.mismatchHost);
          if (!shouldGuard) return;
          ev.preventDefault();
          ev.stopPropagation();
          showLinkWarningModal(meta.href, meta.report, meta.mismatchHost, meta.textHost, a);
        });
      }
    });
  }

  function renderBanner(bodyEl, report, payload) {
    const old = document.getElementById("elfsec-mail-banner");
    if (old) old.remove();
    if (!bodyEl || !bodyEl.parentElement) return;

    const lvl = (report.risk_level || "LOW").toUpperCase();
    const score = Number(report.risk_score) || 0;
    const sv = report.sender_verification || {};
    const senderDom = extractEmailDomain(payload.sender);
    const isTrusted = Boolean(report.trustedDomain);

    const banner = document.createElement("div");
    banner.id = "elfsec-mail-banner";
    banner.className = `elfsec-banner elfsec-lvl-${lvl.toLowerCase()} ${lvl === "LOW" ? "elfsec-compact" : ""}`;
    banner.setAttribute("role", "status");
    applyThemeAttr(banner, report.theme || currentTheme);

    const header = textEl("div", "elfsec-banner-head");

    const brand = textEl("span", "elfsec-brand");
    brand.appendChild(lvl === "HIGH" || lvl === "CRITICAL" ? alertIcon() : shieldIcon());
    brand.appendChild(textEl("span", "", "ElfSec"));
    header.appendChild(brand);

    header.appendChild(textEl("span", "elfsec-badge", `${levelLabel(lvl)} · ${score}/100`));

    if (sv.status && sv.status !== "UNKNOWN") {
      const isBad = sv.status === "IMPERSONATION" || sv.status === "SPOOFED";
      const svPill = textEl("span", `elfsec-verify-pill ${isBad ? "elfsec-verify-bad" : "elfsec-verify-ok"}`);
      svPill.appendChild(isBad ? alertIcon() : checkCircleIcon());
      svPill.appendChild(textEl("span", "", isBad
        ? `Taklit / Doğrulanmamış: ${sv.brand || "Marka"}`
        : `Doğrulanmış: ${sv.brand || "Resmi"}`));
      svPill.title = sv.detail || "";
      header.appendChild(svPill);
    }

    if (report.trackerCounter !== false && payload.trackingPixels > 0) {
      const trPill = textEl("span", "elfsec-tracker-pill");
      trPill.appendChild(eyeIcon());
      trPill.appendChild(textEl("span", "", `Takip Pikseli: ${payload.trackingPixels}`));
      header.appendChild(trPill);
    }

    const meta = textEl("span", "elfsec-meta", `${report.via || "ElfSec"} · ${report.summary || msg("bannerClean", "Belirgin tehdit bulunamadı")}`);
    header.appendChild(meta);

    const actions = textEl("div", "elfsec-banner-actions");

    const detailBtn = textEl("button", "elfsec-icon-btn");
    detailBtn.type = "button";
    detailBtn.setAttribute("aria-expanded", "false");
    detailBtn.appendChild(textEl("span", "", "Detay"));
    detailBtn.appendChild(chevronIcon());

    const rescanBtn = textEl("button", "elfsec-rescan-btn");
    rescanBtn.type = "button";
    rescanBtn.appendChild(refreshIcon());
    rescanBtn.appendChild(textEl("span", "", msg("bannerRescan", "Tekrar Tara")));
    rescanBtn.addEventListener("click", () => {
      lastFingerprint = "";
      triggerScan(true);
    });

    actions.append(detailBtn, rescanBtn);
    header.appendChild(actions);
    banner.appendChild(header);

    if (lvl !== "LOW") {
      const meter = textEl("div", "elfsec-banner-meter");
      const fill = textEl("div", "elfsec-banner-meter-fill");
      fill.style.width = `${Math.max(6, Math.min(100, score))}%`;
      meter.appendChild(fill);
      banner.appendChild(meter);
    }

    const reasons = Array.isArray(report.reasons) ? report.reasons : [];
    if (reasons.length && lvl !== "LOW") {
      const ul = textEl("ul", "elfsec-reasons");
      reasons.slice(0, 5).forEach((r) => ul.appendChild(textEl("li", "", r)));
      banner.appendChild(ul);
    }

    if (report.recommended_action && (lvl === "HIGH" || lvl === "CRITICAL")) {
      banner.appendChild(textEl("div", "elfsec-rec", `Öneri: ${report.recommended_action}`));
    }

    /* Açılır detay paneli */
    const details = textEl("div", "elfsec-details");
    details.hidden = true;

    const grid = textEl("div", "elfsec-details-grid");
    grid.append(
      textEl("span", "", `Gönderici: ${payload.sender || "Bilinmiyor"}`),
      textEl("span", "", `Bağlantı: ${(payload.urls || []).length} · Ek: ${(payload.attachments || []).length}`),
      textEl("span", "", `Motor: ${report.engine || report.via || "ElfSec"}`)
    );
    details.appendChild(grid);

    if (sv.detail) {
      details.appendChild(textEl("div", "elfsec-details-note", sv.detail));
    }

    if (senderDom && (isTrusted || (lvl !== "CRITICAL" && sv.status !== "IMPERSONATION" && sv.status !== "SPOOFED"))) {
      const trustRow = textEl("div", "elfsec-details-actions");
      const trustBtn = textEl("button", "elfsec-trust-btn",
        isTrusted ? `${senderDom} alanını güvenilenden çıkar` : `${senderDom} alan adına güven`);
      trustBtn.type = "button";
      trustBtn.addEventListener("click", () => {
        trustBtn.disabled = true;
        safeSendMessage(
          { type: isTrusted ? "UNTRUST_DOMAIN" : "TRUST_DOMAIN", domain: senderDom },
          () => {
            lastFingerprint = "";
            triggerScan(true);
          }
        );
      });
      trustRow.appendChild(trustBtn);
      details.appendChild(trustRow);
    }

    detailBtn.addEventListener("click", () => {
      const open = details.hidden;
      details.hidden = !open;
      detailBtn.setAttribute("aria-expanded", open ? "true" : "false");
      banner.classList.toggle("elfsec-expanded", open);
    });

    banner.appendChild(details);
    bodyEl.parentElement.insertBefore(banner, bodyEl);
    wireBodyLinks(bodyEl, report, lvl);
  }

  function showFloatingToast(report, target) {
    const old = document.getElementById("elfsec-floating-toast");
    if (old) old.remove();
    const lvl = (report.risk_level || "LOW").toUpperCase();
    const score = Number(report.risk_score) || 0;

    const box = document.createElement("div");
    box.id = "elfsec-floating-toast";
    box.className = `elfsec-toast elfsec-lvl-${lvl.toLowerCase()}`;
    box.setAttribute("role", "status");
    applyThemeAttr(box, currentTheme);

    const head = textEl("div", "elfsec-toast-head");
    head.appendChild(lvl === "HIGH" || lvl === "CRITICAL" ? alertIcon() : shieldIcon());
    head.appendChild(textEl("span", "", "ElfSec Güvenlik Kalkanı"));

    const title = textEl("div", "elfsec-toast-title", `${levelLabel(lvl)} risk · ${score}/100`);
    const msgNode = textEl("div", "elfsec-toast-msg", (report.reasons && report.reasons[0]) || report.summary || String(target || ""));

    const closeBtn = textEl("button", "elfsec-toast-close", "Kapat");
    closeBtn.type = "button";
    closeBtn.addEventListener("click", () => box.remove());

    box.append(head, title, msgNode, closeBtn);
    document.body.appendChild(box);

    let timer = setTimeout(() => box.remove(), 8000);
    box.addEventListener("mouseenter", () => clearTimeout(timer));
    box.addEventListener("mouseleave", () => {
      clearTimeout(timer);
      timer = setTimeout(() => box.remove(), 4000);
    });
  }

  function triggerScan(force) {
    const data = extractEmailFromDom();
    if (!data) {
      lastFingerprint = "";
      const orphan = document.getElementById("elfsec-mail-banner");
      if (orphan) orphan.remove();
      return;
    }
    const fp = `${data.provider}|${data.subject}|${data.sender}|${data.body.slice(0, 250)}`;
    if (!force && fp === lastFingerprint) return;
    lastFingerprint = fp;

    const { bodyEl, trackingPixels, ...payload } = data;
    safeSendMessage({ type: "SCAN_EMAIL", payload }, (report) => {
      if (!report) return;
      if (report.disabled) {
        clearBodyGuards();
        return;
      }
      if (report.theme) applyThemeEverywhere(report.theme);
      renderBanner(bodyEl, report, { ...payload, trackingPixels });
    });
  }

  function scheduleScan() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => triggerScan(false), 600);
  }

  try {
    if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.onMessage) {
      chrome.runtime.onMessage.addListener((msgData) => {
        if (!msgData) return;
        if (msgData.type === "SHOW_TOAST" && msgData.report) {
          showFloatingToast(msgData.report, msgData.target || "");
          return;
        }
        if (msgData.type === "SETTINGS_CHANGED" && msgData.settings) {
          applyThemeEverywhere(msgData.settings.theme || "auto");
          if (!msgData.settings.enabled || !msgData.settings.webmailShield) {
            lastFingerprint = "";
            clearBodyGuards();
          } else {
            lastFingerprint = "";
            triggerScan(true);
          }
        }
      });
    }
  } catch (_e) { /* yoksay */ }

  safeSendMessage({ type: "GET_STATE" }, (st) => {
    if (st && st.settings && st.settings.theme) {
      applyThemeEverywhere(st.settings.theme);
    }
  });

  const observer = new MutationObserver(() => scheduleScan());
  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
    scheduleScan();
  }
})();
