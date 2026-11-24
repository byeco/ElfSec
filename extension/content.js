/* ElfSec Webmail İçerik Betiği: Banner + Doğrulama Rozeti + Takip Pikseli + Hover Önizleme + Modern Modal */
(function () {
  "use strict";

  const EMAIL_RE = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i;
  const TRACKING_HINTS = ["track", "open", "click", "pixel", "beacon", "utm_", "mailtrack", "sendgrid", "mailgun"];
  const SVG_NS = "http://www.w3.org/2000/svg";
  const LEVEL_LABELS = { LOW: "Düşük", MEDIUM: "Orta", HIGH: "Yüksek", CRITICAL: "Kritik" };
  let lastFingerprint = "";

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

  /* Marka işareti: dış kaynak yüklemeden, sayfaya gömülü SVG kalkan. */
  function shieldIcon() {
    const svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("focusable", "false");
    const shield = document.createElementNS(SVG_NS, "path");
    shield.setAttribute("d", "M12 2.6 4.8 5.4v5.9c0 4.5 3.1 8.3 7.2 9.4 4.1-1.1 7.2-4.9 7.2-9.4V5.4L12 2.6Z");
    shield.setAttribute("fill", "none");
    shield.setAttribute("stroke", "currentColor");
    shield.setAttribute("stroke-width", "1.7");
    shield.setAttribute("stroke-linejoin", "round");
    const check = document.createElementNS(SVG_NS, "path");
    check.setAttribute("d", "m8.8 11.8 2.2 2.2 4.2-4.4");
    check.setAttribute("fill", "none");
    check.setAttribute("stroke", "currentColor");
    check.setAttribute("stroke-width", "2");
    check.setAttribute("stroke-linecap", "round");
    check.setAttribute("stroke-linejoin", "round");
    svg.appendChild(shield);
    svg.appendChild(check);
    return svg;
  }
  let debounceTimer = null;
  let highRiskUrls = new Set();

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
      const senderEl = document.querySelector("span.gD[email], span[email]");
      if (senderEl) {
        const name = (senderEl.getAttribute("name") || senderEl.innerText || "").trim();
        const addr = (senderEl.getAttribute("email") || "").trim();
        sender = addr ? (name && name !== addr ? `${name} <${addr}>` : addr) : name;
      }
      bodyEl = document.querySelector(".a3s.aiL") || document.querySelector(".a3s");
      document.querySelectorAll(".aV3, .aZo, [download_url]").forEach((el) => {
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
      bodyEl = document.querySelector("[aria-label='Message body']") ||
               document.querySelector("[aria-label='İleti gövdesi']") ||
               document.querySelector("div[role='document']");
      document.querySelectorAll("[aria-label*='.'], [data-testid*='attachment']").forEach((el) => {
        const fn = (el.innerText || el.getAttribute("title") || "").trim();
        if (fn && fn.includes(".") && fn.length < 160) {
          attachments.push({ filename: fn, size: 0, content_type: "" });
        }
      });
    } else {
      subject = pickText(["h1", "h2", "[data-test-id='message-view-subject']", ".message-subject"]);
      bodyEl = document.querySelector("[data-test-id='message-view-body-content']") ||
               document.querySelector(".mail-Message-Body-Content") ||
               document.querySelector("div[role='document']") ||
               document.querySelector("article");
      /* GÜVENLİK: Gönderici adresini e-posta GÖVDESİNDEN toplama. Aksi halde
         saldırgan gövdeye "no-reply@paypal.com" yazıp sahte "Doğrulanmış"
         rozeti ve düşük risk skoru elde edebilirdi. Gövde metnini çıkar. */
      const pageText = document.body ? document.body.innerText : "";
      const bodyText = bodyEl ? (bodyEl.innerText || "") : "";
      const headerText = bodyText ? pageText.replace(bodyText, " ") : pageText;
      const m = headerText.slice(0, 2000).match(EMAIL_RE);
      if (m) sender = m[0];
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

  function ensureHoverTooltip() {
    let tip = document.getElementById("elfsec-link-tooltip");
    if (!tip) {
      tip = document.createElement("div");
      tip.id = "elfsec-link-tooltip";
      tip.style.display = "none";
      document.body.appendChild(tip);
    }
    return tip;
  }

  function getHostSafe(url) {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch (_e) {
      return "";
    }
  }

  /* "www." farkını yok say; alt alan adı yönünde uyumlu isimleri eşleştir. */
  function normalizeHost(host) {
    return String(host || "").toLowerCase().replace(/^www\./, "").replace(/\.$/, "");
  }

  const BARE_HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/i;
  const FILE_LIKE_TLDS = new Set([
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", "zip", "rar",
    "exe", "msi", "png", "jpg", "jpeg", "gif", "svg", "html", "htm", "js", "json", "xml"
  ]);

  /* Bağlantı metnindeki görünen hedefi çıkar: tam URL veya çıplak alan adı. */
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

  /* Görünen alan adı ile gerçek hedef farklı kayıt alanlarına mı gidiyor? */
  function isHostMismatch(textHost, actualHost) {
    const a = normalizeHost(actualHost);
    const t = normalizeHost(textHost);
    if (!a || !t || a === t) return false;
    return !a.endsWith("." + t) && !t.endsWith("." + a);
  }

  function showLinkWarningModal(href, report, mismatchHost, triggerEl) {
    const old = document.getElementById("elfsec-link-modal");
    if (old) old.remove();

    const lvl = String((report && report.risk_level) || "HIGH").toUpperCase();
    const previousFocus = triggerEl || document.activeElement;

    const overlay = document.createElement("div");
    overlay.id = "elfsec-link-modal";
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.setAttribute("aria-labelledby", "elfsec-modal-title");
    overlay.setAttribute("aria-describedby", "elfsec-modal-sub");
    overlay.tabIndex = -1;

    const card = textEl("div", `elfsec-modal-card elfsec-lvl-${lvl.toLowerCase()}`);

    const head = textEl("div", "elfsec-modal-head");
    const icon = textEl("span", "elfsec-modal-icon");
    icon.appendChild(shieldIcon());
    head.appendChild(icon);
    head.appendChild(textEl("span", "elfsec-modal-chip", `${levelLabel(lvl)} risk • ${report.risk_score ?? 0}/100`));

    const title = textEl("h2", "elfsec-modal-title", mismatchHost
      ? "Hedef adres uyuşmuyor"
      : "Bu bağlantı riskli görünüyor");
    title.id = "elfsec-modal-title";

    const sub = textEl("p", "elfsec-modal-sub", mismatchHost
      ? "Görünen adres ile gerçek hedef farklı. Bu bir oltalama girişimi olabilir; devam etmeyin."
      : "Bağlantı şüpheli olarak işaretlendi. Devam etmeden önce hedefi resmi kanaldan doğrulayın.");
    sub.id = "elfsec-modal-sub";

    const urlBox = textEl("div", "elfsec-modal-url");
    urlBox.appendChild(textEl("span", "elfsec-modal-host", getHostSafe(href) || "Bilinmeyen hedef"));
    urlBox.appendChild(textEl("span", "elfsec-modal-full", href));

    const ul = textEl("ul", "elfsec-modal-reasons");
    const reasons = Array.isArray(report.reasons) && report.reasons.length
      ? report.reasons
      : ["Bağlantı hedefi güvenilir olarak doğrulanamadı."];
    reasons.slice(0, 5).forEach((r) => ul.appendChild(textEl("li", "", r)));

    const actions = textEl("div", "elfsec-modal-actions");
    const safeBtn = textEl("button", "elfsec-btn-safe", "← Güvenli Geri Dön");
    safeBtn.type = "button";
    const openBtn = textEl("button", "elfsec-btn-risk", "Riski biliyorum, yine de aç");
    openBtn.type = "button";
    actions.append(safeBtn, openBtn);

    const hint = textEl("div", "elfsec-modal-hint", "Kapatmak için ESC · Güvenli seçenek varsayılandır");

    card.append(head, title, sub, urlBox, ul, actions, hint);
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

  function wireBodyLinks(bodyEl, report, lvl) {
    const tip = ensureHoverTooltip();
    highRiskUrls = new Set(Array.isArray(report.suspicious_urls) ? report.suspicious_urls : []);

    bodyEl.querySelectorAll("a[href]").forEach((a) => {
      const href = a.getAttribute("href") || "";
      if (!/^https?:\/\//i.test(href)) return;

      const actualHost = getHostSafe(href);
      const textHost = hostFromLinkText(a.innerText);
      const mismatchHost = isHostMismatch(textHost, actualHost);
      const isSus = highRiskUrls.has(href) || mismatchHost;

      if (isSus) {
        a.classList.add("elfsec-sus-link");
      }

      if (!a.dataset.elfsecHover) {
        a.dataset.elfsecHover = "1";
        a.addEventListener("mouseenter", (ev) => {
          tip.className = isSus ? "elfsec-tip-bad" : "elfsec-tip-ok";
          tip.replaceChildren();

          const tipHead = textEl("div", "elfsec-tip-head");
          tipHead.appendChild(shieldIcon());
          tipHead.appendChild(textEl("span", "", mismatchHost
            ? "Hedef uyuşmazlığı"
            : isSus ? "Şüpheli hedef" : "Bağlantı hedefi"));
          tip.appendChild(tipHead);
          tip.appendChild(textEl("div", "elfsec-tip-host", actualHost || "bilinmeyen alan adı"));
          tip.appendChild(textEl("span", "elfsec-tip-url", href));

          /* Görünür alan içinde kalacak şekilde konumlandır. */
          tip.style.display = "block";
          tip.style.left = "0px";
          tip.style.top = "0px";
          const box = tip.getBoundingClientRect();
          let x = ev.clientX + 14;
          let y = ev.clientY + 18;
          if (x + box.width > window.innerWidth - 10) {
            x = Math.max(10, ev.clientX - box.width - 14);
          }
          if (y + box.height > window.innerHeight - 10) {
            y = Math.max(10, ev.clientY - box.height - 14);
          }
          tip.style.left = `${x}px`;
          tip.style.top = `${y}px`;
        });
        a.addEventListener("mouseleave", () => {
          tip.style.display = "none";
        });
      }

      if ((isSus && (lvl === "HIGH" || lvl === "CRITICAL" || mismatchHost)) && !a.dataset.elfsecGuarded) {
        a.dataset.elfsecGuarded = "1";
        a.addEventListener("click", (ev) => {
          if (report.linkModal === false) return;
          ev.preventDefault();
          ev.stopPropagation();
          showLinkWarningModal(href, report, mismatchHost, a);
        });
      }
    });
  }

  function renderBanner(bodyEl, report, payload) {
    const old = document.getElementById("elfsec-mail-banner");
    if (old) old.remove();
    if (!bodyEl || !bodyEl.parentElement) return;

    const lvl = (report.risk_level || "LOW").toUpperCase();
    const banner = document.createElement("div");
    banner.id = "elfsec-mail-banner";
    banner.className = `elfsec-banner elfsec-lvl-${lvl.toLowerCase()}`;
    banner.setAttribute("role", "status");

    const header = document.createElement("div");
    header.className = "elfsec-banner-head";

    const brand = document.createElement("span");
    brand.className = "elfsec-brand";
    brand.appendChild(shieldIcon());
    brand.appendChild(document.createTextNode("ElfSec"));
    header.appendChild(brand);

    const badge = document.createElement("span");
    badge.className = "elfsec-badge";
    badge.textContent = `${levelLabel(lvl)} risk · ${report.risk_score ?? 0}/100`;
    header.appendChild(badge);

    const sv = report.sender_verification || {};
    if (sv.status && sv.status !== "UNKNOWN") {
      const svPill = document.createElement("span");
      const isBad = sv.status === "IMPERSONATION" || sv.status === "SPOOFED";
      svPill.className = `elfsec-verify-pill ${isBad ? "elfsec-verify-bad" : "elfsec-verify-ok"}`;
      svPill.textContent = isBad
        ? `⚠ Doğrulanmamış / Taklit: ${sv.brand || "Marka"}`
        : `✓ Doğrulanmış: ${sv.brand || "Resmi"}`;
      svPill.title = sv.detail || "";
      header.appendChild(svPill);
    }

    if (report.trackerCounter !== false && payload.trackingPixels > 0) {
      const trPill = document.createElement("span");
      trPill.className = "elfsec-tracker-pill";
      trPill.textContent = `👁 Takip Pikseli: ${payload.trackingPixels}`;
      header.appendChild(trPill);
    }

    const meta = document.createElement("span");
    meta.className = "elfsec-meta";
    meta.textContent = `${report.via || "ElfSec"} • ${report.summary || ""}`;
    header.appendChild(meta);

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "elfsec-rescan-btn";
    btn.textContent = (chrome.i18n && chrome.i18n.getMessage("bannerRescan")) || "Tekrar Tara";
    btn.addEventListener("click", () => {
      lastFingerprint = "";
      triggerScan(true);
    });
    header.appendChild(btn);
    banner.appendChild(header);

    const reasons = Array.isArray(report.reasons) ? report.reasons : [];
    if (reasons.length && lvl !== "LOW") {
      const ul = document.createElement("ul");
      ul.className = "elfsec-reasons";
      reasons.slice(0, 5).forEach((r) => {
        const li = document.createElement("li");
        li.textContent = String(r);
        ul.appendChild(li);
      });
      banner.appendChild(ul);
    }

    if (report.recommended_action && (lvl === "HIGH" || lvl === "CRITICAL")) {
      const rec = document.createElement("div");
      rec.className = "elfsec-rec";
      rec.textContent = `Öneri: ${report.recommended_action}`;
      banner.appendChild(rec);
    }

    bodyEl.parentElement.insertBefore(banner, bodyEl);
    wireBodyLinks(bodyEl, report, lvl);
  }

  function showFloatingToast(report, target) {
    const old = document.getElementById("elfsec-floating-toast");
    if (old) old.remove();
    const lvl = (report.risk_level || "LOW").toUpperCase();
    const box = document.createElement("div");
    box.id = "elfsec-floating-toast";
    box.className = `elfsec-toast elfsec-lvl-${lvl.toLowerCase()}`;
    box.setAttribute("role", "status");

    const head = document.createElement("div");
    head.className = "elfsec-toast-head";
    head.appendChild(shieldIcon());
    head.appendChild(document.createTextNode("ElfSec Güvenlik Kalkanı"));

    const title = document.createElement("div");
    title.className = "elfsec-toast-title";
    title.textContent = `${levelLabel(lvl)} risk · ${report.risk_score ?? 0}/100`;

    const msg = document.createElement("div");
    msg.className = "elfsec-toast-msg";
    msg.textContent = (report.reasons && report.reasons[0]) || report.summary || String(target || "");

    const closeBtn = document.createElement("button");
    closeBtn.type = "button";
    closeBtn.className = "elfsec-toast-close";
    closeBtn.textContent = "Kapat";
    closeBtn.addEventListener("click", () => box.remove());

    box.appendChild(head);
    box.appendChild(title);
    box.appendChild(msg);
    box.appendChild(closeBtn);
    document.body.appendChild(box);
    setTimeout(() => box.remove(), 8000);
  }

  function triggerScan(force) {
    const data = extractEmailFromDom();
    if (!data) return;
    const fp = `${data.provider}|${data.subject}|${data.sender}|${data.body.slice(0, 250)}`;
    if (!force && fp === lastFingerprint) return;
    lastFingerprint = fp;

    const { bodyEl, trackingPixels, ...payload } = data;
    chrome.runtime.sendMessage({ type: "SCAN_EMAIL", payload }, (report) => {
      if (chrome.runtime.lastError || !report || report.disabled) return;
      renderBanner(bodyEl, report, { ...payload, trackingPixels });
    });
  }

  function scheduleScan() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => triggerScan(false), 600);
  }

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg && msg.type === "SHOW_TOAST" && msg.report) {
      showFloatingToast(msg.report, msg.target || "");
    }
  });

  const observer = new MutationObserver(() => scheduleScan());
  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
    scheduleScan();
  }
})();
