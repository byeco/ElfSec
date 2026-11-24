/* ElfSec Webmail İçerik Betiği: Banner + Doğrulama Rozeti + Takip Pikseli + Hover Önizleme + Modern Modal */
(function () {
  "use strict";

  const EMAIL_RE = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i;
  const TRACKING_HINTS = ["track", "open", "click", "pixel", "beacon", "utm_", "mailtrack", "sendgrid", "mailgun"];
  let lastFingerprint = "";
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

  function showLinkWarningModal(href, report, mismatchHost) {
    const old = document.getElementById("elfsec-link-modal");
    if (old) old.remove();

    const overlay = document.createElement("div");
    overlay.id = "elfsec-link-modal";

    const card = document.createElement("div");
    card.className = "elfsec-modal-card";

    const title = document.createElement("div");
    title.className = "elfsec-modal-title";
    title.textContent = `ElfSec Güvenlik Kalkanı [${report.risk_level || "HIGH"} ${report.risk_score ?? 0}/100]`;

    const sub = document.createElement("p");
    sub.className = "elfsec-modal-sub";
    sub.textContent = mismatchHost
      ? "Dikkat: Görünür metindeki adres ile gerçek hedef alan adı UYUŞMUYOR!"
      : "Bu bağlantı oltalama veya şüpheli hedef olarak işaretlendi:";

    const urlBox = document.createElement("div");
    urlBox.className = "elfsec-modal-url";
    urlBox.textContent = href;

    const ul = document.createElement("ul");
    ul.className = "elfsec-modal-reasons";
    (report.reasons || []).slice(0, 4).forEach((r) => {
      const li = document.createElement("li");
      li.textContent = String(r);
      ul.appendChild(li);
    });

    const actions = document.createElement("div");
    actions.className = "elfsec-modal-actions";

    const safeBtn = document.createElement("button");
    safeBtn.type = "button";
    safeBtn.className = "elfsec-btn-safe";
    safeBtn.textContent = "Geri Dön (Güvenli)";
    safeBtn.addEventListener("click", () => overlay.remove());

    const openBtn = document.createElement("button");
    openBtn.type = "button";
    openBtn.className = "elfsec-btn-risk";
    openBtn.textContent = "Riski Biliyorum, Yine de Aç";
    openBtn.addEventListener("click", () => {
      overlay.remove();
      window.open(href, "_blank", "noopener,noreferrer");
    });

    actions.appendChild(safeBtn);
    actions.appendChild(openBtn);
    card.appendChild(title);
    card.appendChild(sub);
    card.appendChild(urlBox);
    card.appendChild(ul);
    card.appendChild(actions);
    overlay.appendChild(card);

    overlay.addEventListener("click", (ev) => {
      if (ev.target === overlay) overlay.remove();
    });
    document.body.appendChild(overlay);
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
          tip.textContent = mismatchHost
            ? `⚠ Hedef Uyuşmazlığı! Gerçek hedef: ${actualHost} (${href.slice(0, 90)})`
            : isSus
              ? `⚠ Şüpheli Hedef: ${actualHost} (${href.slice(0, 90)})`
              : `Hedef: ${actualHost}`;
          tip.style.left = `${Math.min(window.innerWidth - 340, ev.clientX + 12)}px`;
          tip.style.top = `${Math.min(window.innerHeight - 70, ev.clientY + 16)}px`;
          tip.style.display = "block";
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
          showLinkWarningModal(href, report, mismatchHost);
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

    const header = document.createElement("div");
    header.className = "elfsec-banner-head";

    const badge = document.createElement("span");
    badge.className = "elfsec-badge";
    badge.textContent = `ElfSec [${lvl}] ${report.risk_score ?? 0}/100`;
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

    const title = document.createElement("div");
    title.className = "elfsec-toast-title";
    title.textContent = `ElfSec [${lvl}] ${report.risk_score ?? 0}/100`;

    const msg = document.createElement("div");
    msg.className = "elfsec-toast-msg";
    msg.textContent = (report.reasons && report.reasons[0]) || report.summary || String(target || "");

    const closeBtn = document.createElement("button");
    closeBtn.type = "button";
    closeBtn.className = "elfsec-toast-close";
    closeBtn.textContent = "Kapat";
    closeBtn.addEventListener("click", () => box.remove());

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
