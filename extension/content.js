/* ElfSec Webmail İçerik Betiği: Gmail, Outlook Web, Yahoo, Yandex, iCloud, Proton Mail */
(function () {
  "use strict";

  const EMAIL_RE = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i;
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
        const txt = headerScope.innerText || "";
        const m = txt.match(EMAIL_RE);
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
      const m = (document.body ? document.body.innerText.slice(0, 2000) : "").match(EMAIL_RE);
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
      bodyEl
    };
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

    const meta = document.createElement("span");
    meta.className = "elfsec-meta";
    meta.textContent = `${report.via || "ElfSec"} • ${report.summary || ""}`;

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "elfsec-rescan-btn";
    btn.textContent = "Tekrar Tara";
    btn.addEventListener("click", () => {
      lastFingerprint = "";
      triggerScan(true);
    });

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
    header.appendChild(meta);
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

    // Şüpheli bağlantıları e-posta gövdesinde işaretle ve HIGH/CRITICAL uyarısı ekle
    highRiskUrls = new Set(Array.isArray(report.suspicious_urls) ? report.suspicious_urls : []);
    if (highRiskUrls.size > 0) {
      bodyEl.querySelectorAll("a[href]").forEach((a) => {
        const href = a.getAttribute("href") || "";
        if (highRiskUrls.has(href)) {
          a.classList.add("elfsec-sus-link");
          a.title = "ElfSec Uyarısı: Şüpheli bağlantı!";
          if ((lvl === "HIGH" || lvl === "CRITICAL") && !a.dataset.elfsecGuarded) {
            a.dataset.elfsecGuarded = "1";
            a.addEventListener("click", (ev) => {
              const ok = window.confirm(
                `ElfSec Güvenlik Uyarısı [${lvl} ${report.risk_score}/100]\n\n` +
                `Bu bağlantı şüpheli işaretlendi:\n${href}\n\nYine de açmak istiyor musunuz?`
              );
              if (!ok) {
                ev.preventDefault();
                ev.stopPropagation();
              }
            });
          }
        }
      });
    }
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

    const { bodyEl, ...payload } = data;
    chrome.runtime.sendMessage({ type: "SCAN_EMAIL", payload }, (report) => {
      if (chrome.runtime.lastError || !report || report.disabled) return;
      renderBanner(bodyEl, report, payload);
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
