/* ElfSec Arka Plan Servis Çalışanı: Native Host, İndirme Kalkanı, İstatistik & Sağ-tık */
/* global importScripts, ElfSecFallback */

if (typeof ElfSecFallback === "undefined" && typeof importScripts === "function") {
  importScripts("fallback_analyzer.js");
}

const NATIVE_HOST_NAME = "com.elfsec.guard";
const DEFAULT_SETTINGS = {
  enabled: true,
  webmailShield: true,
  linkModal: true,
  downloadsShield: true,
  trackerCounter: true,
  trustedDomains: [],
  customBrands: []
};
const DEFAULT_STATS = {
  emailsScanned: 0,
  threatsBlocked: 0,
  verifiedMatched: 0,
  downloadsChecked: 0,
  riskyDownloads: 0
};
const BADGE_COLORS = {
  LOW: "#10b981",
  MEDIUM: "#f59e0b",
  HIGH: "#ef4444",
  CRITICAL: "#b91c1c"
};
const MAX_SCAN_TEXT = 10000;

function cleanString(value, max) {
  return String(value == null ? "" : value).trim().slice(0, max);
}

/* Depodan/mesajdan gelen ayarları beyaz listeye göre temizle (prototype pollution
   ve sınırsız dizi/nesne ile depolama şişmesini engeller). */
function sanitizeSettings(partial, base) {
  const out = { ...DEFAULT_SETTINGS, ...(base || {}) };
  if (!partial || typeof partial !== "object") return out;
  ["enabled", "webmailShield", "linkModal", "downloadsShield", "trackerCounter"].forEach((k) => {
    if (Object.prototype.hasOwnProperty.call(partial, k)) out[k] = Boolean(partial[k]);
  });
  if (Array.isArray(partial.trustedDomains)) {
    out.trustedDomains = partial.trustedDomains
      .filter((d) => typeof d === "string")
      .map((d) => cleanString(d, 253).toLowerCase())
      .filter(Boolean)
      .slice(0, 200);
  }
  if (Array.isArray(partial.customBrands)) {
    out.customBrands = partial.customBrands
      .filter((b) => b && typeof b === "object")
      .map((b) => ({
        label: cleanString(b.label, 80),
        domains: (Array.isArray(b.domains) ? b.domains : [])
          .filter((d) => typeof d === "string")
          .map((d) => cleanString(d, 253).toLowerCase())
          .filter(Boolean)
          .slice(0, 10),
        emails: (Array.isArray(b.emails) ? b.emails : [])
          .filter((e) => typeof e === "string")
          .map((e) => cleanString(e, 254).toLowerCase())
          .filter(Boolean)
          .slice(0, 10)
      }))
      .filter((b) => b.label && b.domains.length)
      .slice(0, 50);
  }
  return out;
}

function sendToNative(payload) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendNativeMessage(NATIVE_HOST_NAME, payload, (response) => {
        if (chrome.runtime.lastError || !response) {
          resolve({
            ok: false,
            error: chrome.runtime.lastError ? chrome.runtime.lastError.message : "Native host yanıt vermedi."
          });
          return;
        }
        resolve(response);
      });
    } catch (e) {
      resolve({ ok: false, error: String(e) });
    }
  });
}

async function getState() {
  const data = await chrome.storage.local.get({
    enabled: true,
    settings: DEFAULT_SETTINGS,
    stats: DEFAULT_STATS,
    nativeConnected: false,
    nativeVersion: "",
    lastScan: null,
    recentAlerts: []
  });
  const settings = sanitizeSettings(data.settings, DEFAULT_SETTINGS);
  settings.enabled = data.enabled !== false;
  const stats = { ...DEFAULT_STATS, ...(data.stats || {}) };
  return { ...data, enabled: settings.enabled, settings, stats };
}

async function updateBadge(tabId, report) {
  if (!tabId || !report) return;
  const lvl = report.risk_level || "LOW";
  const text = lvl === "LOW" ? "OK" : lvl === "MEDIUM" ? "!" : "!!";
  try {
    await chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLORS[lvl] || "#6b7280" });
    await chrome.action.setBadgeText({ tabId, text });
  } catch (_e) {
    // Sekme kapanmış olabilir
  }
}

async function recordScan(report, nativeConnected, nativeVersion) {
  const st = await getState();
  const stats = { ...st.stats };
  if (report.source === "browser_download") {
    stats.downloadsChecked += 1;
    if (report.risk_level === "HIGH" || report.risk_level === "CRITICAL") {
      stats.riskyDownloads += 1;
      stats.threatsBlocked += 1;
    }
  } else {
    stats.emailsScanned += 1;
    if (report.risk_level === "HIGH" || report.risk_level === "CRITICAL") {
      stats.threatsBlocked += 1;
    }
    const sv = report.sender_verification || {};
    if (sv.status === "VERIFIED_STRONG" || sv.status === "VERIFIED_DOMAIN") {
      stats.verifiedMatched += 1;
    }
  }

  const alerts = Array.isArray(st.recentAlerts) ? st.recentAlerts.slice() : [];
  if (report.risk_level === "MEDIUM" || report.risk_level === "HIGH" || report.risk_level === "CRITICAL") {
    alerts.unshift({
      at: new Date().toISOString(),
      source: report.source || "webmail",
      provider: report.provider || (report.source === "browser_download" ? "download" : "webmail"),
      subject: String(report.subject || report.filename || "(konu yok)").slice(0, 120),
      sender: String(report.sender || report.url || "").slice(0, 80),
      risk_score: report.risk_score,
      risk_level: report.risk_level,
      via: nativeConnected ? "Native ElfSec" : "Tarayıcı Yedek"
    });
  }

  await chrome.storage.local.set({
    nativeConnected,
    nativeVersion: nativeVersion || st.nativeVersion,
    lastScan: report,
    stats,
    recentAlerts: alerts.slice(0, 50)
  });
}

async function scanEmail(payload, tabId) {
  const st = await getState();
  if (!st.enabled || !st.settings.webmailShield) {
    return { ok: true, disabled: true, risk_level: "LOW", risk_score: 0, reasons: ["Koruma duraklatıldı."] };
  }

  const domMatch = String(payload.sender || "").match(/@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/);
  const senderDom = domMatch ? domMatch[1].toLowerCase() : "";
  const isTrusted = senderDom && (st.settings.trustedDomains || []).some(
    (td) => senderDom === td || senderDom.endsWith("." + td)
  );
  if (isTrusted) {
    const trustedReport = ElfSecFallback.analyzeEmail(payload, st.settings);
    trustedReport.provider = payload.provider || "webmail";
    trustedReport.via = "Güvenilen Liste";
    await updateBadge(tabId, trustedReport);
    await recordScan(trustedReport, st.nativeConnected, st.nativeVersion);
    return trustedReport;
  }

  const nativeReq = {
    action: "analyze_email",
    provider: payload.provider || "webmail",
    subject: payload.subject || "",
    sender: payload.sender || "",
    body: payload.body || "",
    urls: Array.isArray(payload.urls) ? payload.urls : [],
    attachments: Array.isArray(payload.attachments) ? payload.attachments : []
  };
  let report = await sendToNative(nativeReq);
  const nativeConnected = Boolean(report && report.ok);
  const nativeVersion = nativeConnected ? (report.version || "") : "";
  if (!nativeConnected) {
    report = ElfSecFallback.analyzeEmail(payload, st.settings);
    report.provider = payload.provider || "webmail";
    report.subject = payload.subject || "";
    report.sender = payload.sender || "";
    report.native_fallback_reason = "Masaüstü Native Host bağlı değil (tarayıcı yedek motoru kullanıldı).";
  }
  report.via = nativeConnected ? "Native ElfSec" : "Tarayıcı Yedek Motoru";
  report.linkModal = Boolean(st.settings.linkModal);
  report.trackerCounter = Boolean(st.settings.trackerCounter);
  await updateBadge(tabId, report);
  await recordScan(report, nativeConnected, nativeVersion);
  return report;
}

async function scanTextOrUrl(text) {
  let report = await sendToNative({ action: "analyze_url", text: String(text || "") });
  const nativeConnected = Boolean(report && report.ok);
  if (!nativeConnected) {
    report = ElfSecFallback.analyzeText(text);
  }
  report.via = nativeConnected ? "Native ElfSec" : "Tarayıcı Yedek Motoru";
  return report;
}

function notifyRiskyDownload(report) {
  try {
    if (!chrome.notifications || !chrome.notifications.create) return;
    const fname = report.filename || "İndirilen dosya";
    const reason = (report.reasons && report.reasons[0]) || report.summary || "";
    chrome.notifications.create(`elfsec-dl-${Date.now()}`, {
      type: "basic",
      iconUrl: "icons/icon128.png",
      title: `ElfSec İndirme Uyarısı [${report.risk_level}] ${report.risk_score}/100`,
      message: `${fname}: ${reason}`.slice(0, 220),
      priority: 2
    });
  } catch (_e) {
    // Bildirim izni yoksa sessiz geç
  }
}

chrome.runtime.onInstalled.addListener(() => {
  try {
    chrome.contextMenus.removeAll(() => {
      const selTitle = (chrome.i18n && chrome.i18n.getMessage("ctxScanSelection")) || "ElfSec ile Seçili Metni Tara";
      const lnkTitle = (chrome.i18n && chrome.i18n.getMessage("ctxScanLink")) || "ElfSec ile Bağlantıyı Tara";
      chrome.contextMenus.create({ id: "elfsec-scan-selection", title: selTitle, contexts: ["selection"] });
      chrome.contextMenus.create({ id: "elfsec-scan-link", title: lnkTitle, contexts: ["link"] });
    });
  } catch (_e) {
    // Menü oluşturulamazsa sessiz geç
  }
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  const target = info.linkUrl || info.selectionText || "";
  if (!target) return;
  const report = await scanTextOrUrl(target);
  if (tab && tab.id) {
    chrome.tabs.sendMessage(tab.id, { type: "SHOW_TOAST", report, target }).catch(() => {});
  }
});

if (chrome.downloads && chrome.downloads.onCreated) {
  chrome.downloads.onCreated.addListener(async (item) => {
    const st = await getState();
    if (!st.enabled || !st.settings.downloadsShield) return;
    const rep = ElfSecFallback.analyzeDownload({
      filename: item.filename || item.url || "",
      url: item.finalUrl || item.url || ""
    });
    if (rep.risk_level === "HIGH" || rep.risk_level === "CRITICAL") {
      await recordScan(rep, false, st.nativeVersion);
      notifyRiskyDownload(rep);
    }
  });

  chrome.downloads.onChanged.addListener(async (delta) => {
    if (!delta || !delta.state || delta.state.current !== "complete") return;
    const st = await getState();
    if (!st.enabled || !st.settings.downloadsShield) return;
    chrome.downloads.search({ id: delta.id }, async (items) => {
      if (!items || !items.length || !items[0].filename) return;
      const dl = items[0];
      let rep = await sendToNative({ action: "scan_file", path: dl.filename });
      const nativeOk = Boolean(rep && rep.ok);
      if (!nativeOk) {
        rep = ElfSecFallback.analyzeDownload({
          filename: dl.filename,
          url: dl.finalUrl || dl.url || ""
        });
      }
      await recordScan(rep, nativeOk, nativeOk ? (rep.version || "") : st.nativeVersion);
      if (rep.risk_level === "HIGH" || rep.risk_level === "CRITICAL") {
        notifyRiskyDownload(rep);
      }
    });
  });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Yalnızca bu eklentinin kendi içerik betikleri/sayfaları mesaj gönderebilsin.
  if (!sender || sender.id !== chrome.runtime.id) {
    sendResponse({ ok: false, error: "Yetkisiz gönderici." });
    return false;
  }
  const tabId = sender && sender.tab ? sender.tab.id : null;
  if (!msg || !msg.type) {
    sendResponse({ ok: false });
    return false;
  }
  if (msg.type === "PING") {
    sendToNative({ action: "ping" }).then(async (res) => {
      const connected = Boolean(res && res.ok);
      await chrome.storage.local.set({
        nativeConnected: connected,
        nativeVersion: connected ? (res.version || "") : ""
      });
      sendResponse({ ok: true, nativeConnected: connected, version: res.version || "", engine: res.engine || "" });
    });
    return true;
  }
  if (msg.type === "SCAN_EMAIL") {
    scanEmail(msg.payload || {}, tabId).then(sendResponse);
    return true;
  }
  if (msg.type === "SCAN_TEXT") {
    scanTextOrUrl(String(msg.text || "").slice(0, MAX_SCAN_TEXT)).then(sendResponse);
    return true;
  }
  if (msg.type === "SCAN_LINK_PREVIEW") {
    const res = ElfSecFallback.checkUrl(msg.url || "");
    sendResponse({ ok: true, pts: res.pts, reason: res.reason });
    return false;
  }
  if (msg.type === "GET_STATE" || msg.type === "GET_FULL_STATE") {
    getState().then(sendResponse);
    return true;
  }
  if (msg.type === "SET_ENABLED") {
    getState().then(async (st) => {
      const next = { ...st.settings, enabled: Boolean(msg.enabled) };
      await chrome.storage.local.set({ enabled: next.enabled, settings: next });
      sendResponse({ ok: true, enabled: next.enabled });
    });
    return true;
  }
  if (msg.type === "UPDATE_SETTINGS") {
    getState().then(async (st) => {
      const next = sanitizeSettings(msg.settings, st.settings);
      await chrome.storage.local.set({ enabled: Boolean(next.enabled), settings: next });
      sendResponse({ ok: true, settings: next });
    });
    return true;
  }
  if (msg.type === "CLEAR_HISTORY") {
    chrome.storage.local.set({
      stats: { ...DEFAULT_STATS },
      recentAlerts: [],
      lastScan: null
    }).then(() => sendResponse({ ok: true }));
    return true;
  }
  return false;
});
