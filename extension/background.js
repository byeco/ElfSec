/* ElfSec Arka Plan Servis Çalışanı: Native Messaging köprüsü + yedek motor + sağ-tık menüsü */
/* global importScripts, ElfSecFallback */

if (typeof ElfSecFallback === "undefined" && typeof importScripts === "function") {
  importScripts("fallback_analyzer.js");
}

const NATIVE_HOST_NAME = "com.elfsec.guard";
const BADGE_COLORS = {
  LOW: "#10b981",
  MEDIUM: "#f59e0b",
  HIGH: "#ef4444",
  CRITICAL: "#b91c1c"
};

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
    nativeConnected: false,
    nativeVersion: "",
    lastScan: null,
    recentAlerts: []
  });
  return data;
}

async function updateBadge(tabId, report) {
  if (!tabId || !report) return;
  const lvl = report.risk_level || "LOW";
  const text = lvl === "LOW" ? "OK" : lvl === "MEDIUM" ? "!" : "!!";
  try {
    await chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLORS[lvl] || "#6b7280" });
    await chrome.action.setBadgeText({ tabId, text });
  } catch (_e) {
    // Bazı tarayıcı sekmeleri kapalı olabilir
  }
}

async function recordScan(report, nativeConnected, nativeVersion) {
  const st = await getState();
  const alerts = Array.isArray(st.recentAlerts) ? st.recentAlerts.slice() : [];
  if (report.risk_level === "HIGH" || report.risk_level === "CRITICAL" || report.risk_level === "MEDIUM") {
    alerts.unshift({
      at: new Date().toISOString(),
      provider: report.provider || "webmail",
      subject: String(report.subject || "(konu yok)").slice(0, 120),
      sender: String(report.sender || "").slice(0, 80),
      risk_score: report.risk_score,
      risk_level: report.risk_level,
      via: nativeConnected ? "Native ElfSec" : "Tarayıcı Yedek"
    });
  }
  await chrome.storage.local.set({
    nativeConnected,
    nativeVersion: nativeVersion || st.nativeVersion,
    lastScan: report,
    recentAlerts: alerts.slice(0, 25)
  });
}

async function scanEmail(payload, tabId) {
  const st = await getState();
  if (!st.enabled) {
    return { ok: true, disabled: true, risk_level: "LOW", risk_score: 0, reasons: ["Koruma duraklatıldı."] };
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
  let nativeConnected = Boolean(report && report.ok);
  let nativeVersion = nativeConnected ? (report.version || "") : "";
  if (!nativeConnected) {
    report = ElfSecFallback.analyzeEmail(payload);
    report.provider = payload.provider || "webmail";
    report.subject = payload.subject || "";
    report.sender = payload.sender || "";
    report.native_fallback_reason = "Masaüstü Native Host bağlı değil (tarayıcı yedek motoru kullanıldı).";
  }
  report.via = nativeConnected ? "Native ElfSec" : "Tarayıcı Yedek Motoru";
  await updateBadge(tabId, report);
  await recordScan(report, nativeConnected, nativeVersion);
  return report;
}

async function scanTextOrUrl(text) {
  let report = await sendToNative({ action: "analyze_url", text: String(text || "") });
  let nativeConnected = Boolean(report && report.ok);
  if (!nativeConnected) {
    report = ElfSecFallback.analyzeText(text);
  }
  report.via = nativeConnected ? "Native ElfSec" : "Tarayıcı Yedek Motoru";
  return report;
}

chrome.runtime.onInstalled.addListener(() => {
  try {
    chrome.contextMenus.removeAll(() => {
      chrome.contextMenus.create({
        id: "elfsec-scan-selection",
        title: "ElfSec ile Seçili Metni Tara",
        contexts: ["selection"]
      });
      chrome.contextMenus.create({
        id: "elfsec-scan-link",
        title: "ElfSec ile Bağlantıyı Tara",
        contexts: ["link"]
      });
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

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
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
    scanTextOrUrl(msg.text || "").then(sendResponse);
    return true;
  }
  if (msg.type === "GET_STATE") {
    getState().then(sendResponse);
    return true;
  }
  if (msg.type === "SET_ENABLED") {
    chrome.storage.local.set({ enabled: Boolean(msg.enabled) }).then(() => {
      sendResponse({ ok: true, enabled: Boolean(msg.enabled) });
    });
    return true;
  }
  return false;
});
