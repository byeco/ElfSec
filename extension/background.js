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
  nativeBridgeEnabled: false,
  theme: "auto",
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
const RISK_ORDER = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
const MAX_SCAN_TEXT = 10000;
const DOMAIN_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;

/* Aynı indirme öğesinin onCreated + onChanged akışlarında çift sayılmasını/çift bildirilmesini engeller. */
const seenDownloads = new Map();

function cleanString(value, max) {
  return String(value == null ? "" : value).trim().slice(0, max);
}

function normalizeTheme(value) {
  return value === "dark" || value === "light" ? value : "auto";
}

function normalizeDomain(value) {
  let d = cleanString(value, 253).toLowerCase().replace(/^https?:\/\//, "").replace(/^@/, "");
  d = d.split("/")[0].split(":")[0].replace(/\.$/, "");
  return DOMAIN_RE.test(d) ? d : "";
}

/* Depodan/mesajdan gelen ayarları beyaz listeye göre temizle (prototype pollution
   ve sınırsız dizi/nesne ile depolama şişmesini engeller). */
function sanitizeSettings(partial, base) {
  const out = { ...DEFAULT_SETTINGS, ...(base || {}) };
  if (!partial || typeof partial !== "object") return out;
  ["enabled", "webmailShield", "linkModal", "downloadsShield", "trackerCounter", "nativeBridgeEnabled"].forEach((k) => {
    if (Object.prototype.hasOwnProperty.call(partial, k)) out[k] = Boolean(partial[k]);
  });
  if (Object.prototype.hasOwnProperty.call(partial, "theme")) {
    out.theme = normalizeTheme(partial.theme);
  } else {
    out.theme = normalizeTheme(out.theme);
  }
  if (Array.isArray(partial.trustedDomains)) {
    const uniq = new Set();
    partial.trustedDomains.forEach((d) => {
      if (typeof d === "string") {
        const clean = normalizeDomain(d);
        if (clean) uniq.add(clean);
      }
    });
    out.trustedDomains = Array.from(uniq).slice(0, 200);
  }
  if (Array.isArray(partial.customBrands)) {
    out.customBrands = partial.customBrands
      .filter((b) => b && typeof b === "object")
      .map((b) => ({
        label: cleanString(b.label, 80),
        domains: (Array.isArray(b.domains) ? b.domains : [])
          .filter((d) => typeof d === "string")
          .map((d) => normalizeDomain(d))
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

async function syncGlobalBadge(enabled) {
  try {
    if (!enabled) {
      await chrome.action.setBadgeBackgroundColor({ color: "#64748b" });
      await chrome.action.setBadgeText({ text: "OFF" });
    } else {
      await chrome.action.setBadgeText({ text: "" });
    }
  } catch (_e) {
    /* İzin veya tarayıcı farkı */
  }
}

function broadcastSettings(settings) {
  try {
    if (!chrome.tabs || !chrome.tabs.query) return;
    chrome.tabs.query({}, (tabs) => {
      if (chrome.runtime.lastError || !Array.isArray(tabs)) return;
      tabs.forEach((tab) => {
        if (tab && tab.id) {
          chrome.tabs.sendMessage(tab.id, { type: "SETTINGS_CHANGED", settings }).catch(() => {});
        }
      });
    });
  } catch (_e) {
    /* Sekmelere yayın opsiyonel */
  }
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

async function getDownloadTrack(id) {
  if (seenDownloads.has(id)) return seenDownloads.get(id);
  try {
    if (chrome.storage && chrome.storage.session) {
      const key = `dl_${id}`;
      const res = await chrome.storage.session.get(key);
      if (res && res[key]) {
        seenDownloads.set(id, res[key]);
        return res[key];
      }
    }
  } catch (_e) {
    /* session storage yoksa bellek haritası yeterli */
  }
  return null;
}

async function setDownloadTrack(id, info) {
  seenDownloads.set(id, info);
  if (seenDownloads.size > 200) {
    const firstKey = seenDownloads.keys().next().value;
    seenDownloads.delete(firstKey);
  }
  try {
    if (chrome.storage && chrome.storage.session) {
      await chrome.storage.session.set({ [`dl_${id}`]: info });
    }
  } catch (_e) {
    /* yoksay */
  }
}

async function recordScan(report, nativeConnected, nativeVersion, options) {
  const opts = options || {};
  const st = await getState();
  const stats = { ...st.stats };
  const src = report.source || "webmail";

  if (!opts.skipStats) {
    if (src === "browser_download") {
      stats.downloadsChecked += 1;
      if (report.risk_level === "HIGH" || report.risk_level === "CRITICAL") {
        stats.riskyDownloads += 1;
        stats.threatsBlocked += 1;
      }
    } else if (src === "context_menu" || src === "quick_scan") {
      if (report.risk_level === "HIGH" || report.risk_level === "CRITICAL") {
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
  }

  const alerts = Array.isArray(st.recentAlerts) ? st.recentAlerts.slice() : [];
  if (report.risk_level === "MEDIUM" || report.risk_level === "HIGH" || report.risk_level === "CRITICAL") {
    const providerName =
      report.provider ||
      (src === "browser_download" ? "download" : (src === "context_menu" || src === "quick_scan" ? "web" : "webmail"));
    const title =
      report.subject ||
      report.filename ||
      (report.reasons && report.reasons[0]) ||
      report.summary ||
      "(konu yok)";
    alerts.unshift({
      at: new Date().toISOString(),
      source: src,
      provider: providerName,
      subject: String(title).slice(0, 120),
      sender: String(report.sender || report.url || report.target || "").slice(0, 80),
      risk_score: report.risk_score,
      risk_level: report.risk_level,
      via: nativeConnected ? "Native ElfSec" : "Tarayıcı Yedek"
    });
  }

  const lastScan = { ...report, scanned_at: new Date().toISOString() };
  await chrome.storage.local.set({
    nativeConnected,
    nativeVersion: nativeVersion || st.nativeVersion,
    lastScan,
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
    trustedReport.subject = payload.subject || "";
    trustedReport.sender = payload.sender || "";
    trustedReport.via = "Güvenilen Liste";
    trustedReport.linkModal = Boolean(st.settings.linkModal);
    trustedReport.trackerCounter = Boolean(st.settings.trackerCounter);
    trustedReport.theme = st.settings.theme || "auto";
    trustedReport.trustedDomain = senderDom;
    await updateBadge(tabId, trustedReport);
    await recordScan(trustedReport, st.nativeConnected, st.nativeVersion);
    return trustedReport;
  }

  const bridgeEnabled = st.settings.nativeBridgeEnabled === true;
  let report = null;
  let nativeConnected = false;
  let nativeVersion = "";
  if (bridgeEnabled) {
    const nativeReq = {
      action: "analyze_email",
      provider: payload.provider || "webmail",
      subject: payload.subject || "",
      sender: payload.sender || "",
      body: payload.body || "",
      urls: Array.isArray(payload.urls) ? payload.urls : [],
      attachments: Array.isArray(payload.attachments) ? payload.attachments : []
    };
    report = await sendToNative(nativeReq);
    nativeConnected = Boolean(report && report.ok);
    nativeVersion = nativeConnected ? (report.version || "") : "";
  }
  if (!nativeConnected) {
    report = ElfSecFallback.analyzeEmail(payload, st.settings);
    report.provider = payload.provider || "webmail";
    report.subject = payload.subject || "";
    report.sender = payload.sender || "";
    if (bridgeEnabled) {
      report.native_fallback_reason = "Masaüstü Native Host bağlı değil (tarayıcı yedek motoru kullanıldı).";
    }
  }
  report.via = nativeConnected ? "Native ElfSec" : (bridgeEnabled ? "Tarayıcı Yedek Motoru" : "Tarayıcı Motoru");
  report.linkModal = Boolean(st.settings.linkModal);
  report.trackerCounter = Boolean(st.settings.trackerCounter);
  report.theme = st.settings.theme || "auto";
  report.trustedDomain = "";
  const verifiedMap = {};
  (Array.isArray(payload.urls) ? payload.urls : []).forEach((u) => {
    const v = ElfSecFallback.verifyUrl(u, st.settings);
    if (v && v.verified) {
      verifiedMap[u] = { label: v.label, category: v.category, detail: v.detail, host: v.host };
    }
  });
  report.verified_urls = verifiedMap;
  await updateBadge(tabId, report);
  await recordScan(report, nativeConnected, nativeVersion);
  return report;
}

async function scanTextOrUrl(text, source) {
  const st = await getState();
  const cleanText = String(text || "").slice(0, MAX_SCAN_TEXT);
  const bridgeEnabled = st.settings.nativeBridgeEnabled === true;
  let report = bridgeEnabled ? await sendToNative({ action: "analyze_url", text: cleanText }) : null;
  const nativeConnected = Boolean(report && report.ok);
  const nativeVersion = nativeConnected ? (report.version || "") : (bridgeEnabled ? st.nativeVersion : "");
  if (!nativeConnected) {
    report = ElfSecFallback.analyzeText(cleanText, st.settings);
  }
  const verifiedList = [];
  ElfSecFallback.extractUrls(cleanText).forEach((u) => {
    const v = ElfSecFallback.verifyUrl(u, st.settings);
    if (v && v.verified && !verifiedList.some((x) => x.url === u)) {
      verifiedList.push({ url: u, host: v.host, label: v.label, category: v.category, detail: v.detail });
    }
  });
  report.verified_urls = verifiedList;
  if ((Number(report.risk_score) || 0) === 0 && verifiedList.length > 0) {
    const line = `Doğrulanmış resmi bağlantı: ${verifiedList[0].label} (${verifiedList[0].host})`;
    const rs = Array.isArray(report.reasons) ? report.reasons.slice() : [];
    if (!rs.length || rs[0].indexOf("eşleşmedi") !== -1 || rs[0].indexOf("Bilinen") !== -1) {
      report.reasons = [line];
    } else if (!rs.some((r) => String(r).indexOf("Doğrulanmış resmi bağlantı") !== -1)) {
      report.reasons = [line].concat(rs);
    }
  }
  report.via = nativeConnected ? "Native ElfSec" : (bridgeEnabled ? "Tarayıcı Yedek Motoru" : "Tarayıcı Motoru");
  report.source = source || "quick_scan";
  report.provider = "web";
  report.target = cleanText.slice(0, 120);
  if (report.risk_level === "MEDIUM" || report.risk_level === "HIGH" || report.risk_level === "CRITICAL") {
    await recordScan(report, nativeConnected, nativeVersion);
  } else {
    await chrome.storage.local.set({
      nativeConnected,
      nativeVersion,
      lastScan: { ...report, scanned_at: new Date().toISOString() }
    });
  }
  return report;
}

function notifyRiskyDownload(report) {
  try {
    if (!chrome.notifications || !chrome.notifications.create) return;
    const fname = report.filename || "İndirilen dosya";
    const reason = (report.reasons && report.reasons[0]) || report.summary || "";
    const autoQ = Boolean(report.auto_protected);
    const title = autoQ
      ? `ElfSec Otomatik Karantina [${report.risk_level}] ${report.risk_score}/100`
      : `ElfSec İndirme Uyarısı [${report.risk_level}] ${report.risk_score}/100`;
    const prefix = autoQ ? "Zararlı dosya karantinaya alındı — " : "";
    chrome.notifications.create(`elfsec-dl-${Date.now()}`, {
      type: "basic",
      iconUrl: "icons/icon128.png",
      title,
      message: `${prefix}${fname}: ${reason}`.slice(0, 220),
      priority: 2
    });
  } catch (_e) {
    // Bildirim izni yoksa sessiz geç
  }
}

function notifyTextScan(report, target) {
  try {
    if (!chrome.notifications || !chrome.notifications.create) return;
    const lvl = String((report && report.risk_level) || "LOW").toUpperCase();
    const score = Number(report && report.risk_score) || 0;
    const reason = (report && report.reasons && report.reasons[0]) || (report && report.summary) || String(target || "");
    chrome.notifications.create(`elfsec-ctx-${Date.now()}`, {
      type: "basic",
      iconUrl: "icons/icon128.png",
      title: `ElfSec Tarama [${lvl}] ${score}/100`,
      message: `${reason}`.slice(0, 220),
      priority: lvl === "HIGH" || lvl === "CRITICAL" ? 2 : 0
    });
  } catch (_e) {
    // Bildirim izni yoksa sessiz geç
  }
}

function ensureContextMenus() {
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
}

chrome.runtime.onInstalled.addListener(() => {
  ensureContextMenus();
  getState().then((st) => syncGlobalBadge(st.enabled)).catch(() => {});
});

if (chrome.runtime.onStartup) {
  chrome.runtime.onStartup.addListener(() => {
    getState().then((st) => syncGlobalBadge(st.enabled)).catch(() => {});
  });
}

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  const target = info.linkUrl || info.selectionText || "";
  if (!target) return;
  const report = await scanTextOrUrl(target, "context_menu");
  let shownInTab = false;
  if (tab && tab.id) {
    try {
      await chrome.tabs.sendMessage(tab.id, { type: "SHOW_TOAST", report, target });
      shownInTab = true;
    } catch (_e) {
      shownInTab = false;
    }
  }
  if (!shownInTab) {
    notifyTextScan(report, target);
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
    const isHigh = rep.risk_level === "HIGH" || rep.risk_level === "CRITICAL";
    await setDownloadTrack(item.id, {
      earlyAlerted: isHigh,
      earlyLevel: rep.risk_level || "LOW",
      completed: false
    });
    if (isHigh) {
      notifyRiskyDownload(rep);
    }
  });

  chrome.downloads.onChanged.addListener(async (delta) => {
    if (!delta || !delta.state || delta.state.current !== "complete") return;
    const st = await getState();
    if (!st.enabled || !st.settings.downloadsShield) return;
    const prev = await getDownloadTrack(delta.id);
    if (prev && prev.completed) return;

    chrome.downloads.search({ id: delta.id }, async (items) => {
      if (!items || !items.length || !items[0].filename) return;
      const dl = items[0];
      const bridgeEnabled = st.settings.nativeBridgeEnabled === true;
      let rep = bridgeEnabled
        ? await sendToNative({ action: "scan_file", path: dl.filename, auto_protect: false })
        : null;
      const nativeOk = Boolean(rep && rep.ok);
      if (!nativeOk) {
        rep = ElfSecFallback.analyzeDownload({
          filename: dl.filename,
          url: dl.finalUrl || dl.url || ""
        });
      }
      const lvl = rep.risk_level || "LOW";
      const isHigh = lvl === "HIGH" || lvl === "CRITICAL";
      const escalated = prev && prev.earlyAlerted
        ? (RISK_ORDER[lvl] || 0) > (RISK_ORDER[prev.earlyLevel] || 0)
        : false;

      await setDownloadTrack(delta.id, {
        earlyAlerted: Boolean((prev && prev.earlyAlerted) || isHigh),
        earlyLevel: lvl,
        completed: true
      });
      await recordScan(rep, nativeOk, nativeOk ? (rep.version || "") : st.nativeVersion);
      // Native Host bağlı ve kritik ise masaüstü Toast bildirimi zaten yönetilir; çift tarayıcı bildirimi atma.
      const nativeHandledToast = nativeOk && lvl === "CRITICAL" && !rep.auto_protected;
      if (!nativeHandledToast && (lvl === "CRITICAL" || (!nativeOk && isHigh)) && (!prev || !prev.earlyAlerted || escalated)) {
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
    getState().then(async (st) => {
      if (!st.settings.nativeBridgeEnabled) {
        await chrome.storage.local.set({
          nativeConnected: false,
          nativeVersion: "",
          nativeAiEnabled: false,
          nativeExeShield: false
        });
        sendResponse({
          ok: true,
          nativeEnabled: false,
          nativeConnected: false,
          version: "",
          engine: "",
          aiEnabled: false,
          exeDeepScan: false
        });
        return;
      }
      const res = await sendToNative({ action: "ping" });
      const connected = Boolean(res && res.ok);
      await chrome.storage.local.set({
        nativeConnected: connected,
        nativeVersion: connected ? (res.version || "") : "",
        nativeAiEnabled: connected ? Boolean(res.ai_enabled) : false,
        nativeExeShield: connected ? Boolean(res.exe_deep_scan) : false
      });
      sendResponse({
        ok: true,
        nativeEnabled: true,
        nativeConnected: connected,
        version: res.version || "",
        engine: res.engine || "",
        aiEnabled: Boolean(res && res.ai_enabled),
        exeDeepScan: Boolean(res && res.exe_deep_scan)
      });
    });
    return true;
  }
  if (msg.type === "SCAN_EMAIL") {
    scanEmail(msg.payload || {}, tabId).then(sendResponse);
    return true;
  }
  if (msg.type === "SCAN_TEXT") {
    scanTextOrUrl(msg.text || "", "quick_scan").then(sendResponse);
    return true;
  }
  if (msg.type === "SCAN_LINK_PREVIEW") {
    getState().then((st) => {
      const res = ElfSecFallback.checkUrl(msg.url || "", st.settings);
      sendResponse({
        ok: true,
        pts: res.pts,
        reason: res.reason,
        verified: Boolean(res.verified),
        verifiedLabel: res.verifiedLabel || "",
        verifiedCategory: res.verifiedCategory || "",
        verifiedDetail: res.verifiedDetail || ""
      });
    });
    return true;
  }
  if (msg.type === "GET_STATE" || msg.type === "GET_FULL_STATE") {
    getState().then(sendResponse);
    return true;
  }
  if (msg.type === "GET_VERIFIED_BRANDS") {
    const brands = typeof ElfSecFallback.getVerifiedBrands === "function"
      ? ElfSecFallback.getVerifiedBrands()
      : [];
    sendResponse({ ok: true, brands });
    return false;
  }
  if (msg.type === "SET_ENABLED") {
    getState().then(async (st) => {
      const next = { ...st.settings, enabled: Boolean(msg.enabled) };
      await chrome.storage.local.set({ enabled: next.enabled, settings: next });
      await syncGlobalBadge(next.enabled);
      broadcastSettings(next);
      sendResponse({ ok: true, enabled: next.enabled, settings: next });
    });
    return true;
  }
  if (msg.type === "UPDATE_SETTINGS") {
    getState().then(async (st) => {
      const next = sanitizeSettings(msg.settings, st.settings);
      const patch = { enabled: Boolean(next.enabled), settings: next };
      if (!next.nativeBridgeEnabled) {
        patch.nativeConnected = false;
        patch.nativeVersion = "";
        patch.nativeAiEnabled = false;
        patch.nativeExeShield = false;
      }
      await chrome.storage.local.set(patch);
      await syncGlobalBadge(next.enabled);
      broadcastSettings(next);
      sendResponse({ ok: true, settings: next });
    });
    return true;
  }
  if (msg.type === "TRUST_DOMAIN") {
    const dom = normalizeDomain(msg.domain || "");
    if (!dom) {
      sendResponse({ ok: false, error: "Geçersiz alan adı." });
      return false;
    }
    getState().then(async (st) => {
      const list = (st.settings.trustedDomains || []).slice();
      if (!list.includes(dom)) list.push(dom);
      const next = sanitizeSettings({ trustedDomains: list }, st.settings);
      await chrome.storage.local.set({ settings: next });
      broadcastSettings(next);
      sendResponse({ ok: true, domain: dom, settings: next });
    });
    return true;
  }
  if (msg.type === "UNTRUST_DOMAIN") {
    const dom = normalizeDomain(msg.domain || "");
    getState().then(async (st) => {
      const list = (st.settings.trustedDomains || []).filter((d) => d !== dom);
      const next = sanitizeSettings({ trustedDomains: list }, st.settings);
      await chrome.storage.local.set({ settings: next });
      broadcastSettings(next);
      sendResponse({ ok: true, domain: dom, settings: next });
    });
    return true;
  }
  if (msg.type === "CLEAR_ALERTS") {
    chrome.storage.local.set({ recentAlerts: [] }).then(() => sendResponse({ ok: true }));
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
