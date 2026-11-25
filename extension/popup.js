/* ElfSec Popup Arayüz Mantığı */
document.addEventListener("DOMContentLoaded", () => {
  const I18n = window.ElfSecI18n || { t: (_k, fb) => fb, applyI18n: () => {}, applyTheme: () => {} };
  I18n.applyI18n(document);

  const $ = (id) => document.getElementById(id);
  const statusEl = $("nativeStatus");
  const settingsIconBtn = $("settingsIconBtn");
  const heroCard = $("heroCard");
  const toggleEl = $("enabledToggle");
  const toggleLabel = $("toggleLabel");
  const toggleSub = $("toggleSub");

  const statEmails = $("statEmails");
  const statDownloads = $("statDownloads");
  const statThreats = $("statThreats");
  const statVerified = $("statVerified");

  const qWebmail = $("qWebmail");
  const qModal = $("qModal");
  const qDownloads = $("qDownloads");
  const qTracker = $("qTracker");

  const lastScanTime = $("lastScanTime");
  const lastScanBody = $("lastScanBody");

  const inputEl = $("quickInput");
  const scanBtn = $("scanBtn");
  const clearInputBtn = $("clearInputBtn");
  const resultEl = $("quickResult");

  const alertsEl = $("alertsList");
  const alertsCount = $("alertsCount");
  const alertsTabBadge = $("alertsTabBadge");
  const optionsBtn = $("optionsBtn");
  const appVersion = $("appVersion");

  const tabBtns = Array.from(document.querySelectorAll(".tab-btn"));
  const tabPanels = {
    overview: $("panelOverview"),
    scan: $("panelScan"),
    alerts: $("panelAlerts")
  };
  const filterBtns = Array.from(document.querySelectorAll(".filter-btn"));

  let currentSettings = {};
  let allAlerts = [];
  let activeFilter = "all";

  const SVG_NS = "http://www.w3.org/2000/svg";

  function levelMeta(raw) {
    const lvl = String(raw || "LOW").toUpperCase();
    if (lvl === "CRITICAL") return { code: "CRITICAL", cls: "critical", label: I18n.t("riskCritical", "Kritik") };
    if (lvl === "HIGH") return { code: "HIGH", cls: "high", label: I18n.t("riskHigh", "Yüksek") };
    if (lvl === "MEDIUM") return { code: "MEDIUM", cls: "medium", label: I18n.t("riskMedium", "Orta") };
    return { code: "LOW", cls: "low", label: I18n.t("riskLow", "Düşük") };
  }

  function makeIcon(source) {
    const svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("width", "15");
    svg.setAttribute("height", "15");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "1.8");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    svg.setAttribute("aria-hidden", "true");

    const add = (d) => {
      const p = document.createElementNS(SVG_NS, "path");
      p.setAttribute("d", d);
      svg.appendChild(p);
    };

    if (source === "browser_download") {
      add("M12 3v12");
      add("m7 10 5 5 5-5");
      add("M5 19h14");
    } else if (source === "context_menu" || source === "quick_scan") {
      add("M10 13a5 5 0 0 0 7.07 0l2.83-2.83a5 5 0 0 0-7.07-7.07L11 4.93");
      add("M14 11a5 5 0 0 0-7.07 0L4.1 13.83a5 5 0 0 0 7.07 7.07L13 19.07");
    } else {
      add("M4 6h16v12H4z");
      add("m4 7 8 6 8-6");
    }
    return svg;
  }

  function formatTime(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return "";
    return d.toLocaleTimeString("tr-TR", { hour: "2-digit", minute: "2-digit" });
  }

  function setStatus(text, kind) {
    statusEl.textContent = text;
    statusEl.className = `elf-pill pill-btn ${kind || "warn"}`;
  }

  function setHeroState(enabled) {
    heroCard.classList.toggle("is-active", enabled);
    heroCard.classList.toggle("is-paused", !enabled);
    toggleLabel.textContent = enabled
      ? I18n.t("protectionActive", "Koruma Aktif")
      : I18n.t("protectionPaused", "Koruma Duraklatıldı");
    toggleSub.textContent = enabled
      ? I18n.t("protectionSubActive", "Webmail, link ve indirme kalkanı devrede")
      : I18n.t("protectionSubPaused", "Kalkanlar geçici olarak devre dışı");
  }

  function openOptions(hash) {
    const url = chrome.runtime.getURL(`options.html${hash || ""}`);
    if (chrome.tabs && chrome.tabs.create) {
      chrome.tabs.create({ url });
    } else if (chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    }
  }

  function switchTab(name) {
    tabBtns.forEach((btn) => {
      const active = btn.dataset.tab === name;
      btn.setAttribute("aria-selected", active ? "true" : "false");
    });
    Object.keys(tabPanels).forEach((k) => {
      tabPanels[k].hidden = k !== name;
    });
  }

  function renderLastScan(lastScan) {
    lastScanBody.replaceChildren();
    if (!lastScan) {
      lastScanTime.textContent = "";
      lastScanBody.className = "empty-box";
      lastScanBody.textContent = I18n.t("lastScanEmpty", "Henüz tarama kaydı yok.");
      return;
    }
    lastScanBody.className = "last-scan-box";
    const meta = levelMeta(lastScan.risk_level);
    const score = Number(lastScan.risk_score) || 0;
    lastScanTime.textContent = formatTime(lastScan.scanned_at);

    const top = document.createElement("div");
    top.className = "last-scan-top";
    const title = document.createElement("span");
    title.className = "last-scan-title";
    title.textContent = String(lastScan.subject || lastScan.filename || lastScan.target || lastScan.summary || "(tarama)");
    const badge = document.createElement("span");
    badge.className = `elf-level ${meta.cls}`;
    badge.textContent = `${meta.label} · ${score}/100`;
    top.append(title, badge);

    const meter = document.createElement("div");
    meter.className = "elf-meter";
    const fill = document.createElement("div");
    fill.className = `elf-meter-fill ${meta.cls}`;
    fill.style.width = `${Math.max(4, Math.min(100, score))}%`;
    meter.appendChild(fill);

    const sub = document.createElement("div");
    sub.className = "last-scan-meta";
    sub.textContent = [lastScan.provider || lastScan.source || "webmail", lastScan.via || lastScan.engine || "ElfSec"]
      .filter(Boolean)
      .join(" · ");

    lastScanBody.append(top, meter, sub);
  }

  function renderAlerts() {
    const filtered = allAlerts.filter((a) => {
      const lvl = String((a && a.risk_level) || "LOW").toUpperCase();
      if (activeFilter === "high") return lvl === "HIGH" || lvl === "CRITICAL";
      if (activeFilter === "medium") return lvl === "MEDIUM";
      return true;
    });

    alertsTabBadge.textContent = String(allAlerts.length);
    alertsCount.textContent = `${filtered.length} kayıt`;
    alertsEl.replaceChildren();

    if (!filtered.length) {
      const li = document.createElement("li");
      li.className = "empty-box";
      li.textContent = I18n.t("alertsEmpty", "Henüz alarm yok. Şüpheli e-posta, link veya indirme tespit edilince burada listelenir.");
      alertsEl.appendChild(li);
      return;
    }

    filtered.slice(0, 12).forEach((a) => {
      const meta = levelMeta(a && a.risk_level);
      const li = document.createElement("li");
      li.className = "alert";
      li.dataset.level = meta.code;

      const icoWrap = document.createElement("span");
      icoWrap.className = "alert-src-ico";
      icoWrap.appendChild(makeIcon(a && a.source));

      const main = document.createElement("span");
      main.className = "alert-main";
      main.textContent = String((a && a.subject) || "(konu yok)");

      const chip = document.createElement("span");
      chip.className = `elf-level ${meta.cls}`;
      chip.textContent = `${meta.label} ${Number(a && a.risk_score) || 0}`;

      const sub = document.createElement("span");
      sub.className = "alert-meta";
      sub.textContent = [
        String((a && a.provider) || "webmail"),
        a && a.sender ? String(a.sender) : "",
        formatTime(a && a.at)
      ].filter(Boolean).join(" · ");

      li.append(icoWrap, main, chip, sub);
      alertsEl.appendChild(li);
    });
  }

  function showQuickResult(rep) {
    resultEl.replaceChildren();
    resultEl.className = "scan-result show";
    if (!rep) {
      const p = document.createElement("div");
      p.textContent = "Analiz yapılamadı. Lütfen tekrar deneyin.";
      resultEl.appendChild(p);
      return;
    }

    const meta = levelMeta(rep.risk_level);
    const score = Number.isFinite(Number(rep.risk_score)) ? Number(rep.risk_score) : 0;

    const head = document.createElement("div");
    head.className = "scan-res-head";
    const badge = document.createElement("span");
    badge.className = `elf-level ${meta.cls}`;
    badge.textContent = `${meta.label} Risk`;
    const scoreEl = document.createElement("span");
    scoreEl.className = "scan-res-score";
    scoreEl.textContent = `${score} / 100`;
    head.append(badge, scoreEl);

    const meter = document.createElement("div");
    meter.className = "elf-meter";
    const fill = document.createElement("div");
    fill.className = `elf-meter-fill ${meta.cls}`;
    fill.style.width = `${Math.max(4, Math.min(100, score))}%`;
    meter.appendChild(fill);

    const tags = document.createElement("div");
    tags.className = "scan-tags";
    const viaTag = document.createElement("span");
    viaTag.className = "scan-tag";
    viaTag.textContent = rep.via || rep.engine || "ElfSec";
    tags.appendChild(viaTag);

    if (rep.clickfix_detected) {
      const cf = document.createElement("span");
      cf.className = "scan-tag bad";
      cf.textContent = "ClickFix";
      tags.appendChild(cf);
    }
    if (rep.phishing_detected) {
      const ph = document.createElement("span");
      ph.className = "scan-tag bad";
      ph.textContent = "Phishing";
      tags.appendChild(ph);
    }

    const ul = document.createElement("ul");
    ul.className = "scan-reasons";
    const reasons = Array.isArray(rep.reasons) && rep.reasons.length
      ? rep.reasons
      : [rep.summary || "Bulgu yok."];
    reasons.slice(0, 5).forEach((r) => {
      const li = document.createElement("li");
      li.textContent = String(r);
      ul.appendChild(li);
    });

    resultEl.append(head, meter, tags, ul);
  }

  function setBusy(busy) {
    scanBtn.disabled = busy;
    scanBtn.textContent = busy
      ? I18n.t("scanBtnBusy", "Taranıyor…")
      : I18n.t("scanBtn", "Tara");
    scanBtn.setAttribute("aria-busy", busy ? "true" : "false");
  }

  function saveQuickModules() {
    const next = {
      ...currentSettings,
      webmailShield: qWebmail.checked,
      linkModal: qModal.checked,
      downloadsShield: qDownloads.checked,
      trackerCounter: qTracker.checked
    };
    currentSettings = next;
    chrome.runtime.sendMessage({ type: "UPDATE_SETTINGS", settings: next });
  }

  function refresh() {
    setStatus(I18n.t("statusChecking", "Kontrol ediliyor"), "warn");
    chrome.runtime.sendMessage({ type: "PING" }, (ping) => {
      if (chrome.runtime.lastError) {
        setStatus(I18n.t("statusOffline", "Bağlantı yok"), "warn");
        return;
      }
      if (ping && ping.nativeConnected) {
        const v = ping.version ? ` v${ping.version}` : "";
        setStatus(`Native${v}`, "ok");
        statusEl.title = `Masaüstü ElfSec motoru bağlı${ping.engine ? ` (${ping.engine})` : ""}`;
      } else {
        setStatus(I18n.t("statusFallback", "Yedek Mod"), "warn");
        statusEl.title = "Masaüstü native host bağlı değil; tarayıcı içi yedek motor kullanılıyor. Kurulum için tıklayın.";
      }
    });

    chrome.runtime.sendMessage({ type: "GET_FULL_STATE" }, (st) => {
      if (chrome.runtime.lastError || !st) return;
      currentSettings = st.settings || {};
      I18n.applyTheme(currentSettings.theme || "auto");

      const enabled = Boolean(st.enabled);
      toggleEl.checked = enabled;
      setHeroState(enabled);

      qWebmail.checked = currentSettings.webmailShield !== false;
      qModal.checked = currentSettings.linkModal !== false;
      qDownloads.checked = currentSettings.downloadsShield !== false;
      qTracker.checked = currentSettings.trackerCounter !== false;

      const stats = st.stats || {};
      statEmails.textContent = String(Number(stats.emailsScanned) || 0);
      statDownloads.textContent = String(Number(stats.downloadsChecked) || 0);
      statThreats.textContent = String(Number(stats.threatsBlocked) || 0);
      statVerified.textContent = String(Number(stats.verifiedMatched) || 0);

      renderLastScan(st.lastScan);
      allAlerts = Array.isArray(st.recentAlerts) ? st.recentAlerts : [];
      renderAlerts();
    });
  }

  try {
    appVersion.textContent = chrome.runtime.getManifest().version;
  } catch (_e) { /* varsayılan kalır */ }

  tabBtns.forEach((btn) => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
  });

  filterBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      activeFilter = btn.dataset.filter || "all";
      filterBtns.forEach((b) => b.classList.toggle("is-active", b === btn));
      renderAlerts();
    });
  });

  toggleEl.addEventListener("change", () => {
    const enabled = toggleEl.checked;
    setHeroState(enabled);
    chrome.runtime.sendMessage({ type: "SET_ENABLED", enabled }, () => {
      if (chrome.runtime.lastError) {
        toggleEl.checked = !enabled;
        setHeroState(!enabled);
      }
    });
  });

  [qWebmail, qModal, qDownloads, qTracker].forEach((el) => {
    el.addEventListener("change", saveQuickModules);
  });

  function runQuickScan() {
    const val = (inputEl.value || "").trim();
    if (!val) {
      inputEl.focus();
      return;
    }
    setBusy(true);
    chrome.runtime.sendMessage({ type: "SCAN_TEXT", text: val }, (rep) => {
      setBusy(false);
      if (chrome.runtime.lastError) {
        showQuickResult(null);
        return;
      }
      showQuickResult(rep);
      refresh();
    });
  }

  scanBtn.addEventListener("click", runQuickScan);
  clearInputBtn.addEventListener("click", () => {
    inputEl.value = "";
    resultEl.className = "scan-result";
    resultEl.replaceChildren();
    inputEl.focus();
  });

  inputEl.addEventListener("keydown", (ev) => {
    if ((ev.ctrlKey || ev.metaKey) && ev.key === "Enter") {
      ev.preventDefault();
      runQuickScan();
    }
  });

  statusEl.addEventListener("click", () => openOptions("#native"));
  settingsIconBtn.addEventListener("click", () => openOptions(""));
  optionsBtn.addEventListener("click", () => openOptions(""));

  refresh();
});
