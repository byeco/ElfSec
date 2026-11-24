/* ElfSec Popup Arayüz Mantığı */
document.addEventListener("DOMContentLoaded", () => {
  const $ = (id) => document.getElementById(id);
  const statusEl = $("nativeStatus");
  const toggleEl = $("enabledToggle");
  const toggleLabel = $("toggleLabel");
  const inputEl = $("quickInput");
  const scanBtn = $("scanBtn");
  const resultEl = $("quickResult");
  const alertsEl = $("alertsList");
  const alertsCount = $("alertsCount");
  const optionsBtn = $("optionsBtn");
  const statScanned = $("statScanned");
  const statThreats = $("statThreats");
  const statVerified = $("statVerified");
  const appVersion = $("appVersion");

  const LEVEL_LABELS = { LOW: "Düşük", MEDIUM: "Orta", HIGH: "Yüksek", CRITICAL: "Kritik" };

  function levelOf(raw) {
    const lvl = String(raw || "LOW").toUpperCase();
    return LEVEL_LABELS[lvl] ? lvl : "LOW";
  }

  function setStatus(text, kind) {
    statusEl.textContent = text;
    statusEl.className = `pill ${kind || "warn"}`;
  }

  function formatTime(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return "";
    return d.toLocaleTimeString("tr-TR", { hour: "2-digit", minute: "2-digit" });
  }

  function renderAlerts(items) {
    const all = Array.isArray(items) ? items : [];
    alertsCount.textContent = `${all.length} kayıt`;
    alertsEl.replaceChildren();

    if (!all.length) {
      const li = document.createElement("li");
      li.className = "empty";
      li.textContent = "Henüz alarm yok. Şüpheli e-posta veya indirme yakalanınca burada görünür.";
      alertsEl.appendChild(li);
      return;
    }

    all.slice(0, 6).forEach((a) => {
      const lvl = levelOf(a && a.risk_level);
      const li = document.createElement("li");
      li.className = "alert";
      li.dataset.level = lvl;

      const chip = document.createElement("span");
      chip.className = "alert-level";
      chip.textContent = LEVEL_LABELS[lvl];

      const main = document.createElement("span");
      main.className = "alert-main";
      main.textContent = String((a && a.subject) || "(konu yok)");

      const meta = document.createElement("span");
      meta.className = "alert-meta";
      const when = formatTime(a && a.at);
      meta.textContent = [
        String((a && a.provider) || "webmail"),
        `${Number(a && a.risk_score) || 0}/100`,
        when
      ].filter(Boolean).join(" · ");

      li.append(chip, main, meta);
      alertsEl.appendChild(li);
    });
  }

  function showResult(rep) {
    if (!rep) {
      resultEl.className = "result show warn";
      resultEl.textContent = "Analiz yapılamadı. Lütfen tekrar deneyin.";
      return;
    }
    const lvl = levelOf(rep.risk_level);
    const cls = lvl === "LOW" ? "ok" : lvl === "MEDIUM" ? "warn" : "bad";
    const reason = (rep.reasons && rep.reasons[0]) || rep.summary || "";
    const score = Number.isFinite(Number(rep.risk_score)) ? Number(rep.risk_score) : 0;
    resultEl.className = `result show ${cls}`;
    resultEl.textContent = `${LEVEL_LABELS[lvl]} risk · ${score}/100 — ${reason}`;
  }

  function setBusy(busy) {
    scanBtn.disabled = busy;
    scanBtn.textContent = busy ? "Taranıyor…" : "Tara";
    scanBtn.setAttribute("aria-busy", busy ? "true" : "false");
  }

  function refresh() {
    setStatus("Kontrol ediliyor", "warn");
    chrome.runtime.sendMessage({ type: "PING" }, (ping) => {
      if (chrome.runtime.lastError) {
        setStatus("Bağlantı yok", "warn");
        return;
      }
      if (ping && ping.nativeConnected) {
        const v = ping.version ? ` ${ping.version}` : "";
        setStatus(`Native${v}`, "ok");
        statusEl.title = `Masaüstü ElfSec motoru bağlı${ping.engine ? ` (${ping.engine})` : ""}`;
      } else {
        setStatus("Yedek mod", "warn");
        statusEl.title = "Masaüstü native host bağlı değil; tarayıcı içi yedek motor kullanılıyor.";
      }
    });

    chrome.runtime.sendMessage({ type: "GET_FULL_STATE" }, (st) => {
      if (chrome.runtime.lastError || !st) return;
      const enabled = Boolean(st.enabled);
      toggleEl.checked = enabled;
      toggleLabel.textContent = enabled ? "Koruma açık" : "Koruma kapalı";

      const stats = st.stats || {};
      statScanned.textContent = String((Number(stats.emailsScanned) || 0) + (Number(stats.downloadsChecked) || 0));
      statThreats.textContent = String(Number(stats.threatsBlocked) || 0);
      statVerified.textContent = String(Number(stats.verifiedMatched) || 0);

      renderAlerts(st.recentAlerts);
    });
  }

  try {
    appVersion.textContent = chrome.runtime.getManifest().version;
  } catch (_e) {
    /* manifest okunamazsa varsayılan kalır */
  }

  toggleEl.addEventListener("change", () => {
    const enabled = toggleEl.checked;
    toggleLabel.textContent = enabled ? "Koruma açık" : "Koruma kapalı";
    chrome.runtime.sendMessage({ type: "SET_ENABLED", enabled }, () => {
      if (chrome.runtime.lastError) {
        toggleEl.checked = !enabled;
        toggleLabel.textContent = !enabled ? "Koruma açık" : "Koruma kapalı";
      }
    });
  });

  function runQuickScan() {
    const val = (inputEl.value || "").trim();
    if (!val) {
      inputEl.focus();
      return;
    }
    setBusy(true);
    resultEl.className = "result show warn";
    resultEl.textContent = "Taranıyor…";
    chrome.runtime.sendMessage({ type: "SCAN_TEXT", text: val }, (rep) => {
      setBusy(false);
      if (chrome.runtime.lastError) {
        showResult(null);
        return;
      }
      showResult(rep);
    });
  }

  scanBtn.addEventListener("click", runQuickScan);

  inputEl.addEventListener("keydown", (ev) => {
    if ((ev.ctrlKey || ev.metaKey) && ev.key === "Enter") {
      ev.preventDefault();
      runQuickScan();
    }
  });

  optionsBtn.addEventListener("click", () => {
    if (chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    }
  });

  refresh();
});
