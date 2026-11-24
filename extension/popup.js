/* ElfSec Popup Arayüz Mantığı */
document.addEventListener("DOMContentLoaded", () => {
  const statusEl = document.getElementById("nativeStatus");
  const toggleEl = document.getElementById("enabledToggle");
  const inputEl = document.getElementById("quickInput");
  const scanBtn = document.getElementById("scanBtn");
  const resultEl = document.getElementById("quickResult");
  const alertsEl = document.getElementById("alertsList");
  const optionsBtn = document.getElementById("optionsBtn");
  const statScanned = document.getElementById("statScanned");
  const statThreats = document.getElementById("statThreats");
  const statVerified = document.getElementById("statVerified");

  function refresh() {
    chrome.runtime.sendMessage({ type: "PING" }, (ping) => {
      if (ping && ping.nativeConnected) {
        statusEl.textContent = `Native Bağlı (${ping.version || "ok"})`;
        statusEl.className = "pill ok";
      } else {
        statusEl.textContent = "Tarayıcı Yedek Modu";
        statusEl.className = "pill warn";
      }
    });

    chrome.runtime.sendMessage({ type: "GET_FULL_STATE" }, (st) => {
      if (!st) return;
      toggleEl.checked = Boolean(st.enabled);
      const stats = st.stats || {};
      statScanned.textContent = String((stats.emailsScanned || 0) + (stats.downloadsChecked || 0));
      statThreats.textContent = String(stats.threatsBlocked || 0);
      statVerified.textContent = String(stats.verifiedMatched || 0);

      alertsEl.innerHTML = "";
      const items = Array.isArray(st.recentAlerts) ? st.recentAlerts : [];
      if (!items.length) {
        const li = document.createElement("li");
        li.className = "muted";
        li.textContent = "Henüz şüpheli e-posta veya indirme yakalanmadı.";
        alertsEl.appendChild(li);
        return;
      }
      items.slice(0, 6).forEach((a) => {
        const li = document.createElement("li");
        li.textContent = `[${a.risk_level}] ${a.risk_score}/100 — ${a.subject} (${a.provider})`;
        alertsEl.appendChild(li);
      });
    });
  }

  toggleEl.addEventListener("change", () => {
    chrome.runtime.sendMessage({ type: "SET_ENABLED", enabled: toggleEl.checked });
  });

  scanBtn.addEventListener("click", () => {
    const val = (inputEl.value || "").trim();
    if (!val) return;
    resultEl.textContent = "Taranıyor...";
    chrome.runtime.sendMessage({ type: "SCAN_TEXT", text: val }, (rep) => {
      if (!rep) {
        resultEl.textContent = "Analiz yapılamadı.";
        return;
      }
      const reason = (rep.reasons && rep.reasons[0]) || rep.summary || "";
      resultEl.textContent = `[${rep.risk_level}] ${rep.risk_score}/100 (${rep.via}) — ${reason}`;
    });
  });

  optionsBtn.addEventListener("click", () => {
    if (chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    }
  });

  refresh();
});
