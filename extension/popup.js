/* ElfSec Popup Arayüz Mantığı */
document.addEventListener("DOMContentLoaded", () => {
  const statusEl = document.getElementById("nativeStatus");
  const toggleEl = document.getElementById("enabledToggle");
  const inputEl = document.getElementById("quickInput");
  const scanBtn = document.getElementById("scanBtn");
  const resultEl = document.getElementById("quickResult");
  const alertsEl = document.getElementById("alertsList");

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

    chrome.runtime.sendMessage({ type: "GET_STATE" }, (st) => {
      if (!st) return;
      toggleEl.checked = Boolean(st.enabled);
      alertsEl.innerHTML = "";
      const items = Array.isArray(st.recentAlerts) ? st.recentAlerts : [];
      if (!items.length) {
        const li = document.createElement("li");
        li.className = "muted";
        li.textContent = "Henüz şüpheli webmail yakalanmadı.";
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

  refresh();
});
