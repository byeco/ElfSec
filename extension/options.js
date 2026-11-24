/* ElfSec Ayarlar Sayfası Mantığı */
document.addEventListener("DOMContentLoaded", () => {
  const optWebmail = document.getElementById("optWebmail");
  const optModal = document.getElementById("optModal");
  const optDownloads = document.getElementById("optDownloads");
  const optTracker = document.getElementById("optTracker");
  const registerCmd = document.getElementById("registerCmd");
  const copyCmdBtn = document.getElementById("copyCmdBtn");
  const copyMsg = document.getElementById("copyMsg");
  const trustedInput = document.getElementById("trustedInput");
  const addTrustedBtn = document.getElementById("addTrustedBtn");
  const trustedList = document.getElementById("trustedList");
  const brandLabel = document.getElementById("brandLabel");
  const brandDomain = document.getElementById("brandDomain");
  const brandEmail = document.getElementById("brandEmail");
  const addBrandBtn = document.getElementById("addBrandBtn");
  const brandsList = document.getElementById("brandsList");
  const statsSummary = document.getElementById("statsSummary");
  const exportBtn = document.getElementById("exportBtn");
  const clearBtn = document.getElementById("clearBtn");

  let currentSettings = {};
  let currentState = {};

  const extId = (chrome.runtime && chrome.runtime.id) || "jkmbfppdffpiodlmikbdfdihdkejcfjj";
  registerCmd.textContent = `elfsec.exe browser register --extension-id ${extId}`;

  function saveSettings(partial) {
    currentSettings = { ...currentSettings, ...partial };
    chrome.runtime.sendMessage({ type: "UPDATE_SETTINGS", settings: currentSettings }, render);
  }

  function render() {
    chrome.runtime.sendMessage({ type: "GET_FULL_STATE" }, (st) => {
      if (!st) return;
      currentState = st;
      currentSettings = st.settings || {};
      optWebmail.checked = currentSettings.webmailShield !== false;
      optModal.checked = currentSettings.linkModal !== false;
      optDownloads.checked = currentSettings.downloadsShield !== false;
      optTracker.checked = currentSettings.trackerCounter !== false;

      trustedList.replaceChildren();
      (currentSettings.trustedDomains || []).forEach((dom) => {
        const li = document.createElement("li");
        li.appendChild(document.createTextNode(dom));
        const rm = document.createElement("button");
        rm.type = "button";
        rm.className = "secondary";
        rm.textContent = "Sil";
        rm.setAttribute("aria-label", `${dom} alan adını kaldır`);
        rm.addEventListener("click", () => {
          saveSettings({ trustedDomains: (currentSettings.trustedDomains || []).filter((x) => x !== dom) });
        });
        li.appendChild(rm);
        trustedList.appendChild(li);
      });

      brandsList.replaceChildren();
      (currentSettings.customBrands || []).forEach((b, idx) => {
        const li = document.createElement("li");
        li.appendChild(document.createTextNode(`${b.label} — ${(b.domains || []).join(", ")} ${(b.emails || []).join(", ")}`));
        const rm = document.createElement("button");
        rm.type = "button";
        rm.className = "secondary";
        rm.textContent = "Sil";
        rm.setAttribute("aria-label", `${b.label} markasını kaldır`);
        rm.addEventListener("click", () => {
          const next = (currentSettings.customBrands || []).slice();
          next.splice(idx, 1);
          saveSettings({ customBrands: next });
        });
        li.appendChild(rm);
        brandsList.appendChild(li);
      });

      const s = st.stats || {};
      statsSummary.textContent =
        `Taranan e-posta: ${s.emailsScanned || 0} | İndirme: ${s.downloadsChecked || 0} | ` +
        `Engellenen tehdit: ${s.threatsBlocked || 0} | Doğrulanan marka: ${s.verifiedMatched || 0}`;
    });
  }

  [optWebmail, optModal, optDownloads, optTracker].forEach((el) => {
    el.addEventListener("change", () => {
      saveSettings({
        webmailShield: optWebmail.checked,
        linkModal: optModal.checked,
        downloadsShield: optDownloads.checked,
        trackerCounter: optTracker.checked
      });
    });
  });

  copyCmdBtn.addEventListener("click", () => {
    const done = () => {
      copyMsg.textContent = "Kopyalandı!";
      setTimeout(() => { copyMsg.textContent = ""; }, 2500);
    };
    const fail = () => {
      copyMsg.textContent = "Kopyalanamadı — komutu elle seçin.";
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(registerCmd.textContent).then(done).catch(fail);
    } else {
      fail();
    }
  });

  addTrustedBtn.addEventListener("click", () => {
    const dom = (trustedInput.value || "").trim().toLowerCase().replace(/^@/, "");
    if (!dom || !dom.includes(".")) return;
    const list = (currentSettings.trustedDomains || []).slice();
    if (!list.includes(dom)) list.push(dom);
    trustedInput.value = "";
    saveSettings({ trustedDomains: list });
  });

  addBrandBtn.addEventListener("click", () => {
    const lbl = (brandLabel.value || "").trim();
    const dom = (brandDomain.value || "").trim().toLowerCase().replace(/^@/, "");
    const em = (brandEmail.value || "").trim().toLowerCase();
    if (!lbl || !dom) return;
    const list = (currentSettings.customBrands || []).slice();
    list.push({ label: lbl, domains: [dom], emails: em ? [em] : [] });
    brandLabel.value = "";
    brandDomain.value = "";
    brandEmail.value = "";
    saveSettings({ customBrands: list });
  });

  /* Enter ile ekleme: form alanlarında klavye akışı. */
  [trustedInput, brandLabel, brandDomain, brandEmail].forEach((el) => {
    el.addEventListener("keydown", (ev) => {
      if (ev.key !== "Enter") return;
      ev.preventDefault();
      if (el === trustedInput) addTrustedBtn.click();
      else addBrandBtn.click();
    });
  });

  exportBtn.addEventListener("click", () => {
    const blob = new Blob([JSON.stringify(currentState.recentAlerts || [], null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "elfsec-browser-alerts.json";
    a.click();
    URL.revokeObjectURL(url);
  });

  clearBtn.addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "CLEAR_HISTORY" }, render);
  });

  render();
});
