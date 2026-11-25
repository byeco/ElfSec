/* ElfSec Ayarlar Sayfası Mantığı */
document.addEventListener("DOMContentLoaded", () => {
  const I18n = window.ElfSecI18n || { t: (_k, fb) => fb, applyI18n: () => {}, applyTheme: () => {} };
  I18n.applyI18n(document);

  const $ = (id) => document.getElementById(id);
  const optVersion = $("optVersion");
  const sideNativePill = $("sideNativePill");
  const nativeCardPill = $("nativeCardPill");
  const nativeStateTitle = $("nativeStateTitle");
  const nativeStateDetail = $("nativeStateDetail");
  const testNativeBtn = $("testNativeBtn");
  const extIdBadge = $("extIdBadge");

  const optWebmail = $("optWebmail");
  const optModal = $("optModal");
  const optDownloads = $("optDownloads");
  const optTracker = $("optTracker");
  const themeBtns = Array.from(document.querySelectorAll("[data-theme-choice]"));

  const registerCmd = $("registerCmd");
  const copyCmdBtn = $("copyCmdBtn");
  const copyMsg = $("copyMsg");

  const trustedInput = $("trustedInput");
  const addTrustedBtn = $("addTrustedBtn");
  const trustedErr = $("trustedErr");
  const trustedCount = $("trustedCount");
  const trustedList = $("trustedList");

  const brandLabel = $("brandLabel");
  const brandDomain = $("brandDomain");
  const brandEmail = $("brandEmail");
  const addBrandBtn = $("addBrandBtn");
  const brandErr = $("brandErr");
  const brandsCount = $("brandsCount");
  const brandsList = $("brandsList");

  const builtinCount = $("builtinCount");
  const builtinSearch = $("builtinSearch");
  const builtinBrandsList = $("builtinBrandsList");

  const kpiEmails = $("kpiEmails");
  const kpiDownloads = $("kpiDownloads");
  const kpiThreats = $("kpiThreats");
  const kpiVerified = $("kpiVerified");
  const statsSummary = $("statsSummary");
  const optAlertsPreview = $("optAlertsPreview");
  const exportBtn = $("exportBtn");
  const clearBtn = $("clearBtn");
  const clearConfirmBar = $("clearConfirmBar");
  const clearYesBtn = $("clearYesBtn");
  const clearNoBtn = $("clearNoBtn");

  const navLinks = Array.from(document.querySelectorAll(".nav-link"));

  const DOMAIN_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;
  const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  let currentSettings = {};
  let currentState = {};
  let builtinBrands = [];

  const extId = (chrome.runtime && chrome.runtime.id) || "jkmbfppdffpiodlmikbdfdihdkejcfjj";
  extIdBadge.textContent = extId;
  registerCmd.textContent = `elfsec.exe browser register --extension-id ${extId}`;

  try {
    optVersion.textContent = chrome.runtime.getManifest().version;
  } catch (_e) { /* varsayılan kalır */ }

  function updateNavHighlight() {
    const hash = window.location.hash || "#shields";
    navLinks.forEach((a) => {
      a.classList.toggle("is-active", a.getAttribute("href") === hash);
    });
  }

  window.addEventListener("hashchange", updateNavHighlight);
  updateNavHighlight();

  function setNativeBadge(connected, version, engine) {
    const label = connected
      ? `Native${version ? ` v${version}` : ""}`
      : I18n.t("statusFallback", "Yedek Mod");
    const cls = `elf-pill ${connected ? "ok" : "warn"}`;
    sideNativePill.textContent = label;
    sideNativePill.className = cls;
    nativeCardPill.textContent = label;
    nativeCardPill.className = cls;
    nativeStateTitle.textContent = connected
      ? `Masaüstü ElfSec motoru bağlı${version ? ` (v${version})` : ""}`
      : "Masaüstü Native Host bağlı değil (Tarayıcı yedek motoru aktif)";
    nativeStateDetail.textContent = connected
      ? `Motor: ${engine || "elfsec-local"} · com.elfsec.guard`
      : "Eşleştirmek için aşağıdaki komutu terminalde çalıştırın.";
  }

  function testNativeConnection() {
    sideNativePill.textContent = I18n.t("statusChecking", "Kontrol ediliyor");
    sideNativePill.className = "elf-pill warn";
    chrome.runtime.sendMessage({ type: "PING" }, (ping) => {
      if (chrome.runtime.lastError || !ping) {
        setNativeBadge(false, "", "");
        return;
      }
      setNativeBadge(Boolean(ping.nativeConnected), ping.version || "", ping.engine || "");
    });
  }

  function applyThemeSelection(theme) {
    const active = theme === "dark" || theme === "light" ? theme : "auto";
    I18n.applyTheme(active);
    themeBtns.forEach((b) => {
      b.classList.toggle("is-active", b.dataset.themeChoice === active);
    });
  }

  function saveSettings(partial) {
    currentSettings = { ...currentSettings, ...partial };
    chrome.runtime.sendMessage({ type: "UPDATE_SETTINGS", settings: currentSettings }, render);
  }

  function renderBuiltinCatalog() {
    const q = (builtinSearch.value || "").trim().toLowerCase();
    const list = builtinBrands.filter((b) => {
      if (!q) return true;
      const hay = [b.label].concat(b.domains || []).concat(b.aliases || []).join(" ").toLowerCase();
      return hay.includes(q);
    });
    builtinCount.textContent = String(builtinBrands.length);
    builtinBrandsList.replaceChildren();
    if (!list.length) {
      const emp = document.createElement("div");
      emp.className = "empty-row";
      emp.textContent = "Eşleşen yerleşik marka bulunamadı.";
      builtinBrandsList.appendChild(emp);
      return;
    }
    list.forEach((b) => {
      const card = document.createElement("div");
      card.className = "brand-chip";
      const lbl = document.createElement("strong");
      lbl.textContent = b.label;
      const doms = document.createElement("span");
      doms.textContent = (b.domains || []).join(", ");
      card.append(lbl, doms);
      builtinBrandsList.appendChild(card);
    });
  }

  function render() {
    chrome.runtime.sendMessage({ type: "GET_FULL_STATE" }, (st) => {
      if (chrome.runtime.lastError || !st) return;
      currentState = st;
      currentSettings = st.settings || {};
      optWebmail.checked = currentSettings.webmailShield !== false;
      optModal.checked = currentSettings.linkModal !== false;
      optDownloads.checked = currentSettings.downloadsShield !== false;
      optTracker.checked = currentSettings.trackerCounter !== false;
      applyThemeSelection(currentSettings.theme || "auto");

      const trusted = currentSettings.trustedDomains || [];
      trustedCount.textContent = `${trusted.length} kayıt`;
      trustedList.replaceChildren();
      if (!trusted.length) {
        const li = document.createElement("li");
        li.className = "empty-row";
        li.textContent = "Henüz güvenilen alan adı eklenmedi.";
        trustedList.appendChild(li);
      } else {
        trusted.forEach((dom) => {
          const li = document.createElement("li");
          li.className = "item-row";
          const span = document.createElement("span");
          span.textContent = dom;
          const rm = document.createElement("button");
          rm.type = "button";
          rm.className = "elf-btn elf-btn-secondary";
          rm.style.minHeight = "32px";
          rm.style.padding = "4px 10px";
          rm.style.fontSize = "12px";
          rm.textContent = "Sil";
          rm.setAttribute("aria-label", `${dom} alan adını kaldır`);
          rm.addEventListener("click", () => {
            saveSettings({ trustedDomains: trusted.filter((x) => x !== dom) });
          });
          li.append(span, rm);
          trustedList.appendChild(li);
        });
      }

      const customBrands = currentSettings.customBrands || [];
      brandsCount.textContent = `${customBrands.length} özel`;
      brandsList.replaceChildren();
      if (!customBrands.length) {
        const li = document.createElement("li");
        li.className = "empty-row";
        li.textContent = "Henüz özel marka eklenmedi.";
        brandsList.appendChild(li);
      } else {
        customBrands.forEach((b, idx) => {
          const li = document.createElement("li");
          li.className = "item-row";
          const copy = document.createElement("div");
          const title = document.createElement("strong");
          title.textContent = b.label;
          const sub = document.createElement("div");
          sub.className = "item-row-sub";
          sub.textContent = [(b.domains || []).join(", "), (b.emails || []).join(", ")].filter(Boolean).join(" · ");
          copy.append(title, sub);

          const rm = document.createElement("button");
          rm.type = "button";
          rm.className = "elf-btn elf-btn-secondary";
          rm.style.minHeight = "32px";
          rm.style.padding = "4px 10px";
          rm.style.fontSize = "12px";
          rm.textContent = "Sil";
          rm.setAttribute("aria-label", `${b.label} markasını kaldır`);
          rm.addEventListener("click", () => {
            const next = customBrands.slice();
            next.splice(idx, 1);
            saveSettings({ customBrands: next });
          });
          li.append(copy, rm);
          brandsList.appendChild(li);
        });
      }

      const s = st.stats || {};
      kpiEmails.textContent = String(Number(s.emailsScanned) || 0);
      kpiDownloads.textContent = String(Number(s.downloadsChecked) || 0);
      kpiThreats.textContent = String(Number(s.threatsBlocked) || 0);
      kpiVerified.textContent = String(Number(s.verifiedMatched) || 0);
      statsSummary.textContent =
        `Riskli indirme: ${Number(s.riskyDownloads) || 0} · Toplam kayıtlı alarm: ${(st.recentAlerts || []).length}`;

      optAlertsPreview.replaceChildren();
      const preview = Array.isArray(st.recentAlerts) ? st.recentAlerts.slice(0, 5) : [];
      if (!preview.length) {
        const li = document.createElement("li");
        li.className = "empty-row";
        li.textContent = "Kayıtlı alarm geçmişi temiz.";
        optAlertsPreview.appendChild(li);
      } else {
        preview.forEach((a) => {
          const li = document.createElement("li");
          li.className = "item-row";
          const copy = document.createElement("div");
          const title = document.createElement("strong");
          title.textContent = String((a && a.subject) || "(konu yok)");
          const sub = document.createElement("div");
          sub.className = "item-row-sub";
          sub.textContent = `${a.provider || "webmail"} · ${a.sender || ""} · ${a.via || ""}`;
          copy.append(title, sub);

          const lvl = String((a && a.risk_level) || "LOW").toLowerCase();
          const pill = document.createElement("span");
          pill.className = `elf-level ${lvl}`;
          pill.textContent = `${a.risk_level || "LOW"} · ${Number(a.risk_score) || 0}/100`;
          li.append(copy, pill);
          optAlertsPreview.appendChild(li);
        });
      }
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

  themeBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      const theme = btn.dataset.themeChoice || "auto";
      applyThemeSelection(theme);
      saveSettings({ theme });
    });
  });

  testNativeBtn.addEventListener("click", testNativeConnection);

  copyCmdBtn.addEventListener("click", () => {
    const done = () => {
      copyMsg.textContent = I18n.t("copiedMsg", "Komut panoya kopyalandı.");
      setTimeout(() => { copyMsg.textContent = ""; }, 2500);
    };
    const fail = () => {
      copyMsg.textContent = I18n.t("copyFailMsg", "Kopyalanamadı — komutu elle seçin.");
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(registerCmd.textContent).then(done).catch(fail);
    } else {
      fail();
    }
  });

  addTrustedBtn.addEventListener("click", () => {
    trustedErr.textContent = "";
    const dom = (trustedInput.value || "")
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, "")
      .replace(/^@/, "")
      .split("/")[0];
    if (!DOMAIN_RE.test(dom)) {
      trustedErr.textContent = "Geçerli bir alan adı girin (örn: sirketim.com.tr).";
      trustedInput.focus();
      return;
    }
    const list = (currentSettings.trustedDomains || []).slice();
    if (!list.includes(dom)) list.push(dom);
    trustedInput.value = "";
    saveSettings({ trustedDomains: list });
  });

  addBrandBtn.addEventListener("click", () => {
    brandErr.textContent = "";
    const lbl = (brandLabel.value || "").trim();
    const dom = (brandDomain.value || "")
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, "")
      .replace(/^@/, "")
      .split("/")[0];
    const em = (brandEmail.value || "").trim().toLowerCase();
    if (!lbl) {
      brandErr.textContent = "Marka adı boş bırakılamaz.";
      brandLabel.focus();
      return;
    }
    if (!DOMAIN_RE.test(dom)) {
      brandErr.textContent = "Geçerli bir resmi alan adı girin (örn: sirketim.com).";
      brandDomain.focus();
      return;
    }
    if (em && !EMAIL_RE.test(em)) {
      brandErr.textContent = "Resmi e-posta adresi geçersiz görünüyor.";
      brandEmail.focus();
      return;
    }
    const list = (currentSettings.customBrands || []).slice();
    list.push({ label: lbl, domains: [dom], emails: em ? [em] : [] });
    brandLabel.value = "";
    brandDomain.value = "";
    brandEmail.value = "";
    saveSettings({ customBrands: list });
  });

  [trustedInput, brandLabel, brandDomain, brandEmail].forEach((el) => {
    el.addEventListener("keydown", (ev) => {
      if (ev.key !== "Enter") return;
      ev.preventDefault();
      if (el === trustedInput) addTrustedBtn.click();
      else addBrandBtn.click();
    });
  });

  builtinSearch.addEventListener("input", renderBuiltinCatalog);

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
    clearConfirmBar.classList.add("show");
  });

  clearNoBtn.addEventListener("click", () => {
    clearConfirmBar.classList.remove("show");
  });

  clearYesBtn.addEventListener("click", () => {
    clearConfirmBar.classList.remove("show");
    chrome.runtime.sendMessage({ type: "CLEAR_HISTORY" }, render);
  });

  chrome.runtime.sendMessage({ type: "GET_VERIFIED_BRANDS" }, (res) => {
    if (chrome.runtime.lastError || !res || !Array.isArray(res.brands)) return;
    builtinBrands = res.brands;
    renderBuiltinCatalog();
  });

  testNativeConnection();
  render();
});
