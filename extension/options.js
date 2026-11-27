/* ElfSec Ayarlar Sayfası Mantığı */
document.addEventListener("DOMContentLoaded", () => {
  const I18n = window.ElfSecI18n || { t: (_k, fb) => fb, applyI18n: () => {}, applyTheme: () => {} };
  I18n.applyI18n(document);

  const $ = (id) => document.getElementById(id);
  const optVersion = $("optVersion");
  const sideMasterDot = $("sideMasterDot");
  const sideMasterLabel = $("sideMasterLabel");
  const sideShieldFraction = $("sideShieldFraction");
  const sideNativePill = $("sideNativePill");
  const navTrustedCount = $("navTrustedCount");
  const navBrandsCount = $("navBrandsCount");
  const navAlertsCount = $("navAlertsCount");

  const postureHero = $("postureHero");
  const heroMasterTitle = $("heroMasterTitle");
  const heroShieldChip = $("heroShieldChip");
  const heroNativeChip = $("heroNativeChip");
  const optMasterEnabled = $("optMasterEnabled");
  const masterPausedNotice = $("masterPausedNotice");

  const optWebmail = $("optWebmail");
  const optModal = $("optModal");
  const optDownloads = $("optDownloads");
  const optTracker = $("optTracker");
  const shieldBindings = [
    { input: optWebmail, card: $("cardWebmail"), badge: $("stateWebmail") },
    { input: optModal, card: $("cardModal"), badge: $("stateModal") },
    { input: optDownloads, card: $("cardDownloads"), badge: $("stateDownloads") },
    { input: optTracker, card: $("cardTracker"), badge: $("stateTracker") }
  ];
  const themeBtns = Array.from(document.querySelectorAll("[data-theme-choice]"));

  const nativeStatusCard = $("nativeStatusCard");
  const nativeCardPill = $("nativeCardPill");
  const nativeStateTitle = $("nativeStateTitle");
  const nativeStateDetail = $("nativeStateDetail");
  const nativeEngineChip = $("nativeEngineChip");
  const testNativeBtn = $("testNativeBtn");
  const optNativeBridge = $("optNativeBridge");
  const cardNativeBridge = $("cardNativeBridge");
  const stateNativeBridge = $("stateNativeBridge");
  const extIdBadge = $("extIdBadge");
  const copyExtIdBtn = $("copyExtIdBtn");
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
  const builtinSearchClear = $("builtinSearchClear");
  const builtinMatchCount = $("builtinMatchCount");
  const builtinBrandsList = $("builtinBrandsList");

  const kpiEmails = $("kpiEmails");
  const kpiDownloads = $("kpiDownloads");
  const kpiThreats = $("kpiThreats");
  const kpiVerified = $("kpiVerified");
  const statsSummary = $("statsSummary");
  const optAlertsCount = $("optAlertsCount");
  const optAlertsPreview = $("optAlertsPreview");
  const historyFilterBtns = Array.from(document.querySelectorAll("[data-history-filter]"));
  const exportBtn = $("exportBtn");
  const clearBtn = $("clearBtn");
  const clearConfirmBar = $("clearConfirmBar");
  const clearYesBtn = $("clearYesBtn");
  const clearNoBtn = $("clearNoBtn");
  const rateStoreLink = $("rateStoreLink");
  const elfToast = $("elfToast");

  const navLinks = Array.from(document.querySelectorAll(".nav-link"));
  const sectionEls = Array.from(document.querySelectorAll("main > section.card[id]"));

  const DOMAIN_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;
  const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const SVG_NS = "http://www.w3.org/2000/svg";

  let currentSettings = {};
  let currentState = {};
  let builtinBrands = [];
  let historyFilter = "all";
  let toastTimer = null;

  const extId = (chrome.runtime && chrome.runtime.id) || "jkmbfppdffpiodlmikbdfdihdkejcfjj";
  extIdBadge.textContent = extId;
  registerCmd.textContent = `elfsec.exe browser register --extension-id ${extId}`;

  if (rateStoreLink) {
    const ua = (navigator && navigator.userAgent) || "";
    if (ua.includes("Firefox/")) {
      rateStoreLink.href = "https://addons.mozilla.org/firefox/addon/elfsec-guard/reviews/";
    } else if (ua.includes("Edg/")) {
      rateStoreLink.href = `https://microsoftedge.microsoft.com/addons/detail/${extId}`;
    } else {
      rateStoreLink.href = `https://chromewebstore.google.com/detail/${extId}/reviews`;
    }
  }

  try {
    optVersion.textContent = chrome.runtime.getManifest().version;
  } catch (_e) { /* varsayılan kalır */ }

  function showToast(message, kind) {
    if (!elfToast || !message) return;
    clearTimeout(toastTimer);
    elfToast.textContent = message;
    elfToast.className = `elf-toast ${kind === "warn" ? "warn " : ""}show`;
    toastTimer = setTimeout(() => {
      elfToast.classList.remove("show");
    }, 2400);
  }

  function makeSvg(paths, size) {
    const svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("width", String(size || 15));
    svg.setAttribute("height", String(size || 15));
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "1.9");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    svg.setAttribute("aria-hidden", "true");
    paths.forEach((d) => {
      const p = document.createElementNS(SVG_NS, "path");
      p.setAttribute("d", d);
      svg.appendChild(p);
    });
    return svg;
  }

  function makeSourceIcon(source) {
    if (source === "browser_download") {
      return makeSvg(["M12 3v12", "m7 10 5 5 5-5", "M5 19h14"], 15);
    }
    if (source === "context_menu" || source === "quick_scan") {
      return makeSvg([
        "M10 13a5 5 0 0 0 7.07 0l2.83-2.83a5 5 0 0 0-7.07-7.07L11 4.93",
        "M14 11a5 5 0 0 0-7.07 0L4.1 13.83a5 5 0 0 0 7.07 7.07L13 19.07"
      ], 15);
    }
    return makeSvg(["M3 5h18v14H3z", "m3 7 9 6 9-6"], 15);
  }

  function levelMeta(raw) {
    const lvl = String(raw || "LOW").toUpperCase();
    if (lvl === "CRITICAL") return { code: "CRITICAL", cls: "critical", label: I18n.t("riskCritical", "Kritik") };
    if (lvl === "HIGH") return { code: "HIGH", cls: "high", label: I18n.t("riskHigh", "Yüksek") };
    if (lvl === "MEDIUM") return { code: "MEDIUM", cls: "medium", label: I18n.t("riskMedium", "Orta") };
    return { code: "LOW", cls: "low", label: I18n.t("riskLow", "Düşük") };
  }

  function formatTime(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return "";
    return d.toLocaleString("tr-TR", {
      day: "2-digit",
      month: "2-digit",
      hour: "2-digit",
      minute: "2-digit"
    });
  }

  function setActiveNav(targetId) {
    const hash = `#${targetId || "shields"}`;
    navLinks.forEach((a) => {
      a.classList.toggle("is-active", a.getAttribute("href") === hash);
    });
  }

  navLinks.forEach((a) => {
    a.addEventListener("click", () => {
      const id = (a.getAttribute("href") || "").replace(/^#/, "");
      if (id) setActiveNav(id);
    });
  });

  window.addEventListener("hashchange", () => {
    setActiveNav((window.location.hash || "#shields").replace(/^#/, ""));
  });

  if (typeof IntersectionObserver === "function" && sectionEls.length) {
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((e) => e.isIntersecting)
          .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
        if (visible && visible.target && visible.target.id) {
          setActiveNav(visible.target.id);
        }
      },
      { rootMargin: "-18% 0px -62% 0px", threshold: [0.05, 0.25, 0.5] }
    );
    sectionEls.forEach((sec) => observer.observe(sec));
  }
  setActiveNav((window.location.hash || "#shields").replace(/^#/, ""));

  function syncShieldUI(enabled) {
    const activeLabel = I18n.t("shieldActive", "Aktif");
    const offLabel = I18n.t("shieldOff", "Kapalı");
    let activeCount = 0;

    shieldBindings.forEach(({ input, card, badge }) => {
      const on = Boolean(input.checked);
      if (on) activeCount += 1;
      card.classList.toggle("is-on", on);
      badge.textContent = on ? activeLabel : offLabel;
    });

    const fraction = `${activeCount}/4`;
    sideShieldFraction.textContent = fraction;
    heroShieldChip.textContent = `${fraction} ${I18n.t("activeShieldsChip", "Kalkan")}`;
    heroShieldChip.className = `hero-chip ${enabled && activeCount > 0 ? "ok" : "warn"}`;

    postureHero.classList.toggle("is-paused", !enabled);
    sideMasterDot.classList.toggle("is-paused", !enabled);
    masterPausedNotice.hidden = Boolean(enabled);

    const postureText = enabled
      ? I18n.t("protectionActive", "Koruma Aktif")
      : I18n.t("protectionPaused", "Koruma Duraklatıldı");
    heroMasterTitle.textContent = postureText;
    sideMasterLabel.textContent = postureText;
  }

  function setNativeBadge(connected, version, engine, bridgeEnabled) {
    const enabled = bridgeEnabled !== false;
    if (!enabled) {
      const label = I18n.t("statusBrowserOnly", "Tarayıcı Modu");
      sideNativePill.textContent = label;
      sideNativePill.className = "elf-pill ok side-native-link";
      nativeCardPill.textContent = label;
      nativeCardPill.className = "elf-pill ok";
      heroNativeChip.textContent = label;
      heroNativeChip.className = "hero-chip ok";
      nativeStatusCard.classList.remove("is-connected");
      nativeStateTitle.textContent = I18n.t("nativeDisabledTitle", "Yalnızca tarayıcı içi koruma aktif");
      nativeStateDetail.textContent = I18n.t(
        "nativeDisabledDetail",
        "Masaüstü Native Host köprüsü kapalı (varsayılan). İsteğe bağlı derin tarama için yukarıdaki anahtardan açabilirsiniz."
      );
      nativeEngineChip.textContent = I18n.t("nativeBrowserOnlyChip", "Tarayıcı İçi");
      testNativeBtn.disabled = true;
      return;
    }

    testNativeBtn.disabled = false;
    const label = connected
      ? `Native${version ? ` v${version}` : ""}`
      : I18n.t("statusFallback", "Yedek Mod");
    const cls = `elf-pill ${connected ? "ok" : "warn"}`;

    sideNativePill.textContent = label;
    sideNativePill.className = `${cls} side-native-link`;
    nativeCardPill.textContent = label;
    nativeCardPill.className = cls;
    heroNativeChip.textContent = label;
    heroNativeChip.className = `hero-chip ${connected ? "ok" : "warn"}`;
    nativeStatusCard.classList.toggle("is-connected", Boolean(connected));

    nativeStateTitle.textContent = connected
      ? `${I18n.t("nativeConnectedTitle", "Masaüstü ElfSec motoru bağlı")}${version ? ` (v${version})` : ""}`
      : I18n.t("nativeDisconnectedTitle", "Masaüstü Native Host bağlı değil");
    nativeStateDetail.textContent = connected
      ? `${I18n.t("nativeEngineLabel", "Motor")}: ${engine || "elfsec-local"} · com.elfsec.guard`
      : I18n.t("nativeDisconnectedDetail", "Tarayıcı yedek motoru aktif. Derin PE/MotW taraması için aşağıdaki komutu çalıştırın.");
    nativeEngineChip.textContent = connected
      ? `${engine || "elfsec-local"}`
      : I18n.t("nativeFallbackChip", "Tarayıcı Yedek");
  }

  function testNativeConnection(showFeedback) {
    if (currentSettings.nativeBridgeEnabled !== true) {
      setNativeBadge(false, "", "", false);
      return;
    }
    sideNativePill.textContent = I18n.t("statusChecking", "Kontrol ediliyor");
    sideNativePill.className = "elf-pill warn side-native-link";
    testNativeBtn.disabled = true;
    testNativeBtn.classList.add("is-spinning");

    chrome.runtime.sendMessage({ type: "PING" }, (ping) => {
      testNativeBtn.disabled = false;
      testNativeBtn.classList.remove("is-spinning");
      if (chrome.runtime.lastError || !ping) {
        setNativeBadge(false, "", "", true);
        if (showFeedback) showToast(I18n.t("toastNativeFallback", "Masaüstü host bulunamadı — yedek motor aktif"), "warn");
        return;
      }
      if (ping.nativeEnabled === false) {
        setNativeBadge(false, "", "", false);
        return;
      }
      const connected = Boolean(ping.nativeConnected);
      setNativeBadge(connected, ping.version || "", ping.engine || "", true);
      if (showFeedback) {
        showToast(
          connected
            ? I18n.t("toastNativeOk", "Masaüstü Native Host bağlantısı doğrulandı")
            : I18n.t("toastNativeFallback", "Masaüstü host bulunamadı — yedek motor aktif"),
          connected ? "ok" : "warn"
        );
      }
    });
  }

  function applyThemeSelection(theme) {
    const active = theme === "dark" || theme === "light" ? theme : "auto";
    I18n.applyTheme(active);
    themeBtns.forEach((b) => {
      const selected = b.dataset.themeChoice === active;
      b.classList.toggle("is-active", selected);
      b.setAttribute("aria-pressed", selected ? "true" : "false");
    });
  }

  function saveSettings(partial, toastMsg) {
    currentSettings = { ...currentSettings, ...partial };
    chrome.runtime.sendMessage({ type: "UPDATE_SETTINGS", settings: currentSettings }, () => {
      render();
      if (toastMsg) showToast(toastMsg);
    });
  }

  function renderBuiltinCatalog() {
    const q = (builtinSearch.value || "").trim().toLowerCase();
    builtinSearchClear.hidden = !q;

    const list = builtinBrands.filter((b) => {
      if (!q) return true;
      const hay = [b.label].concat(b.domains || []).concat(b.aliases || []).join(" ").toLowerCase();
      return hay.includes(q);
    });

    builtinCount.textContent = String(builtinBrands.length);
    builtinMatchCount.textContent = `${list.length} / ${builtinBrands.length}`;
    builtinBrandsList.replaceChildren();

    if (!list.length) {
      const emp = document.createElement("div");
      emp.className = "empty-row";
      emp.textContent = I18n.t("builtinEmpty", "Eşleşen yerleşik marka bulunamadı.");
      builtinBrandsList.appendChild(emp);
      return;
    }

    list.forEach((b) => {
      const card = document.createElement("div");
      card.className = "brand-chip";

      const head = document.createElement("div");
      head.className = "brand-chip-head";

      const avatar = document.createElement("span");
      avatar.className = "brand-chip-avatar";
      avatar.textContent = String(b.label || "?").slice(0, 1).toUpperCase();

      const nameWrap = document.createElement("div");
      nameWrap.className = "brand-chip-name";
      const lbl = document.createElement("span");
      lbl.textContent = b.label;
      const tick = makeSvg(["M20 6 9 17l-5-5"], 13);
      nameWrap.append(lbl, tick);

      head.append(avatar, nameWrap);

      const tags = document.createElement("div");
      tags.className = "brand-domain-tags";
      (b.domains || []).forEach((d) => {
        const chip = document.createElement("span");
        chip.className = "domain-chip";
        chip.textContent = d;
        tags.appendChild(chip);
      });

      card.append(head, tags);
      builtinBrandsList.appendChild(card);
    });
  }

  function renderAlertsList(alerts) {
    const list = Array.isArray(alerts) ? alerts : [];
    const filtered = list.filter((a) => {
      const lvl = String((a && a.risk_level) || "LOW").toUpperCase();
      if (historyFilter === "high") return lvl === "HIGH" || lvl === "CRITICAL";
      if (historyFilter === "medium") return lvl === "MEDIUM";
      return true;
    });

    optAlertsCount.textContent = `${filtered.length} ${I18n.t("trustedCountSuffix", "kayıt")}`;
    navAlertsCount.textContent = String(list.length);
    optAlertsPreview.replaceChildren();

    const preview = filtered.slice(0, 15);
    if (!preview.length) {
      const li = document.createElement("li");
      li.className = "empty-row";
      li.textContent = I18n.t("alertsClean", "Seçili filtrede kayıtlı alarm bulunamadı.");
      optAlertsPreview.appendChild(li);
      return;
    }

    preview.forEach((a) => {
      const meta = levelMeta(a && a.risk_level);
      const li = document.createElement("li");
      li.className = "alert-row";
      li.dataset.level = meta.code;

      const ico = document.createElement("span");
      ico.className = "alert-src-ico";
      ico.appendChild(makeSourceIcon(a && a.source));

      const copy = document.createElement("div");
      copy.className = "alert-copy";
      const title = document.createElement("strong");
      title.textContent = String((a && a.subject) || I18n.t("noSubject", "(konu yok)"));
      const sub = document.createElement("div");
      sub.className = "item-row-sub";
      sub.textContent = [
        a && a.provider ? String(a.provider) : "webmail",
        a && a.sender ? String(a.sender) : "",
        a && a.via ? String(a.via) : "",
        formatTime(a && a.at)
      ].filter(Boolean).join(" · ");
      copy.append(title, sub);

      const pill = document.createElement("span");
      pill.className = `elf-level ${meta.cls}`;
      pill.textContent = `${meta.label} · ${Number(a && a.risk_score) || 0}/100`;

      li.append(ico, copy, pill);
      optAlertsPreview.appendChild(li);
    });
  }

  function render() {
    chrome.runtime.sendMessage({ type: "GET_FULL_STATE" }, (st) => {
      if (chrome.runtime.lastError || !st) return;
      currentState = st;
      currentSettings = st.settings || {};

      const masterEnabled = st.enabled !== false;
      optMasterEnabled.checked = masterEnabled;
      optWebmail.checked = currentSettings.webmailShield !== false;
      optModal.checked = currentSettings.linkModal !== false;
      optDownloads.checked = currentSettings.downloadsShield !== false;
      optTracker.checked = currentSettings.trackerCounter !== false;
      const bridgeEnabled = currentSettings.nativeBridgeEnabled === true;
      if (optNativeBridge) optNativeBridge.checked = bridgeEnabled;
      if (cardNativeBridge) cardNativeBridge.classList.toggle("is-on", bridgeEnabled);
      if (stateNativeBridge) {
        stateNativeBridge.textContent = bridgeEnabled
          ? I18n.t("shieldActive", "Aktif")
          : I18n.t("shieldOff", "Kapalı");
      }
      if (!bridgeEnabled) {
        setNativeBadge(false, "", "", false);
      } else {
        setNativeBadge(Boolean(st.nativeConnected), st.nativeVersion || "", "", true);
      }
      syncShieldUI(masterEnabled);
      applyThemeSelection(currentSettings.theme || "auto");

      const trusted = currentSettings.trustedDomains || [];
      trustedCount.textContent = `${trusted.length} ${I18n.t("trustedCountSuffix", "kayıt")}`;
      navTrustedCount.textContent = String(trusted.length);
      trustedList.replaceChildren();
      if (!trusted.length) {
        const li = document.createElement("li");
        li.className = "empty-row";
        li.textContent = I18n.t("trustedEmpty", "Henüz güvenilen alan adı eklenmedi. Eklediğiniz alan adları burada listelenir.");
        trustedList.appendChild(li);
      } else {
        trusted.forEach((dom) => {
          const li = document.createElement("li");
          li.className = "item-row";

          const main = document.createElement("div");
          main.className = "item-main";
          const mono = document.createElement("span");
          mono.className = "monogram-badge";
          mono.textContent = dom.slice(0, 1);
          const span = document.createElement("span");
          span.className = "item-domain-text";
          span.textContent = dom;
          main.append(mono, span);

          const actions = document.createElement("div");
          actions.className = "item-actions";
          const allowChip = document.createElement("span");
          allowChip.className = "allow-chip";
          allowChip.textContent = I18n.t("trustedBadge", "İzin Listesinde");

          const rm = document.createElement("button");
          rm.type = "button";
          rm.className = "elf-btn elf-btn-secondary btn-compact btn-remove";
          rm.textContent = I18n.t("removeBtn", "Sil");
          rm.setAttribute("aria-label", `${dom}`);
          rm.addEventListener("click", () => {
            saveSettings(
              { trustedDomains: trusted.filter((x) => x !== dom) },
              I18n.t("toastDomainRemoved", "Alan adı kaldırıldı")
            );
          });
          actions.append(allowChip, rm);

          li.append(main, actions);
          trustedList.appendChild(li);
        });
      }

      const customBrands = currentSettings.customBrands || [];
      brandsCount.textContent = `${customBrands.length} ${I18n.t("brandsCountSuffix", "özel")}`;
      navBrandsCount.textContent = String(customBrands.length);
      brandsList.replaceChildren();
      if (!customBrands.length) {
        const li = document.createElement("li");
        li.className = "empty-row";
        li.textContent = I18n.t("brandsEmpty", "Henüz özel marka eklenmedi. Kurumunuzun resmi alan adını ekleyerek taklit e-postaları tespit edin.");
        brandsList.appendChild(li);
      } else {
        customBrands.forEach((b, idx) => {
          const li = document.createElement("li");
          li.className = "item-row";

          const main = document.createElement("div");
          main.className = "item-main";
          const mono = document.createElement("span");
          mono.className = "monogram-badge";
          mono.textContent = String(b.label || "?").slice(0, 1);

          const copy = document.createElement("div");
          copy.className = "item-copy";
          const title = document.createElement("strong");
          title.textContent = b.label;
          const sub = document.createElement("div");
          sub.className = "item-row-sub";
          sub.textContent = [(b.domains || []).join(", "), (b.emails || []).join(", ")].filter(Boolean).join(" · ");
          copy.append(title, sub);
          main.append(mono, copy);

          const rm = document.createElement("button");
          rm.type = "button";
          rm.className = "elf-btn elf-btn-secondary btn-compact btn-remove";
          rm.textContent = I18n.t("removeBtn", "Sil");
          rm.setAttribute("aria-label", `${b.label}`);
          rm.addEventListener("click", () => {
            const next = customBrands.slice();
            next.splice(idx, 1);
            saveSettings({ customBrands: next }, I18n.t("toastBrandRemoved", "Özel marka kaldırıldı"));
          });

          li.append(main, rm);
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

      renderAlertsList(st.recentAlerts);
    });
  }

  optMasterEnabled.addEventListener("change", () => {
    const enabled = optMasterEnabled.checked;
    syncShieldUI(enabled);
    chrome.runtime.sendMessage({ type: "SET_ENABLED", enabled }, () => {
      if (chrome.runtime.lastError) {
        optMasterEnabled.checked = !enabled;
        syncShieldUI(!enabled);
        return;
      }
      showToast(
        enabled
          ? I18n.t("toastProtectionOn", "Genel koruma etkinleştirildi")
          : I18n.t("toastProtectionOff", "Genel koruma duraklatıldı"),
        enabled ? "ok" : "warn"
      );
    });
  });

  [optWebmail, optModal, optDownloads, optTracker].forEach((el) => {
    el.addEventListener("change", () => {
      syncShieldUI(optMasterEnabled.checked);
      saveSettings({
        webmailShield: optWebmail.checked,
        linkModal: optModal.checked,
        downloadsShield: optDownloads.checked,
        trackerCounter: optTracker.checked
      }, I18n.t("toastSaved", "Ayarlar kaydedildi"));
    });
  });

  themeBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      const theme = btn.dataset.themeChoice || "auto";
      applyThemeSelection(theme);
      saveSettings({ theme }, I18n.t("toastThemeChanged", "Tema güncellendi"));
    });
  });

  testNativeBtn.addEventListener("click", () => testNativeConnection(true));

  if (optNativeBridge) {
    optNativeBridge.addEventListener("change", () => {
      const bridgeEnabled = optNativeBridge.checked;
      currentSettings = { ...currentSettings, nativeBridgeEnabled: bridgeEnabled };
      chrome.runtime.sendMessage({ type: "UPDATE_SETTINGS", settings: currentSettings }, () => {
        render();
        if (bridgeEnabled) {
          showToast(I18n.t("toastNativeBridgeOn", "Masaüstü Native Host köprüsü açıldı"));
          testNativeConnection(true);
        } else {
          setNativeBadge(false, "", "", false);
          showToast(I18n.t("toastNativeBridgeOff", "Masaüstü Native Host köprüsü kapatıldı — tarayıcı modu aktif"));
        }
      });
    });
  }

  function copyText(text, onSuccess, onFail) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(onSuccess).catch(onFail);
    } else {
      onFail();
    }
  }

  copyCmdBtn.addEventListener("click", () => {
    const labelEl = copyCmdBtn.querySelector("span");
    copyText(
      registerCmd.textContent,
      () => {
        copyMsg.textContent = I18n.t("copiedMsg", "Komut panoya kopyalandı.");
        if (labelEl) labelEl.textContent = I18n.t("copiedShort", "Kopyalandı");
        showToast(I18n.t("copiedMsg", "Komut panoya kopyalandı."));
        setTimeout(() => {
          copyMsg.textContent = "";
          if (labelEl) labelEl.textContent = I18n.t("copyCmdBtn", "Komutu Kopyala");
        }, 2500);
      },
      () => {
        copyMsg.textContent = I18n.t("copyFailMsg", "Kopyalanamadı — komutu elle seçin.");
      }
    );
  });

  copyExtIdBtn.addEventListener("click", () => {
    copyText(
      extId,
      () => {
        copyExtIdBtn.textContent = I18n.t("copiedShort", "Kopyalandı");
        showToast(I18n.t("toastIdCopied", "Uzantı kimliği kopyalandı"));
        setTimeout(() => {
          copyExtIdBtn.textContent = I18n.t("copyIdBtn", "ID Kopyala");
        }, 2000);
      },
      () => {
        copyMsg.textContent = I18n.t("copyFailMsg", "Kopyalanamadı — komutu elle seçin.");
      }
    );
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
      trustedErr.textContent = I18n.t("errInvalidDomain", "Geçerli bir alan adı girin (örn: sirketim.com.tr).");
      trustedInput.focus();
      return;
    }
    const list = (currentSettings.trustedDomains || []).slice();
    if (!list.includes(dom)) list.push(dom);
    trustedInput.value = "";
    saveSettings({ trustedDomains: list }, I18n.t("toastDomainAdded", "Alan adı güvenilenlere eklendi"));
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
      brandErr.textContent = I18n.t("errBrandNameRequired", "Marka adı boş bırakılamaz.");
      brandLabel.focus();
      return;
    }
    if (!DOMAIN_RE.test(dom)) {
      brandErr.textContent = I18n.t("errBrandDomainInvalid", "Geçerli bir resmi alan adı girin (örn: sirketim.com).");
      brandDomain.focus();
      return;
    }
    if (em && !EMAIL_RE.test(em)) {
      brandErr.textContent = I18n.t("errBrandEmailInvalid", "Resmi e-posta adresi geçersiz görünüyor.");
      brandEmail.focus();
      return;
    }
    const list = (currentSettings.customBrands || []).slice();
    list.push({ label: lbl, domains: [dom], emails: em ? [em] : [] });
    brandLabel.value = "";
    brandDomain.value = "";
    brandEmail.value = "";
    saveSettings({ customBrands: list }, I18n.t("toastBrandAdded", "Özel marka eklendi"));
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
  builtinSearchClear.addEventListener("click", () => {
    builtinSearch.value = "";
    renderBuiltinCatalog();
    builtinSearch.focus();
  });

  historyFilterBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      historyFilter = btn.dataset.historyFilter || "all";
      historyFilterBtns.forEach((b) => b.classList.toggle("is-active", b === btn));
      renderAlertsList(currentState.recentAlerts);
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
    showToast(I18n.t("toastExported", "Geçmiş JSON olarak indirildi"));
  });

  clearBtn.addEventListener("click", () => {
    clearConfirmBar.classList.add("show");
  });

  clearNoBtn.addEventListener("click", () => {
    clearConfirmBar.classList.remove("show");
  });

  clearYesBtn.addEventListener("click", () => {
    clearConfirmBar.classList.remove("show");
    chrome.runtime.sendMessage({ type: "CLEAR_HISTORY" }, () => {
      render();
      showToast(I18n.t("toastCleared", "Tüm istatistik ve geçmiş temizlendi"), "warn");
    });
  });

  chrome.runtime.sendMessage({ type: "GET_VERIFIED_BRANDS" }, (res) => {
    if (chrome.runtime.lastError || !res || !Array.isArray(res.brands)) return;
    builtinBrands = res.brands;
    renderBuiltinCatalog();
  });

  render();
  chrome.runtime.sendMessage({ type: "GET_FULL_STATE" }, (st) => {
    if (!chrome.runtime.lastError && st && st.settings && st.settings.nativeBridgeEnabled === true) {
      testNativeConnection(false);
    }
  });
});
