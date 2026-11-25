/* ElfSec Tarayıcı Yedek Güvenlik Motoru (%100 yerel, ağ/API yok). */
(function (root) {
  "use strict";

  var PHISHING_PATTERNS = [
    /acil.*(hesabınız|hesabiniz|kapanacak|doğrula|dogrula)/i,
    /(hesabınız|hesabiniz|şifreniz|sifreniz).*(askıya|askiya|kilitlendi|kapanacak|donduruldu)/i,
    /hemen (tıkla|tikla|doğrula|dogrula|giriş yap|giris yap)/i,
    /verify your account/i,
    /urgent.*(suspend|verify|click|action required)/i,
    /password.*expir/i,
    /fatura.*ödenmedi/i,
    /kargonuz.*(teslim edilemedi|bekliyor|ücret)/i,
    /e-devlet.*(ceza|borç|borc|doğrulama)/i
  ];

  var PROMPT_INJECTION_PATTERNS = [
    /ignore (all |prior |previous )?instructions/i,
    /disregard .*instructions/i,
    /system prompt/i,
    /reveal .*prompt/i,
    /önceki talimatları (yoksay|unut)/i,
    /talimatları görmezden gel/i
  ];

  var URGENCY_PATTERNS = [
    /\b(acil|hemen|derhal|son gün|24 saat|48 saat|hemen şimdi)\b/i,
    /\b(urgent|immediately|act now|last chance|expires today)\b/i
  ];

  var CREDENTIAL_WORDS = /(şifre|sifre|password|iban|kart (numara|bilgi)|otp|sms kodu|doğrulama kodu|dogrulama kodu|t\.?c\.? (kimlik|no)|cvv)/i;
  var ACTION_WORDS = /(gönder|gonder|paylaş|paylas|ilet|gir|tıkla|tikla|onayla|güncelle|guncelle)/i;

  var CLICKFIX_PATTERNS = [
    /powershell(?:\.exe)?\b[^\n]*(?:-enc\b|-encodedcommand\b|-w\s+h(?:idden)?|-ep\s+bypass|\biex\b|downloadstring|invoke-webrequest|\birm\b)/i,
    /\bmshta(?:\.exe)?\s+(?:https?:\/\/|javascript:|vbscript:)/i,
    /\bcmd(?:\.exe)?\s+\/[ck]\s+[^\n]*(?:curl|powershell|mshta|certutil|bitsadmin)/i,
    /\bcertutil(?:\.exe)?\b[^\n]*-urlcache[^\n]*https?:\/\//i,
    /\b(?:curl|wget)(?:\.exe)?\s+https?:\/\/[^\n]*\|\s*(?:sh|bash|powershell|cmd)/i
  ];

  var SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz", ".sbs", ".quest"];
  var SHORTENERS = ["bit.ly", "tinyurl", "t.co", "goo.gl", "is.gd", "cutt.ly", "rebrand.ly", "shorturl"];
  var FREEMAIL = ["gmail.com", "hotmail.com", "outlook.com", "yahoo.com", "yandex.com", "proton.me", "icloud.com", "live.com"];
  var BRAND_WORDS = [
    "banka", "bank", "garanti", "akbank", "ziraat", "isbank", "işbank", "yapikredi", "yapıkredi",
    "paypal", "apple", "microsoft", "netflix", "vodafone", "turkcell", "türk telekom", "turk telekom",
    "e-devlet", "edevlet", "ptt", "kargo", "trendyol", "hepsiburada", "amazon"
  ];
  var EXEC_EXT = [".exe", ".msi", ".scr", ".com", ".pif", ".cpl", ".dll", ".iso", ".img", ".jar"];
  var SCRIPT_EXT = [".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".reg", ".lnk"];
  var MACRO_EXT = [".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm"];
  var ARCHIVE_EXT = [".zip", ".rar", ".7z"];
  var RISKY_EXT = EXEC_EXT.concat(SCRIPT_EXT).concat(ARCHIVE_EXT);
  var DOC_EXT = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt"];

  /* Resmi devlet, belediye, eğitim uzantıları (en uzun son-ek önce) */
  var OFFICIAL_TLD_RULES = [
    { suffix: ".gov.tr", category: "OFFICIAL_GOV", label: "T.C. Resmi Devlet Kurumu (.gov.tr)" },
    { suffix: ".bel.tr", category: "OFFICIAL_GOV", label: "T.C. Belediye Kurumu (.bel.tr)" },
    { suffix: ".pol.tr", category: "OFFICIAL_GOV", label: "T.C. Emniyet Genel Müdürlüğü (.pol.tr)" },
    { suffix: ".tsk.tr", category: "OFFICIAL_GOV", label: "Türk Silahlı Kuvvetleri (.tsk.tr)" },
    { suffix: ".kep.tr", category: "OFFICIAL_GOV", label: "Kayıtlı Elektronik Posta (.kep.tr)" },
    { suffix: ".edu.tr", category: "OFFICIAL_EDU", label: "T.C. Yükseköğretim Kurumu (.edu.tr)" },
    { suffix: ".k12.tr", category: "OFFICIAL_EDU", label: "T.C. Millî Eğitim Kurumu (.k12.tr)" },
    { suffix: ".gov.uk", category: "OFFICIAL_GOV", label: "Resmi Kamu Kurumu (.gov.uk)" },
    { suffix: ".gov.au", category: "OFFICIAL_GOV", label: "Resmi Kamu Kurumu (.gov.au)" },
    { suffix: ".gc.ca", category: "OFFICIAL_GOV", label: "Resmi Kamu Kurumu (.gc.ca)" },
    { suffix: ".gouv.fr", category: "OFFICIAL_GOV", label: "Resmi Kamu Kurumu (.gouv.fr)" },
    { suffix: ".europa.eu", category: "OFFICIAL_GOV", label: "Avrupa Birliği Kurumu (.europa.eu)" },
    { suffix: ".gov", category: "OFFICIAL_GOV", label: "Resmi Devlet Kurumu (.gov)" }
  ];

  /* Herkesin bildiği resmi kuruluş ve teknoloji alan adları */
  var KNOWN_OFFICIAL_DOMAINS = [
    { domain: "github.com", label: "GitHub" },
    { domain: "gitlab.com", label: "GitLab" },
    { domain: "bitbucket.org", label: "Bitbucket" },
    { domain: "stackoverflow.com", label: "Stack Overflow" },
    { domain: "npmjs.com", label: "npm" },
    { domain: "pypi.org", label: "PyPI" },
    { domain: "mozilla.org", label: "Mozilla" },
    { domain: "wikipedia.org", label: "Wikipedia" },
    { domain: "wikimedia.org", label: "Wikimedia" },
    { domain: "cloudflare.com", label: "Cloudflare" },
    { domain: "openai.com", label: "OpenAI" },
    { domain: "anthropic.com", label: "Anthropic" },
    { domain: "linkedin.com", label: "LinkedIn" },
    { domain: "x.com", label: "X" },
    { domain: "twitter.com", label: "Twitter / X" },
    { domain: "zoom.us", label: "Zoom" },
    { domain: "slack.com", label: "Slack" },
    { domain: "adobe.com", label: "Adobe" },
    { domain: "nvidia.com", label: "NVIDIA" },
    { domain: "spotify.com", label: "Spotify" },
    { domain: "byeco.com.tr", label: "byeco" },
    { domain: "turkishairlines.com", label: "Türk Hava Yolları" },
    { domain: "thy.com", label: "Türk Hava Yolları" },
    { domain: "flypgs.com", label: "Pegasus" },
    { domain: "sahibinden.com", label: "sahibinden.com" },
    { domain: "n11.com", label: "n11" },
    { domain: "migros.com.tr", label: "Migros" },
    { domain: "getir.com", label: "Getir" },
    { domain: "yemeksepeti.com", label: "Yemeksepeti" },
    { domain: "halkbank.com.tr", label: "Halkbank" },
    { domain: "vakifbank.com.tr", label: "VakıfBank" },
    { domain: "qnbfinansbank.com", label: "QNB" },
    { domain: "qnb.com.tr", label: "QNB" },
    { domain: "denizbank.com", label: "DenizBank" },
    { domain: "enpara.com", label: "Enpara.com" },
    { domain: "ing.com.tr", label: "ING Türkiye" },
    { domain: "teb.com.tr", label: "TEB" }
  ];

  /* Kullanıcı içerikli / barındırma alt alan adları asla doğrulanmış resmi kurum sayılmaz */
  var USER_CONTENT_HOSTS = [
    "github.io",
    "githubusercontent.com",
    "sites.google.com",
    "docs.google.com",
    "drive.google.com",
    "forms.gle",
    "storage.googleapis.com",
    "onedrive.live.com",
    "sharepoint.com",
    "web.app",
    "firebaseapp.com",
    "pages.dev",
    "vercel.app",
    "netlify.app",
    "workers.dev",
    "blogspot.com",
    "wordpress.com",
    "wixsite.com",
    "weebly.com"
  ];

  /* backend/app/verified_senders.py ile senkronize 22 resmi marka */
  var VERIFIED_BRANDS = [
    {
      id: "apple", label: "Apple",
      aliases: ["apple", "apple id", "icloud", "app store", "itunes"],
      domains: ["apple.com", "email.apple.com", "id.apple.com", "insideicloud.icloud.com", "icloud.com"],
      emails: ["no_reply@email.apple.com", "noreply@email.apple.com", "appleid@id.apple.com", "do_not_reply@apple.com", "noreply@insideicloud.icloud.com", "apple_support@apple.com"]
    },
    {
      id: "google", label: "Google",
      aliases: ["google", "gmail", "google play", "youtube"],
      domains: ["google.com", "accounts.google.com", "youtube.com"],
      emails: ["no-reply@accounts.google.com", "security-noreply@google.com", "noreply@google.com"]
    },
    {
      id: "microsoft", label: "Microsoft",
      aliases: ["microsoft", "outlook", "office 365", "onedrive", "xbox"],
      domains: ["microsoft.com", "accountprotection.microsoft.com", "email.microsoft.com", "mail.support.microsoft.com", "communication.microsoft.com"],
      emails: ["account-security-noreply@accountprotection.microsoft.com", "msa@communication.microsoft.com", "noreply@microsoft.com"]
    },
    {
      id: "paypal", label: "PayPal",
      aliases: ["paypal"],
      domains: ["paypal.com", "mail.paypal.com"],
      emails: ["service@paypal.com", "paypal@mail.paypal.com"]
    },
    {
      id: "amazon", label: "Amazon",
      aliases: ["amazon", "amazon prime"],
      domains: ["amazon.com", "amazon.com.tr"],
      emails: ["no-reply@amazon.com", "auto-confirm@amazon.com", "siparis-guncelleme@amazon.com.tr"]
    },
    {
      id: "netflix", label: "Netflix",
      aliases: ["netflix"],
      domains: ["netflix.com", "mailer.netflix.com", "account.netflix.com"],
      emails: ["info@account.netflix.com", "info@mailer.netflix.com"]
    },
    {
      id: "meta", label: "Meta / Instagram",
      aliases: ["instagram", "facebook", "whatsapp", "meta"],
      domains: ["mail.instagram.com", "facebookmail.com", "whatsapp.com", "meta.com"],
      emails: ["security@mail.instagram.com", "security@facebookmail.com", "no-reply@mail.instagram.com"]
    },
    {
      id: "github", label: "GitHub",
      aliases: ["github"],
      domains: ["github.com"],
      emails: ["noreply@github.com"]
    },
    {
      id: "steam", label: "Steam",
      aliases: ["steam", "steampowered"],
      domains: ["steampowered.com"],
      emails: ["noreply@steampowered.com"]
    },
    {
      id: "discord", label: "Discord",
      aliases: ["discord"],
      domains: ["discord.com", "discordapp.com"],
      emails: ["noreply@discord.com"]
    },
    {
      id: "edevlet", label: "e-Devlet",
      aliases: ["e-devlet", "edevlet", "turkiye.gov"],
      domains: ["turkiye.gov.tr"],
      emails: ["bilgilendirme@turkiye.gov.tr", "noreply@turkiye.gov.tr"]
    },
    {
      id: "garanti", label: "Garanti BBVA",
      aliases: ["garanti", "garanti bbva"],
      domains: ["garanti.com.tr", "garantibbva.com.tr"],
      emails: ["bilgilendirme@garantibbva.com.tr", "noreply@garantibbva.com.tr"]
    },
    {
      id: "akbank", label: "Akbank",
      aliases: ["akbank"],
      domains: ["akbank.com"],
      emails: ["bilgilendirme@akbank.com", "noreply@akbank.com"]
    },
    {
      id: "ziraat", label: "Ziraat Bankası",
      aliases: ["ziraat", "ziraat bank", "ziraat bankası", "ziraat bankasi"],
      domains: ["ziraatbank.com.tr"],
      emails: ["bilgilendirme@ziraatbank.com.tr", "noreply@ziraatbank.com.tr"]
    },
    {
      id: "isbank", label: "İş Bankası",
      aliases: ["işbank", "isbank", "iş bankası", "is bankasi"],
      domains: ["isbank.com.tr"],
      emails: ["bilgilendirme@isbank.com.tr", "noreply@isbank.com.tr"]
    },
    {
      id: "yapikredi", label: "Yapı Kredi",
      aliases: ["yapıkredi", "yapikredi", "yapı kredi", "yapi kredi"],
      domains: ["yapikredi.com.tr"],
      emails: ["bilgilendirme@yapikredi.com.tr", "noreply@yapikredi.com.tr"]
    },
    {
      id: "ptt", label: "PTT",
      aliases: ["ptt", "ptt kargo"],
      domains: ["ptt.gov.tr", "pttavm.com"],
      emails: ["bilgi@ptt.gov.tr", "noreply@ptt.gov.tr"]
    },
    {
      id: "trendyol", label: "Trendyol",
      aliases: ["trendyol"],
      domains: ["trendyol.com", "mail.trendyol.com"],
      emails: ["no-reply@trendyol.com", "bilgi@mail.trendyol.com"]
    },
    {
      id: "hepsiburada", label: "Hepsiburada",
      aliases: ["hepsiburada"],
      domains: ["hepsiburada.com"],
      emails: ["no-reply@hepsiburada.com", "bilgi@hepsiburada.com"]
    },
    {
      id: "turkcell", label: "Turkcell",
      aliases: ["turkcell"],
      domains: ["turkcell.com.tr"],
      emails: ["bilgilendirme@turkcell.com.tr"]
    },
    {
      id: "turktelekom", label: "Türk Telekom",
      aliases: ["türk telekom", "turk telekom", "turktelekom"],
      domains: ["turktelekom.com.tr"],
      emails: ["bilgilendirme@turktelekom.com.tr"]
    },
    {
      id: "vodafone", label: "Vodafone",
      aliases: ["vodafone"],
      domains: ["vodafone.com.tr"],
      emails: ["bilgilendirme@vodafone.com.tr"]
    }
  ];

  function getVerifiedBrands() {
    return VERIFIED_BRANDS.map(function (b) {
      return {
        id: b.id,
        label: b.label,
        aliases: b.aliases.slice(),
        domains: b.domains.slice(),
        emails: b.emails.slice()
      };
    });
  }

  function extractUrls(text) {
    var re = /https?:\/\/[^\s<>'"]+/gi;
    var found = [];
    var m;
    while ((m = re.exec(text || "")) !== null) {
      var u = m[0].replace(/[.,;)\]}!]+$/, "");
      if (found.indexOf(u) === -1) {
        found.push(u);
      }
      if (found.length >= 100) break;
    }
    return found;
  }

  function getHost(url) {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch (_e) {
      return "";
    }
  }

  function hasMixedScript(host) {
    if (!host) return false;
    var hasLatin = /[a-z]/i.test(host);
    var hasNonLatin = /[\u0400-\u04ff\u0370-\u03ff]/.test(host);
    return hasLatin && hasNonLatin;
  }

  function matchOfficialTld(dom) {
    var d = String(dom || "").toLowerCase().replace(/\.$/, "");
    if (!d) return null;
    for (var i = 0; i < OFFICIAL_TLD_RULES.length; i++) {
      var rule = OFFICIAL_TLD_RULES[i];
      if (d.endsWith(rule.suffix) && d.length > rule.suffix.length) {
        return rule;
      }
    }
    return null;
  }

  function verifyDomain(host, options) {
    var opts = options || {};
    var d = String(host || "").toLowerCase().trim().replace(/\.$/, "");
    var empty = { verified: false, category: "", label: "", detail: "" };
    if (!d || d.indexOf(".") === -1) return empty;
    if (d.indexOf("xn--") === 0 || d.indexOf(".xn--") !== -1) return empty;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(d) || hasMixedScript(d)) return empty;
    if (domainMatches(d, USER_CONTENT_HOSTS)) return empty;

    if (Array.isArray(opts.trustedDomains) && domainMatches(d, opts.trustedDomains)) {
      return {
        verified: true,
        category: "TRUSTED_USER",
        label: d,
        detail: "Kullanıcı güvenilen alan adı: " + d
      };
    }

    var customList = Array.isArray(opts.customBrands) ? opts.customBrands : [];
    for (var i = 0; i < customList.length; i++) {
      var cb = customList[i];
      if (cb && cb.label && Array.isArray(cb.domains) && domainMatches(d, cb.domains)) {
        return {
          verified: true,
          category: "VERIFIED_ORG",
          label: String(cb.label),
          detail: "Özel doğrulanmış kurum: " + cb.label + " (" + d + ")"
        };
      }
    }

    for (var j = 0; j < VERIFIED_BRANDS.length; j++) {
      var b = VERIFIED_BRANDS[j];
      if (domainMatches(d, b.domains)) {
        return {
          verified: true,
          category: "VERIFIED_ORG",
          label: b.label,
          detail: "Doğrulanmış resmi kuruluş: " + b.label + " (" + d + ")"
        };
      }
    }

    for (var k = 0; k < KNOWN_OFFICIAL_DOMAINS.length; k++) {
      var kd = KNOWN_OFFICIAL_DOMAINS[k];
      if (d === kd.domain || d.endsWith("." + kd.domain)) {
        return {
          verified: true,
          category: "VERIFIED_ORG",
          label: kd.label,
          detail: "Doğrulanmış resmi kuruluş: " + kd.label + " (" + d + ")"
        };
      }
    }

    var tldRule = matchOfficialTld(d);
    if (tldRule) {
      return {
        verified: true,
        category: tldRule.category,
        label: tldRule.label,
        detail: tldRule.label + " (" + d + ")"
      };
    }

    return empty;
  }

  function verifyUrl(url, options) {
    var raw = String(url || "").trim();
    var empty = { verified: false, category: "", label: "", detail: "", url: raw, host: "" };
    if (!raw) return empty;
    var parsed;
    try {
      parsed = new URL(raw);
    } catch (_e) {
      return empty;
    }
    if (parsed.protocol !== "https:") return empty;
    if (parsed.username || parsed.password || raw.indexOf("@") !== -1) return empty;
    var host = (parsed.hostname || "").toLowerCase().replace(/\.$/, "");
    if (!host) return empty;
    var ul = raw.toLowerCase();
    if (SHORTENERS.some(function (s) { return ul.indexOf(s) !== -1; })) return empty;
    var pathLow = (parsed.pathname || "").toLowerCase().replace(/\/+$/, "");
    if (RISKY_EXT.some(function (ext) { return pathLow.endsWith(ext) || ul.replace(/\/+$/, "").endsWith(ext); })) {
      return empty;
    }
    var res = verifyDomain(host, options);
    if (!res.verified) {
      return { verified: false, category: "", label: "", detail: "", url: raw, host: host };
    }
    return {
      verified: true,
      category: res.category,
      label: res.label,
      detail: res.detail,
      url: raw,
      host: host
    };
  }

  function checkUrl(url, options) {
    var ul = String(url || "").toLowerCase();
    var host = getHost(url);
    if (SHORTENERS.some(function (s) { return ul.indexOf(s) !== -1; })) {
      return { pts: 15, reason: "Kısaltılmış URL (gerçek adres gizli): " + url, verified: false };
    }
    if (host.indexOf("xn--") === 0 || host.indexOf(".xn--") !== -1) {
      return { pts: 25, reason: "Homoglif/IDN sahteciliği (punycode): " + url, verified: false };
    }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      return { pts: 25, reason: "IP adresine giden link: " + url, verified: false };
    }
    if (SUSPICIOUS_TLDS.some(function (t) { return host.endsWith(t); })) {
      return { pts: 20, reason: "Şüpheli TLD içeren URL: " + url, verified: false };
    }
    if (ul.indexOf("@") !== -1) {
      return { pts: 15, reason: "Aldatıcı yapıda URL (@ işareti): " + url, verified: false };
    }
    if (RISKY_EXT.some(function (ext) { return ul.replace(/\/+$/, "").endsWith(ext); })) {
      return { pts: 20, reason: "Çalıştırılabilir/arşiv dosyasına link: " + url, verified: false };
    }
    if (hasMixedScript(host)) {
      return { pts: 25, reason: "Karışık alfabe sahteciliği (homoglif): " + url, verified: false };
    }
    var v = verifyUrl(url, options);
    if (v.verified) {
      return {
        pts: 0,
        reason: "",
        verified: true,
        verifiedLabel: v.label,
        verifiedCategory: v.category,
        verifiedDetail: v.detail
      };
    }
    if (/(login|signin|verify|account|update|secure|banking)/i.test(ul)) {
      return { pts: 8, reason: "Kimlik-avı anahtar kelimeli URL: " + url, verified: false };
    }
    return { pts: 0, reason: "", verified: false };
  }

  function domainMatches(dom, officialList) {
    if (!dom) return false;
    return (officialList || []).some(function (od) {
      var o = String(od || "").toLowerCase().trim();
      return o && (dom === o || dom.endsWith("." + o));
    });
  }

  function verifySender(sender, subject, customBrands) {
    var raw = String(sender || "");
    var m = raw.match(/([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})/);
    var addr = m ? m[1].toLowerCase() : "";
    var dom = addr.indexOf("@") !== -1 ? addr.split("@")[1] : "";
    var disp = m ? (raw.slice(0, m.index) + raw.slice(m.index + m[0].length)).toLowerCase() : raw.toLowerCase();
    var subj = String(subject || "").toLowerCase();

    var allBrands = VERIFIED_BRANDS.slice();
    if (Array.isArray(customBrands)) {
      customBrands.forEach(function (cb) {
        if (cb && cb.label && Array.isArray(cb.domains) && cb.domains.length) {
          allBrands.unshift({
            id: String(cb.id || cb.label).toLowerCase(),
            label: String(cb.label),
            aliases: Array.isArray(cb.aliases) && cb.aliases.length ? cb.aliases.map(function (a) { return String(a).toLowerCase(); }) : [String(cb.label).toLowerCase()],
            domains: cb.domains.map(function (d) { return String(d).toLowerCase().trim(); }),
            emails: Array.isArray(cb.emails) ? cb.emails.map(function (e) { return String(e).toLowerCase().trim(); }) : []
          });
        }
      });
    }

    for (var i = 0; i < allBrands.length; i++) {
      var b = allBrands[i];
      var exact = addr && b.emails.indexOf(addr) !== -1;
      if (exact || domainMatches(dom, b.domains)) {
        return {
          status: "VERIFIED_DOMAIN",
          brand: b.label,
          matched_address: addr,
          exact_official_address: exact,
          detail: "Bilinen resmi '" + b.label + "' adresi/alan adı eşleşti (" + (addr || dom) + ")."
        };
      }
    }

    if (dom) {
      for (var j = 0; j < allBrands.length; j++) {
        var b2 = allBrands[j];
        var claimed = b2.aliases.some(function (a) {
          var compact = a.replace(/\s+/g, "");
          return disp.indexOf(a) !== -1 || subj.indexOf(a) !== -1 || (compact.length >= 4 && dom.indexOf(compact) !== -1);
        });
        if (claimed) {
          return {
            status: "IMPERSONATION",
            brand: b2.label,
            matched_address: addr,
            exact_official_address: false,
            detail: "Doğrulanmamış marka göndericisi: '" + b2.label + "' adına geliyor ancak resmi alan adı (" + b2.domains[0] + ") değil (" + dom + ")!"
          };
        }
      }
      var tldRule = matchOfficialTld(dom);
      if (tldRule) {
        return {
          status: "VERIFIED_DOMAIN",
          brand: tldRule.label,
          matched_address: addr,
          exact_official_address: false,
          detail: "Resmi kurum alan adı eşleşti (" + dom + ")."
        };
      }
    }
    return { status: "UNKNOWN", brand: "", matched_address: addr, exact_official_address: false, detail: "" };
  }

  function levelFromScore(score) {
    if (score < 25) return "LOW";
    if (score < 50) return "MEDIUM";
    if (score < 75) return "HIGH";
    return "CRITICAL";
  }

  function analyzeEmail(payload, options) {
    var opts = options || {};
    var subject = String((payload && payload.subject) || "");
    var sender = String((payload && payload.sender) || "");
    var body = String((payload && payload.body) || "");
    var blob = subject + "\n" + body;
    var low = blob.toLowerCase();

    var sm = sender.match(/@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/);
    var dom = sm ? sm[1].toLowerCase() : "";

    if (Array.isArray(opts.trustedDomains) && dom && domainMatches(dom, opts.trustedDomains)) {
      return {
        ok: true,
        source: "browser_fallback",
        engine: "elfsec-browser-fallback/1.0",
        risk_score: 0,
        risk_level: "LOW",
        summary: "Güvenilen alan adı listesinde (" + dom + ").",
        reasons: ["Kullanıcı güvenilen alan adı izin listesi eşleşti."],
        suspicious_urls: [],
        phishing_detected: false,
        prompt_injection_detected: false,
        sender_verification: {
          status: "VERIFIED_DOMAIN",
          brand: dom,
          matched_address: sender,
          exact_official_address: false,
          detail: "Kullanıcı tarafından güvenilen alan adı: " + dom
        },
        recommended_action: "Güvenilen gönderici."
      };
    }

    var score = 0;
    var reasons = [];
    var susUrls = [];
    var verifiedUrls = [];
    var phishing = false;
    var promptInj = false;

    for (var i = 0; i < PHISHING_PATTERNS.length; i++) {
      if (PHISHING_PATTERNS[i].test(low)) {
        score += 25;
        reasons.push("Oltalama kalıbı: aciliyet + hesap/kapanma/doğrulama baskısı.");
        phishing = true;
        break;
      }
    }

    for (var j = 0; j < PROMPT_INJECTION_PATTERNS.length; j++) {
      if (PROMPT_INJECTION_PATTERNS[j].test(low)) {
        score += 30;
        reasons.push("Prompt injection: gizli talimat enjeksiyonu.");
        promptInj = true;
        break;
      }
    }

    if (URGENCY_PATTERNS.some(function (p) { return p.test(low); })) {
      score += 10;
      reasons.push("Aciliyet baskısı dili.");
    }

    if (CREDENTIAL_WORDS.test(low) && ACTION_WORDS.test(low)) {
      score += 15;
      reasons.push("Hassas bilgi talebi (şifre/IBAN/OTP) + aksiyon isteği.");
      phishing = true;
    }

    var urls = Array.isArray(payload && payload.urls) ? payload.urls.slice() : [];
    extractUrls(blob).forEach(function (u) {
      if (urls.indexOf(u) === -1) urls.push(u);
    });
    urls.slice(0, 100).forEach(function (u) {
      var res = checkUrl(u, opts);
      if (res.pts > 0 && susUrls.indexOf(u) === -1) {
        score += res.pts;
        susUrls.push(u);
        reasons.push(res.reason);
      } else if (res.verified && !verifiedUrls.some(function (x) { return x.url === u; })) {
        verifiedUrls.push({
          url: u,
          host: getHost(u),
          label: res.verifiedLabel,
          category: res.verifiedCategory,
          detail: res.verifiedDetail
        });
      }
    });

    if (dom && FREEMAIL.indexOf(dom) !== -1) {
      var head = low.slice(0, 500) + " " + sender.toLowerCase();
      if (BRAND_WORDS.some(function (b) { return head.indexOf(b) !== -1; })) {
        score += 25;
        reasons.push("Gönderici taklidi: kurumsal kimlik + bedava posta (" + dom + ").");
        phishing = true;
      }
    }

    var attachments = Array.isArray(payload && payload.attachments) ? payload.attachments : [];
    attachments.forEach(function (att) {
      var fn = String((att && att.filename) || att || "").toLowerCase();
      if (!fn) return;
      var parts = fn.split(".");
      if (parts.length >= 3 &&
          RISKY_EXT.indexOf("." + parts[parts.length - 1]) !== -1 &&
          DOC_EXT.indexOf("." + parts[parts.length - 2]) !== -1) {
        score += 25;
        reasons.push("Çift uzantı tuzağı: " + fn);
      } else if (MACRO_EXT.some(function (e) { return fn.endsWith(e); })) {
        score += 15;
        reasons.push("Makrolu Office eki: " + fn);
      } else if (RISKY_EXT.some(function (e) { return fn.endsWith(e); })) {
        score += 20;
        reasons.push("Riskli ek: " + fn);
      }
    });

    var sv = verifySender(sender, subject, opts.customBrands);
    if (sv.status === "IMPERSONATION") {
      score += 30;
      reasons.push(sv.detail);
      phishing = true;
    } else if (sv.status === "VERIFIED_DOMAIN" && susUrls.length === 0 && !promptInj && score > 0) {
      score = Math.max(0, score - (sv.exact_official_address ? 20 : 10));
    }

    score = Math.max(0, Math.min(100, score));
    var level = levelFromScore(score);
    return {
      ok: true,
      source: "browser_fallback",
      engine: "elfsec-browser-fallback/1.0",
      risk_score: score,
      risk_level: level,
      summary: reasons.length
        ? "Tarayıcı yedek analizi: " + reasons.length + " bulgu, skor " + score + "/100."
        : "Belirgin tehdit kalıbı bulunamadı.",
      reasons: reasons.length ? reasons : ["Bilinen oltalama / injection kalıbı eşleşmedi."],
      suspicious_urls: susUrls,
      verified_urls: verifiedUrls,
      phishing_detected: phishing,
      prompt_injection_detected: promptInj,
      sender_verification: sv,
      recommended_action: score >= 50
        ? "Bağlantılara tıklamayın, ekleri açmayın, göndericiyi resmi kanaldan doğrulayın."
        : "Şüpheli bir durum yok, normal dikkat yeterli."
    };
  }

  function analyzeText(text, options) {
    var raw = String(text || "").trim();
    if (!raw) {
      return {
        ok: true,
        risk_score: 0,
        risk_level: "LOW",
        clickfix_detected: false,
        reasons: ["İncelenecek metin yok."],
        suspicious_urls: [],
        engine: "elfsec-browser-fallback/1.0"
      };
    }
    var clickfix = CLICKFIX_PATTERNS.some(function (p) { return p.test(raw); });
    var rep = analyzeEmail({ subject: "", sender: "", body: raw }, options);
    var score = rep.risk_score + (clickfix ? 40 : 0);
    var reasons = rep.reasons.filter(function (r) {
      return r !== "Bilinen oltalama / injection kalıbı eşleşmedi.";
    });
    if (clickfix) {
      reasons.unshift("ClickFix / zararlı komut kopyalama tuzağı tespit edildi.");
    }
    var verifiedUrls = Array.isArray(rep.verified_urls) ? rep.verified_urls : [];
    if (score === 0 && verifiedUrls.length > 0) {
      reasons.unshift("Doğrulanmış resmi bağlantı: " + verifiedUrls[0].label + " (" + verifiedUrls[0].host + ")");
    }
    score = Math.max(0, Math.min(100, score));
    return {
      ok: true,
      source: "browser_fallback",
      engine: "elfsec-browser-fallback/1.0",
      risk_score: score,
      risk_level: levelFromScore(score),
      clickfix_detected: clickfix,
      phishing_detected: rep.phishing_detected || rep.suspicious_urls.length > 0,
      reasons: reasons.length ? reasons : ["Bilinen ClickFix veya phishing kalıbı eşleşmedi."],
      suspicious_urls: rep.suspicious_urls,
      verified_urls: verifiedUrls,
      summary: "Tarayıcı analizi: skor " + score + "/100."
    };
  }

  function analyzeDownload(item) {
    var rawName = String((item && item.filename) || "");
    var baseName = rawName.split(/[\\/]/).pop() || rawName;
    var low = baseName.toLowerCase();
    var url = String((item && item.url) || "");

    var score = 0;
    var reasons = [];
    var susUrls = [];

    if (/[\u202e\u202d\u2066-\u2069]/.test(baseName)) {
      score += 35;
      reasons.push("Unicode RLO dosya adı sahteciliği: " + baseName);
    }

    var parts = low.split(".");
    var lastExt = parts.length >= 2 ? "." + parts[parts.length - 1] : "";
    var prevExt = parts.length >= 3 ? "." + parts[parts.length - 2] : "";
    if (parts.length >= 3 && (EXEC_EXT.indexOf(lastExt) !== -1 || SCRIPT_EXT.indexOf(lastExt) !== -1) && DOC_EXT.indexOf(prevExt) !== -1) {
      score += 45;
      reasons.push("Çift uzantı tuzağı (" + prevExt + lastExt + "): " + baseName);
    } else if (SCRIPT_EXT.indexOf(lastExt) !== -1) {
      score += 35;
      reasons.push("Riskli betik/kısayol indirmesi (" + lastExt + "): " + baseName);
    } else if (EXEC_EXT.indexOf(lastExt) !== -1) {
      score += 25;
      reasons.push("Çalıştırılabilir/disk kalıbı indirmesi (" + lastExt + "): " + baseName);
    } else if (MACRO_EXT.indexOf(lastExt) !== -1) {
      score += 20;
      reasons.push("Makrolu Office belgesi (" + lastExt + "): " + baseName);
    } else if (ARCHIVE_EXT.indexOf(lastExt) !== -1) {
      score += 8;
      reasons.push("Arşiv dosyası (" + lastExt + ") — açmadan taratın.");
    }

    if (url) {
      var ures = checkUrl(url);
      if (ures.pts > 0) {
        score += ures.pts;
        susUrls.push(url);
        reasons.push("İndirme kaynağı şüpheli: " + ures.reason);
      }
    }

    score = Math.max(0, Math.min(100, score));
    return {
      ok: true,
      source: "browser_download",
      engine: "elfsec-browser-fallback/1.0",
      filename: baseName,
      url: url,
      risk_score: score,
      risk_level: levelFromScore(score),
      reasons: reasons.length ? reasons : ["İndirilen dosya uzantısı ve kaynağı temiz görünüyor."],
      suspicious_urls: susUrls,
      summary: reasons.length ? "İndirme analizi: " + reasons[0] : "Temiz indirme."
    };
  }

  var api = {
    analyzeEmail: analyzeEmail,
    analyzeText: analyzeText,
    analyzeDownload: analyzeDownload,
    verifySender: verifySender,
    verifyDomain: verifyDomain,
    verifyUrl: verifyUrl,
    getVerifiedBrands: getVerifiedBrands,
    extractUrls: extractUrls,
    checkUrl: checkUrl
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  } else {
    root.ElfSecFallback = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : this);
