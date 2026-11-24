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
    "paypal", "apple", "microsoft", "netflix", "vodafone", "turkcell", "e-devlet", "edevlet",
    "ptt", "kargo", "trendyol", "hepsiburada", "amazon"
  ];
  var EXEC_EXT = [".exe", ".msi", ".scr", ".com", ".pif", ".cpl", ".dll", ".iso", ".img", ".jar"];
  var SCRIPT_EXT = [".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".reg", ".lnk"];
  var MACRO_EXT = [".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm"];
  var ARCHIVE_EXT = [".zip", ".rar", ".7z"];
  var RISKY_EXT = EXEC_EXT.concat(SCRIPT_EXT).concat(ARCHIVE_EXT);
  var DOC_EXT = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt"];

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
      domains: ["microsoft.com", "accountprotection.microsoft.com", "email.microsoft.com", "communication.microsoft.com"],
      emails: ["account-security-noreply@accountprotection.microsoft.com", "msa@communication.microsoft.com", "noreply@microsoft.com"]
    },
    { id: "paypal", label: "PayPal", aliases: ["paypal"], domains: ["paypal.com", "mail.paypal.com"], emails: ["service@paypal.com", "paypal@mail.paypal.com"] },
    { id: "amazon", label: "Amazon", aliases: ["amazon", "amazon prime"], domains: ["amazon.com", "amazon.com.tr"], emails: ["no-reply@amazon.com", "auto-confirm@amazon.com"] },
    { id: "netflix", label: "Netflix", aliases: ["netflix"], domains: ["netflix.com", "mailer.netflix.com", "account.netflix.com"], emails: ["info@account.netflix.com"] },
    { id: "meta", label: "Meta / Instagram", aliases: ["instagram", "facebook", "whatsapp", "meta"], domains: ["mail.instagram.com", "facebookmail.com", "whatsapp.com", "meta.com"], emails: ["security@mail.instagram.com", "security@facebookmail.com"] },
    { id: "github", label: "GitHub", aliases: ["github"], domains: ["github.com"], emails: ["noreply@github.com"] },
    { id: "steam", label: "Steam", aliases: ["steam", "steampowered"], domains: ["steampowered.com"], emails: ["noreply@steampowered.com"] },
    { id: "discord", label: "Discord", aliases: ["discord"], domains: ["discord.com", "discordapp.com"], emails: ["noreply@discord.com"] },
    { id: "edevlet", label: "e-Devlet", aliases: ["e-devlet", "edevlet", "turkiye.gov"], domains: ["turkiye.gov.tr"], emails: ["bilgilendirme@turkiye.gov.tr"] },
    { id: "garanti", label: "Garanti BBVA", aliases: ["garanti", "garanti bbva"], domains: ["garanti.com.tr", "garantibbva.com.tr"], emails: ["bilgilendirme@garantibbva.com.tr"] },
    { id: "akbank", label: "Akbank", aliases: ["akbank"], domains: ["akbank.com"], emails: ["bilgilendirme@akbank.com"] },
    { id: "ziraat", label: "Ziraat Bankası", aliases: ["ziraat", "ziraat bank"], domains: ["ziraatbank.com.tr"], emails: ["bilgilendirme@ziraatbank.com.tr"] },
    { id: "isbank", label: "İş Bankası", aliases: ["isbank", "işbank", "iş bankası", "is bankasi"], domains: ["isbank.com.tr"], emails: ["bilgilendirme@isbank.com.tr"] },
    { id: "yapikredi", label: "Yapı Kredi", aliases: ["yapikredi", "yapıkredi", "yapı kredi"], domains: ["yapikredi.com.tr"], emails: ["bilgilendirme@yapikredi.com.tr"] },
    { id: "ptt", label: "PTT", aliases: ["ptt", "ptt kargo"], domains: ["ptt.gov.tr", "pttavm.com"], emails: ["bilgi@ptt.gov.tr"] },
    { id: "trendyol", label: "Trendyol", aliases: ["trendyol"], domains: ["trendyol.com", "mail.trendyol.com"], emails: ["no-reply@trendyol.com"] },
    { id: "hepsiburada", label: "Hepsiburada", aliases: ["hepsiburada"], domains: ["hepsiburada.com"], emails: ["no-reply@hepsiburada.com"] }
  ];

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

  function checkUrl(url) {
    var ul = String(url || "").toLowerCase();
    var host = getHost(url);
    if (SHORTENERS.some(function (s) { return ul.indexOf(s) !== -1; })) {
      return { pts: 15, reason: "Kısaltılmış URL (gerçek adres gizli): " + url };
    }
    if (host.indexOf("xn--") === 0 || host.indexOf(".xn--") !== -1) {
      return { pts: 25, reason: "Homoglif/IDN sahteciliği (punycode): " + url };
    }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      return { pts: 25, reason: "IP adresine giden link: " + url };
    }
    if (SUSPICIOUS_TLDS.some(function (t) { return host.endsWith(t); })) {
      return { pts: 20, reason: "Şüpheli TLD içeren URL: " + url };
    }
    if (ul.indexOf("@") !== -1) {
      return { pts: 15, reason: "Aldatıcı yapıda URL (@ işareti): " + url };
    }
    if (RISKY_EXT.some(function (ext) { return ul.replace(/\/+$/, "").endsWith(ext); })) {
      return { pts: 20, reason: "Çalıştırılabilir/arşiv dosyasına link: " + url };
    }
    if (hasMixedScript(host)) {
      return { pts: 25, reason: "Karışık alfabe sahteciliği (homoglif): " + url };
    }
    if (/(login|signin|verify|account|update|secure|banking)/i.test(ul)) {
      return { pts: 8, reason: "Kimlik-avı anahtar kelimeli URL: " + url };
    }
    return { pts: 0, reason: "" };
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
      var res = checkUrl(u);
      if (res.pts > 0 && susUrls.indexOf(u) === -1) {
        score += res.pts;
        susUrls.push(u);
        reasons.push(res.reason);
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
      phishing_detected: phishing,
      prompt_injection_detected: promptInj,
      sender_verification: sv,
      recommended_action: score >= 50
        ? "Bağlantılara tıklamayın, ekleri açmayın, göndericiyi resmi kanaldan doğrulayın."
        : "Şüpheli bir durum yok, normal dikkat yeterli."
    };
  }

  function analyzeText(text) {
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
    var rep = analyzeEmail({ subject: "", sender: "", body: raw });
    var score = rep.risk_score + (clickfix ? 40 : 0);
    var reasons = rep.reasons.filter(function (r) {
      return r !== "Bilinen oltalama / injection kalıbı eşleşmedi.";
    });
    if (clickfix) {
      reasons.unshift("ClickFix / zararlı komut kopyalama tuzağı tespit edildi.");
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
    extractUrls: extractUrls,
    checkUrl: checkUrl
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  } else {
    root.ElfSecFallback = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : this);
