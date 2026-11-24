/* ElfSec Tarayıcı Yedek Güvenlik Motoru (Native Host bağlı değilken 100% çevrimdışı çalışır). */
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
  var RISKY_EXT = [".exe", ".zip", ".rar", ".scr", ".js", ".vbs", ".bat", ".ps1", ".msi", ".jar", ".iso", ".lnk"];
  var DOC_EXT = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt"];

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

  function levelFromScore(score) {
    if (score < 25) return "LOW";
    if (score < 50) return "MEDIUM";
    if (score < 75) return "HIGH";
    return "CRITICAL";
  }

  function analyzeEmail(payload) {
    var subject = String((payload && payload.subject) || "");
    var sender = String((payload && payload.sender) || "");
    var body = String((payload && payload.body) || "");
    var blob = subject + "\n" + body;
    var low = blob.toLowerCase();

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

    var sm = sender.match(/@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/);
    var dom = sm ? sm[1].toLowerCase() : "";
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

  var api = {
    analyzeEmail: analyzeEmail,
    analyzeText: analyzeText,
    extractUrls: extractUrls,
    checkUrl: checkUrl
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  } else {
    root.ElfSecFallback = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : this);
