/**
 * ElfSec Next.js istemcisi — bağımlılık yok (Node 18+ global fetch yeterli).
 *
 * Bunu neden yazdım: sitemden ElfSec API'ye her seferinde elle fetch
 * yazmak yerine tek dosyalık bir sarmalayıcı olsun istedim. Token ve
 * limit işleri burada, skor işi ElfSec tarafında.
 *
 * GÜVENLİK (oku, önemli):
 *  - Bu dosyayı SADECE sunucu tarafında kullan (API Route / Server Action).
 *    Token'ı asla `NEXT_PUBLIC_` ile başlayan değişkene koyma — tarayıcıya
 *    gömülür, herkes görür. Token yalnız `process.env.ELFSEC_API_TOKEN`'da durur.
 *  - Tarayıcı ElfSec'e direkt bağlanmaz: Tarayıcı -> senin Next.js route'un
 *    -> ElfSec API (localhost ya da iç ağ). Token hiç dışarı çıkmaz.
 *
 * Kurulum:
 *  1. Bu dosyayı Next.js projene kopyala, örn: `lib/elfsec.js`
 *  2. `.env.local` dosyasına yaz (repoya EKLEME):
 *       ELFSEC_API_URL=http://127.0.0.1:8765
 *       ELFSEC_API_TOKEN=uzun-rastgele-deger
 *  3. Örnek route için `route-example.js` dosyasına bak.
 *
 * Kullanım:
 *  import { createElfSecClient } from "../lib/elfsec.js";
 *  const elfsec = createElfSecClient();
 *  const rapor = await elfsec.analyze({ subject, sender, body });
 *  // rapor -> { ok, risk_level: "LOW|MEDIUM|HIGH|CRITICAL", risk_score, reasons, ... }
 */

// Sunucu tarafıyla aynı sınırlar (app/serve.py): fazla veri yollanmaz.
const MAX_SUBJECT = 1000;
const MAX_SENDER = 500;
const MAX_BODY = 30000;

/** API hatası: `err.status` ile dal kur (401/429/413/500). */
export class ElfSecError extends Error {
  /** @param {number} status HTTP kodu */
  constructor(status, message) {
    super(message);
    this.name = "ElfSecError";
    this.status = status;
  }
}

/**
 * İstemci kur.
 * @param {object} [opts]
 * @param {string} [opts.baseUrl] ElfSec adresi (varsayılan: env ya da localhost)
 * @param {string} [opts.token] Bearer token (varsayılan: env; BOŞSA localhost'ta çalışır)
 * @param {number} [opts.timeoutMs] istek zaman aşımı (varsayılan 15000)
 */
export function createElfSecClient(opts = {}) {
  const baseUrl = (opts.baseUrl ?? process.env.ELFSEC_API_URL ?? "http://127.0.0.1:8765").replace(/\/$/, "");
  const token = opts.token ?? process.env.ELFSEC_API_TOKEN ?? "";
  const timeoutMs = opts.timeoutMs ?? 15000;

  /** Düşük seviye çağrı: timeout + hata eşleme burada. */
  async function call(path, payload) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const res = await fetch(baseUrl + path, {
        method: payload === undefined ? "GET" : "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: payload === undefined ? undefined : JSON.stringify(payload),
        signal: ctrl.signal,
      });
      let data = null;
      try {
        data = await res.json();
      } catch {
        throw new ElfSecError(res.status, `ElfSec yanıtı JSON değil (HTTP ${res.status})`);
      }
      if (!res.ok || data?.ok === false) {
        // 401 = token yanlış/eksik, 429 = hız sınırı (Retry-After'a bak),
        // 413 = gövde çok büyük, 500 = iç hata.
        throw new ElfSecError(res.status, data?.error ?? `ElfSec hatası (HTTP ${res.status})`);
      }
      return data;
    } catch (e) {
      if (e?.name === "AbortError") throw new ElfSecError(504, `ElfSec zaman aşımı (${timeoutMs}ms)`);
      if (e instanceof ElfSecError) throw e;
      // Bağlantı yoksa: ElfSec çalışmıyor demektir (serve başlatılmamış).
      throw new ElfSecError(503, `ElfSec'e ulaşılamadı: ${e?.message ?? e}`);
    } finally {
      clearTimeout(timer);
    }
  }

  const clip = (v, n) => String(v ?? "").slice(0, n);

  return {
    /** Sunucu ayakta mı? -> { ok, version, engine } */
    health() {
      return call("/v1/health");
    },

    /**
     * Tek maili skorla.
     * @param {object} mail
     * @param {string} [mail.subject] konu (<=1000)
     * @param {string} [mail.sender] gönderici (<=500)
     * @param {string} [mail.body] gövde HTML ya da düz metin (<=30000, fazlası kırpılır)
     * @param {Record<string,string>} [mail.headers] başlıklar (en fazla 20)
     */
    analyze({ subject = "", sender = "", body = "", headers } = {}) {
      return call("/v1/analyze", {
        subject: clip(subject, MAX_SUBJECT),
        sender: clip(sender, MAX_SENDER),
        body: clip(body, MAX_BODY),
        ...(headers ? { headers } : {}),
      });
    },

    /** Sadece temizle (skor yok): -> { safe_html, plain_text, urls } */
    sanitize(body = "") {
      return call("/v1/sanitize", { body: clip(body, MAX_BODY) });
    },
  };
}
