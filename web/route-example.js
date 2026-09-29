/**
 * Örnek Next.js API Route (App Router) — kopyala: `app/api/scan/route.js`
 *
 * Akış: Tarayıcı -> BURASI (token burada, güvende) -> ElfSec API -> skor.
 * Tarayıcı ElfSec'e direkt dokunmaz, token tarayıcıya hiç gitmez.
 *
 * Girdi:  POST { subject, sender, body }
 * Çıktı:  { risk_level, risk_score, reasons, phishing, advice }
 *          + risk_level'e göre HTTP kodu: LOW/MEDIUM=200, HIGH+=200 ama
 *            `blocked: true` bayrağıyla (formu durdurmak senin işin).
 */

import { createElfSecClient, ElfSecError } from "../lib/elfsec.js";

const elfsec = createElfSecClient(); // env: ELFSEC_API_URL + ELFSEC_API_TOKEN

export async function POST(req) {
  let input;
  try {
    input = await req.json();
  } catch {
    return Response.json({ error: "geçersiz JSON" }, { status: 400 });
  }

  // Kaba doğrulama: boş/form-dışı istek ElfSec'e gitmesin.
  const body = String(input?.body ?? "");
  if (!body.trim() || body.length > 30000) {
    return Response.json({ error: "body boş ya da çok büyük (max 30000)" }, { status: 400 });
  }

  try {
    const r = await elfsec.analyze({
      subject: String(input?.subject ?? ""),
      sender: String(input?.sender ?? ""),
      body,
    });
    return Response.json({
      risk_level: r.risk_level,
      risk_score: r.risk_score,
      reasons: r.reasons ?? [],
      phishing: !!r.phishing_detected,
      prompt_injection: !!r.prompt_injection_detected,
      advice: r.recommendation ?? "",
      // Sitenin iş mantığı örneği: HIGH+ ise formu engelle.
      blocked: r.risk_level === "HIGH" || r.risk_level === "CRITICAL",
    });
  } catch (e) {
    if (e instanceof ElfSecError) {
      // ElfSec kapalıysa site ölmesin: 503 + kullanıcıya düzgün mesaj.
      const code = e.status === 401 || e.status === 429 ? 503 : 502;
      return Response.json({ error: "tarama şu an yapılamıyor, sonra tekrar deneyin" }, { status: code });
    }
    return Response.json({ error: "beklenmeyen hata" }, { status: 500 });
  }
}
