# ElfSec Browser Extension — Privacy Policy / Gizlilik Politikası

**Last updated / Son güncelleme:** 2026-11-24 (v1.6.0)

## English

1. **Zero Data Collection & Zero Cloud:** ElfSec processes opened webmail content, selected links, and downloaded file metadata **100% locally** inside your browser and (when optionally connected) via your local desktop `elfsec.exe` Native Messaging Host (`com.elfsec.guard`).
2. **No External Servers / No Telemetry:** The extension makes **zero** network requests to any third-party server, API, LLM, or analytics service. The optional desktop CLI's shortened-URL expansion is **off by default**; when a user explicitly enables it, it validates targets and refuses localhost/private-network addresses.
3. **Local Storage Only:** Your preferences (protection toggles, trusted domains, custom verified brands), scan counters, and recent alert summaries are stored exclusively in `chrome.storage.local` on your device and can be exported or cleared anytime from the Options page.
4. **Local Alert Log (Optional Native Host):** When the optional `elfsec.exe` Native Host is connected, only HIGH/CRITICAL findings (subject, sender, matched domain/URL, score) are appended to a rotating local JSONL log under ElfSec's data directory (max 2 MB, then rotated). This log never leaves the device and is used by the desktop tray/service to show notifications.
5. **No Sale or Sharing of Data:** ElfSec never collects, transmits, sells, or shares user data with anyone.

## Türkçe

1. **Sıfır Veri Toplama & Sıfır Bulut:** ElfSec açılan webmail içeriğini, seçili bağlantıları ve indirilen dosya üstverisini **%100 yerelde** tarayıcınız içinde veya (isteğe bağlı kuruluysa) masaüstünüzdeki yerel `elfsec.exe` Native Messaging Host (`com.elfsec.guard`) üzerinden inceler.
2. **Dış Sunucu / Telemetri Yok:** Eklenti hiçbir üçüncü taraf sunucuya, API'ye, yapay zeka servisine veya analiz aracına ağ isteği göndermez. Masaüstü CLI'deki kısaltılmış URL genişletme **varsayılan olarak kapalıdır**; kullanıcı açarsa hedefler doğrulanır ve localhost/özel ağ adreslerine istek atılmaz.
3. **Yalnızca Yerel Depolama:** Ayarlarınız (kalkan anahtarları, güvenilen alan adları, özel markalar), sayaçlar ve son alarm özetleri yalnızca cihazınızdaki `chrome.storage.local` içinde saklanır; Ayarlar sayfasından tek tıkla dışa aktarılabilir veya silinebilir.
4. **Yerel Alarm Günlüğü (İsteğe Bağlı Native Host):** İsteğe bağlı `elfsec.exe` Native Host bağlıysa yalnızca HIGH/CRITICAL bulgular (konu, gönderici, eşleşen alan adı/URL, skor) ElfSec veri dizinindeki döngüsel yerel JSONL günlüğüne eklenir (en fazla 2 MB, sonra döndürülür). Bu günlük cihazdan dışarı çıkmaz; masaüstü tepsi/servis bildirimleri için kullanılır.
5. **Veri Paylaşımı Yok:** Kullanıcı verileri kesinlikle toplanmaz, aktarılmaz ve satılmaz.
