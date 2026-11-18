# AegisNexus bağımsız keşif sistemi

ViewSrc entegrasyonu önerisi kullanıcının kararıyla kaldırıldı. Uygulama, veritabanı, işçi ve inceleme ekranı AegisNexus içindedir. ViewSrc kodu değiştirilmedi.

## Çalıştırma

```sh
./run.sh --crawler
```

Konsol: http://127.0.0.1:8010. İlk açılışta keşif kapalıdır. Adres ekleyip **Keşfi başlat** düğmesine basın. Kapatmak için Ctrl+C. Sonraki açılışlarda kaydedilen açık/kapalı ayarı korunur. `--port 8011` alternatif port; `--no-build` mevcut keşif derlemesini kullanır.

Python sanal ortamı ve Node/npm gerekir; ilk kurulum bağımlılıkları indirmek için internet kullanır. Keşif API anahtarı, ücretli servis, LLM, Redis veya ViewSrc gerektirmez. Canlı sayfaları ve kaynakları toplamak internet gerektirir; HTML içe aktarma ağsızdır.

Yerel konsol yalnızca loopback adresinde açılır; uzaktan erişim için tasarlanmamıştır. Bağlı uygulamada `/crawler` yönetici ekranıdır; API yönetici yetkisi ister. Bağlı kurulumda `alembic upgrade head` uygulanmalı, Celery beat ve phishing kuyruğunu tüketen worker çalışmalıdır. Yerel konsol aynı Alembic migration'larıyla şemayı günceller ve kendi işçisini çalıştırır.

## Akış

1. Tam URL ekleyin veya HTML kaynak kodunu içe aktarın. Yol ve sorgu URL kimliğinde korunur; sorgu değerleri ekranda gizlenir.
2. Kaynaklar sekmesinde herkese açık satır başına URL listesi veya `name_value` alanı içeren CT JSON listesi eklenebilir. Açık keşifte saatlik, tur başına en fazla 5 kaynak ve kaynak başına 100 aday alınır. Hazır kaynak ekli değildir.
   - **CertStream (canlı CT akışı):** `certstream` türünde tek bir kaynak eklenebilir. Sabit, ücretsiz genel uç nokta (`wss://certstream.calidog.io`, `AEGIS_CERTSTREAM_URL` ile değiştirilebilir) dinlenir; API anahtarı gerektirmez. Yeni yayımlanan TLS sertifikalarının alan adları süzgeçten geçirilir (marka adı, typosquat benzerliği, anahtar sözcük, riskli uzantı, punycode) ve yalnızca eşleşenler aday olur. Dinleyici hiçbir sayfayı ziyaret etmez; ziyaret/skor/onay mevcut işçi akışındadır. Firehose üç katmanda frenlenir: süzgeç eşiği (`AEGIS_CERTSTREAM_THRESHOLD`, varsayılan 40), dakika başına alım tavanı (`AEGIS_CERTSTREAM_RATE`, varsayılan 20) ve mevcut günlük/kuyruk sınırları. Eşleşme phishing kanıtı değildir.
3. İşçi sayfa, yönlendirme ve robots.txt denetimi yapar; form alanlarını, marka/alan uyumunu, script hash'lerini, tracker ve favicon izlerini çıkarır. Aynı host üzerinde iki seviyeye kadar bağlantı takip eder; bir başlangıç için toplam beş sayfa sınırı vardır.
4. İsteğe bağlı Chromium, ön puanı en az 35 olan sayfalarda DOM ve ekran görüntüsü toplar. Form göndermez; POST, indirme ve WebSocket trafiği engellenir. Tarayıcı başarısızsa statik gözlem korunur.
5. Açıklanabilir risk puanı ve analiz kapsamı inceleme kuyruğuna gelir. Puan kalibre edilmiş phishing yüzdesi değildir; mevcut sinyal grupları toplamda 80 puana kadar çıkar. Düşük puan güvenli olduğunun garantisi değildir.
6. Yalnızca insan onayı doğrulanmış tehdit kaydı oluşturur. Son 48 saatte başarılı, tam ve canlı gözlem gerekir. Arşiv HTML'i doğrudan onaylanamaz. Geri çekme yalnızca bu crawler'ın yayımladığı kaydı siler; bağımsız kaynak kayıtları korunur.
7. Keşif açıkken 24 saatten eski onaylar geri çekilip yeniden taramaya alınır; yeni insan kararı gerekir. Keşif duraklatıldığında bu zamanlanmış kontroller de durur. Elle yeniden tarama da önce eski yayını geri çeker.

## Sınırlar ve ağ koruması

Varsayılan günlük aday taraması 1.000, tarayıcı bütçesi 100; panelden değiştirilebilir. Kaynak okuma ve robots/favicon/alt kaynak istekleri aday sayısına dahil değildir. Bekleyen kuyruk en fazla 10.000 aday, kaynak listesi en fazla 20 kayıttır. Başarısız işler en fazla üç kez denenir; kota beklemesi deneme hakkını tüketmez. İş sahipliği süreli kilitle korunur; eski işçi yeni sonucu ezemez.

HTML en fazla 1 MB, robots 128 KB, favicon 128 KB; yönlendirme zinciri sınırlıdır. Aynı host için tek sayfa işi ve işler arasında en az iki saniye ara vardır. Bu ara her alt kaynağa uygulanmaz; bu nedenle pozitif `Crawl-delay` isteyen siteler taranmaz. Robots hatalarında erişim varsayılmaz. Kaynak beslemeleri operatörün açıkça verdiği veri uç noktalarıdır; robots sayfa politikası bu uç noktalara uygulanmaz.

Özel ağ/IP, metadata uç noktaları, URL kullanıcı bilgisi ve standart dışı portlar reddedilir. DNS sonucu bağlantıya sabitlenir; her yönlendirme tekrar denetlenir. HTTPS'ten HTTP'ye düşüş engellenir. Hariç tutulan alanlar alt alanlarıyla birlikte aday, kaynak yönlendirmesi ve tarayıcı aşamalarında kontrol edilir. Tarayıcı 40 saniyelik ayrı süreçte çalışır; istek sayısı ve içerik boyutu sınırlıdır. Bu süreç ayrı işletim sistemi/container izolasyonu veya bellek kotası değildir.

## Veriler ve yapılandırma

- SQLite varsayılanı: `data/aegis.db`; yerel başlatıcı için `AEGIS_DATABASE_URL` ile değiştirilebilir.
- HTML ve ekran görüntüleri: `data/crawler`; `CRAWLER_DATA_DIR` ile değiştirilebilir. Ham HTML web ekranında çalıştırılmaz veya sunulmaz.
- `crawl_candidates`, `crawl_observations`, `crawl_reviews`, `crawl_sources`, `crawl_settings`: aday, gözlem, karar, kaynak ve ayarlar.
- `AEGIS_CHROMIUM_PATH`: kurulu Chromium çalıştırılabilir dosyasının yolu. Ayarlanmazsa Playwright'ın kurulu Chromium'u kullanılır. Tarayıcı aşaması varsayılan kapalıdır.
- Adayların kendi bulguları tehdit beslemesine otomatik geri verilmez. Eski genel feed dönüştürücüsü de yeni girdileri aday olarak işler; geçmişte yanlış sınıflanmış kayıtlar otomatik silinmez.

HTML ve görüntüler diskte tutulur; otomatik saklama süresi/temizleme henüz yoktur. Disk kullanımını izleyin ve veri dizinini erişimi sınırlı tutun. Ham URL ve kaynak HTML hassas içerik barındırabilir; sorgu maskelemesi bir veri anonimleştirme garantisi değildir.

## Kapsam

Bu sürüm başlangıç adresleri, kullanıcı tanımlı kaynaklar, sınırlı bağlantı keşfi ve isteğe bağlı CertStream (canlı CT akışı) ile kendi verisini toplar. Küresel internet keşfi, Common Crawl indeks taraması, öğrenilmiş phishing-kit sınıflandırıcısı veya kalibre edilmiş olasılık modeli içermez. CertStream süzgeci kural tabanlıdır; genel public CertStream sunucusu ara sıra kesilebilir (dinleyici artan beklemeyle yeniden bağlanır) ve istikrar için ileride kendi `certstream-server-go` örneği bağlanabilir. Bağlı kurulumda dinleyici `scripts/run_certstream.py` ile ayrı bir servis olarak çalıştırılır; yerel konsolda supervisor otomatik başlatır. Marka listesi ve kurallar sınırlıdır; meşru harici giriş formları yanlış pozitif üretebilir. İlişkili gözlemler içerik/script/tracker/favicon benzerliğidir; aynı saldırgan veya phishing kanıtı değildir.

Testler dış ağ kapalıyken özel IP/yönlendirme, eşzamanlı iş sahipliği, eski sonuç, aday/doğrulanmış ayrımı, canlı/arşiv onayı, kaynak dışlama, bütçe, yeniden tarama ve yerel konsol erişim denetimlerini sınar. Gerçek sitelerde doğruluk ve ölçek ölçümü ayrıca yapılmalıdır.
