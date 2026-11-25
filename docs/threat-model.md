# Tehdit Modeli ve OWASP ASVS / Top 10 Eşleştirmesi

> **Not:** Bu tehdit modeli uygulanabilir derinlemesine savunma kontrollerini belgeler; hiçbir yazılım mutlak güvenlik garantisi veremez. Canlı dağıtımlar ağ segmentasyonu, TLS sonlandırma, merkezi audit sink ve düzenli yama yönetimi gerektirir.

## 1. Varlıklar (Assets)
1. Azure Key Vault secret değerleri (en yüksek gizlilik)
2. Azure Service Principal kimlik bilgileri (`AZURE_CLIENT_SECRET`, Entra access token)
3. Secret metadata'sı (isimler, tag'ler, contentType — hassas bilgi içerebilir)
4. Uygulama oturum çerezleri, local bootstrap token, OIDC client secret
5. Audit kayıtlarının bütünlüğü ve gizliliği

## 2. Güven Sınırları (Trust Boundaries)
- **TB-1:** Tarayıcı ↔ Spring Boot (Same-Origin HTTP/HTTPS)
- **TB-2:** Reverse Proxy / Ingress ↔ Spring Boot (Server profili, yalnızca trusted proxy)
- **TB-3:** Spring Boot ↔ Entra ID / Azure ARM / Azure Key Vault (HTTPS, doğrulanmış Azure endpoint)
- **TB-4:** İşletim Sistemi / Container ↔ Secret Kaynağı (Mounted file / ENV / K8s Secret)

## 3. Tehditler, OWASP Eşleştirmesi ve Kontroller

| ID | Tehdit | OWASP Top 10 / ASVS | Uygulanan Kontrol | Doğrulama Yöntemi |
|---|---|---|---|---|
| T01 | Secret değerlerinin log, hata yanıtı, tarayıcı storage veya cache'e sızması | A02 / ASVS V6, V8 | Metadata-only Caffeine cache; `Cache-Control: no-store`; SDK HTTP body logging kapalı; RFC 9457 safe ProblemDetail; Frontend'de localStorage/sessionStorage/IndexedDB/SW/toast/URL kullanımı yasak; 30 sn auto-clear | Canary secret leak testleri (backend + Playwright) |
| T02 | Yetkisiz kullanıcı veya yanlış vault erişimi (IDOR / Broken Access Control) | A01 / ASVS V4 | Her endpoint'te backend RBAC + vault scope kontrolü; opaque vault ID; discovery filtreleme; async operation ID'lerde owner+vault kontrolü; deny-by-default | RBAC matris testleri, cross-vault IDOR testleri |
| T03 | CSRF ve Cross-Origin istekleri | A01, A05 / ASVS V4.2 | Spring Security CSRF (cookie/header token), CORS tamamen kapalı, strict `Origin`/`Referer` kontrolü, `SameSite=Strict` (local) / `Lax` (server OIDC) | CSRF reddi ve cross-origin engelleme testleri |
| T04 | DNS Rebinding (Local profilde tarayıcı üzerinden localhost erişimi) | A05 / ASVS V14 | Strict `Host` header allowlist (`localhost`, `127.0.0.1`, `[::1]`) ve `Origin` doğrulaması | DNS rebinding Host header testleri |
| T05 | SSRF ve Credential Yönlendirme (Arbitrary URL / Redirect) | A10 / ASVS V12.6 | Serbest URL yok; yalnızca ARM discovery veya admin statik config; HTTPS + `.vault.azure.net` + port 443 doğrulaması; HTTP redirect üzerinden credential sızması engelli | SSRF & URL validation unit testleri |
| T06 | Local Bootstrap Token ele geçirme / tekrar kullanma / sızdırma | A07 / ASVS V2, V3 | 256-bit SecureRandom token, tek kullanımlık tüketim, kısa TTL (varsayılan 10 dk), sabit zamanlı karşılaştırma, brute-force rate limit, URL/log yasağı, session fixation'a karşı session ID rotation, 15 dk idle timeout | Bootstrap replay, expiry, rate limit, session fixation testleri |
| T07 | Server OIDC yanlış yapılandırması veya local profile sessiz düşüş | A05, A07 / ASVS V14 | Fail-closed startup doğrulayıcı: eksik OIDC issuer/client/secret veya eksik `APP_ALLOWED_VAULT_IDS` durumunda uygulama başlamaz; local fallback yok; trusted proxy sınırı | Server fail-closed startup testleri |
| T08 | XSS ve Clickjacking | A03 / ASVS V5.3, V14.4 | Angular strict template escaping, `Content-Security-Policy` (`default-src 'self'; frame-ancestors 'none'; object-src 'none'`), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` | Güvenlik header ve XSS encoding testleri |
| T09 | Yanlışlıkla kalıcı silme (Purge) veya toplu yıkım | A04 / ASVS V1 | Purge endpoint/UI/SDK çağrısı yok; soft-delete varsayılan kapalı (`APP_DELETE_ENABLED=false`), `ADMIN` + tam isim yazarak onay + üretim ortam etiketi zorunlu | Feature flag, RBAC ve UI onay testleri |
| T10 | Azure 401/403 hatalarının kullanıcı login hatasıyla karışması | A09 / ASVS V7 | RFC 9457 `errorCode` ayrımı (`AUTH_REQUIRED` vs `AZURE_CREDENTIAL_INVALID` vs `AZURE_PERMISSION_DENIED`); raw Azure hata gövdesi ve stack trace dönülmez | WireMock Azure 401/403/404/429/5xx testleri |
| T11 | DoS / Rate limit / Büyük payload / Heap dump sızıntısı | A05, A06 / ASVS V13, V14 | Request size limitleri, rate limit filtresi, bounded cache ve timeout'lar, Actuator yalnızca `/actuator/health` (detaysız); `env`, `configprops`, `heapdump`, `beans` tamamen kapalı | Actuator kapalı uç testleri, rate limit ve 25KB+ payload testleri |
| T12 | Audit izlenebilirlik eksikliği (Azure yalnızca SP'yi görür) | A09 / ASVS V7.2 | Uygulama düzeyinde kullanıcı subject + vault + secret name + action + outcome + correlation ID içeren Elasticsearch uyumlu structured JSON audit logları (başarısız/reddedilmiş işlemler dahil) | Audit log doğrulama ve canary yokluğu testleri |

## 4. Bilinen Kısıtlar ve Varsayımlar
- Java `String` ve JavaScript `string` immutable/GC yapıları nedeniyle bellekten anında sıfırlama garanti edilemez (best-effort minimizasyon uygulanır).
- Azure Key Vault `setSecret` işlemi upsert olduğundan create ve update ön kontrolleri harici yazıcılara karşı atomik CAS değildir; uygulama içi kilit yalnızca aynı JVM örneği içindeki eşzamanlı istekleri serileştirir.
- Çoklu replica (HA) için dağıtık session store ve merkezi audit altyapısı MVP kapsamı dışındadır; Helm chart tek replica (`replicas: 1`) zorlar.
- Clipboard temizliği tarayıcı güvenlik politikaları gereği otomatik garanti edilmez; kopyalama yalnızca açık kullanıcı tıklamasıyla yapılır.
