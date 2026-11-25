# ADR-001: Azure Key Vault Manager Mimari Karar Kayıtları

Tarih: 2026-11-25  
Durum: Kabul Edildi

## ADR-001.1 — Tek Origin Executable JAR (Spring Boot 3.5 + Angular 21)
- **Karar:** Angular 21 production çıktısı Gradle derlemesi ile `backend/src/main/resources/static/` içine kopyalanır ve tek executable JAR içinde sunulur.
- **Gerekçe:** CORS tamamen kapalı tutulur, same-origin CSRF ve `SameSite=Strict` (local) / `SameSite=Lax` (OIDC redirect uyumlu server) cookie politikaları ek reverse proxy karmaşıklığı olmadan uygulanır.
- **Kısıt:** SPA fallback controller yalnızca `/api/**` ve `/actuator/**` dışındaki GET isteklerini `index.html`'e yönlendirir; `/api/**` 404 yanıtları asla SPA HTML olarak dönmez.

## ADR-001.2 — Azure Service Principal Kimliği ve Credential Factory
- **Karar:** MVP'de yalnızca `ClientSecretCredentialBuilder` (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` veya `AZURE_CLIENT_SECRET_FILE`) kullanılır. `AzureCliCredential`, `DefaultAzureCredential` veya otomatik zincirleme fallback yasaktır.
- **Tasarım:** `AzureCredentialFactory` arayüzü gelecekte Workload Identity / Managed Identity sağlayıcılarının eklenmesine olanak tanır ancak MVP'de tek deterministik sağlayıcı aktiftir. Hem `AZURE_CLIENT_SECRET` hem `AZURE_CLIENT_SECRET_FILE` birlikte verilirse uygulama fail-closed olarak başlamaz.
- **Bulut Varsayımı:** MVP Azure Public Cloud (`https://*.vault.azure.net`, `AzureEnvironment.AZURE`) hedefler; sovereign cloud uçları otomatik varsayılmaz.

## ADR-001.3 — Opaque Vault ID ve SSRF Savunması
- **Karar:** API katmanında kullanıcıdan serbest vault URL'si alınmaz. Her keşfedilen (ARM) veya statik yapılandırılan (data-plane-only) vault için backend kararlı, URL-safe opaque kimlik (SHA-256 tabanlı kısaltılmış ID) üretir.
- **Doğrulama:** `AzureVaultUrlValidator` her vault URI'si için HTTPS, beklenen Azure public cloud DNS suffix (`.vault.azure.net`), standart 443 port (veya varsayılan HTTPS portu), kullanıcı bilgisi/path/query olmaması ve güvenilir discovery/config kaydı eşleşmesini doğrular. HTTP istemcisi redirect takip ederek başka hosta bearer token göndermez.

## ADR-001.4 — Uygulama Kimlik Doğrulaması ve Deny-by-Default RBAC
- **Karar:** Azure service principal uygulamanın kimliğidir; son kullanıcı yetkilendirmesi uygulama içinde ayrıca zorlanır.
- **Local Profil:** Varsayılan `127.0.0.1:8765` bind, tek kullanımlık 256-bit yüksek entropili bootstrap token (kısa ömürlü, yalnızca stdout operatör kanalına tek seferlik gösterilir, log dosyasına/URL query'ye yazılmaz), oturum açılışında session ID rotation, `HttpOnly`, `SameSite=Strict`, 15 dk idle timeout. Dış ağ erişimi reddedilir (container local modu için açık `APP_LOCAL_ALLOW_CONTAINER_BIND=true` istisnası gerekir ve host `127.0.0.1:8765` publish edilir).
- **Server Profil:** Spring Security OAuth2 Login / OIDC (Ory Hydra uyumlu), HTTPS + `Secure` cookie, doğrulanmış `iss` ve `sub`, zorunlu `APP_ALLOWED_VAULT_IDS` ve açık kullanıcı/grup → vault → rol (`VIEWER`, `OPERATOR`, `MANAGER`, `ADMIN`) eşleşmesi. Eksik yapılandırmada startup başarısız olur; local profiline fallback yapılmaz.
- **Yetkilendirme:** Her REST endpoint ve async operation ID sorgusu backend'de kullanıcı + vault kapsamı ile doğrulanır. Eşleşmeyen kullanıcı hiçbir vault'a erişemez (deny-by-default).

## ADR-001.5 — Progressive Multi-Page Metadata Pagination ve Caffeine Cache
- **Karar:** `SecretClient.listPropertiesOfSecrets()` çağrısı arka planda tüm continuation page'leri otomatik dolaşır (`iterableByPage()`), hiçbir zaman `getSecret` (value) çağırmaz. Her sayfa tamamlandığında atomik olarak yeni immutable snapshot yayımlanır.
- **Cache Anahtarı:** `(tenantId, vaultId, credentialContextId)`. Yalnızca metadata saklanır; bounded size (varsayılan max 200 vault snapshot) ve varsayılan 5 dk TTL (`APP_METADATA_TTL`).
- **Yarış Önleme:** Aynı vault için eşzamanlı refresh istekleri tek uçuşta birleştirilir (coalescing). Her mutasyon ve yeni refresh artan `generationId` üretir; eski bir in-flight refresh daha yeni bir snapshot/generation'ı ezemez.
- **Hata/Stale Semantiği:** İlk sayfa sonrası hata oluşursa `PARTIAL_ERROR`, tamamen başarısız olursa `ERROR` durumu döner; önceki başarılı snapshot varsa `stale=true` olarak açık uyarıyla gösterilir.

## ADR-001.6 — CRUD, Non-Atomic Yarış Koşulları ve Purge Yasağı
- **Create:** Azure ad kuralları (`^[0-9a-zA-Z-]{1,127}$`) ve UTF-8 byte sınırı (resmi Azure Key Vault sınırı: 25 KB = 25.600 byte; `contentType` <= 255 karakter) doğrulanır; value trim edilmez. Uygulama içi `(vaultId, secretName)` kilidi altında aktif ve soft-deleted ad kontrolü yapılır. Azure `setSecret` upsert olduğundan bu kontrol harici yazıcılara karşı atomik değildir; bu sınır dokümante edilir ve UI'da belirtilir.
- **Update:** Form açıldığında gözlemlenen `expectedLatestVersion` kontrol edilir; değişmişse `409 Conflict` dönülür. Bu kontrol de harici yazıcılara karşı atomik CAS değildir. Varsayılan olarak mevcut metadata korunur ve kullanıcının açık değişiklikleri uygulanır.
- **Mutation Retry Politikası:** Mutasyon (create/update/delete/recover) istemcisi için belirsiz 5xx/timeout yanıtlarında kör otomatik retry yapılarak fazladan versiyon üretilmez (`maxRetries=0` mutasyon yolunda; okuma/listeleme yolunda `Retry-After` uyumlu sınırlı backoff).
- **Delete/Recover:** Yalnızca `ADMIN` rolü (ve delete için ayrıca `APP_DELETE_ENABLED=true`) ile soft-delete ve recover desteklenir. `beginDeleteSecret` / `beginRecoverDeletedSecret` poller'ları asenkron takip edilir; başarı doğrulanmadan tamamlandı dönülmez.
- **Purge:** Uygulamada permanent purge için hiçbir endpoint, UI bileşeni veya Azure SDK çağrısı bulunmaz.

## ADR-001.7 — Audit ve Hassas Veri Hijyeni
- **Karar:** Tüm yetkili, başarısız ve reddedilmiş işlemler Elasticsearch uyumlu structured JSON formatında UTC timestamp, authenticated subject, vault ID, secret name/version, action, outcome ve correlation ID ile audit edilir. Secret value, Azure client secret, token, tags veya contentType asla loglanmaz.
- **Sınırlar:** Java `String` ve tarayıcı JS belleği garbage collected olduğu için bellek temizliği best-effort'tur; gereksiz kopyalar azaltılır, `Cache-Control: no-store` uygulanır ve JVM heapdump/env actuator uçları kapalı tutulur. Local dosya/stdout audit logları değiştirilemez (immutable) değildir; server dağıtımında merkezi, erişimi kısıtlı ve retention tanımlı audit sink zorunludur.
