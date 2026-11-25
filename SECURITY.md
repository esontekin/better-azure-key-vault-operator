# Güvenlik Politikası ve Kontroller (`SECURITY.md`)

Bu belge, **Azure Key Vault Manager** (`azure-key-vault-operator`) uygulamasının güvenlik mimarisini, OWASP ASVS / Top 10 eşleştirmesini, hassas veri hijyeni kurallarını, güvenlik tarama kapılarını ve güvenlik açığı bildirim sürecini özetler.

> **Önemli Not:** Derinlemesine savunma kontrolleri uygulanmış olsa da hiçbir yazılım mutlak güvenlik garantisi veremez. Üretim ortamlarında TLS sonlandırma, ağ segmentasyonu, merkezi audit saklama, düzenli bağımlılık güncellemesi ve en az yetki prensibi birlikte uygulanmalıdır.

---

## 1. Tehdit Modeli ve OWASP ASVS / Top 10 Eşleştirmesi

Tam tehdit analizi [docs/threat-model.md](docs/threat-model.md) dosyasında yer alır. Başlıca kontroller:

| Alan | OWASP Referansı | Uygulanan Kontrol |
|---|---|---|
| Erişim Kontrolü & IDOR | Top 10 A01 / ASVS V4 | Her REST endpoint ve async operation ID sorgusunda backend RBAC + vault scope kontrolü; opaque vault ID; discovery sonuçlarının kullanıcı yetkisine göre filtrelenmesi; deny-by-default. |
| Kimlik Doğrulama & Oturum | Top 10 A07 / ASVS V2, V3 | Local profilde 256-bit tek kullanımlık kısa ömürlü bootstrap token (constant-time SHA-256 doğrulama, brute-force rate limit), session ID rotation, `HttpOnly`/`SameSite=Strict`, 15 dk idle timeout. Server profilde OIDC (Ory Hydra uyumlu), `Secure` cookie, doğrulanmış `iss`/`sub`, fail-closed başlangıç. |
| Kriptografi & Veri Hijyeni | Top 10 A02 / ASVS V6, V8 | Secret değerleri hiçbir cache, DB, log, URL, toast, `localStorage`, `sessionStorage`, `IndexedDB` veya Service Worker'da saklanmaz. Tüm hassas API yanıtlarında `Cache-Control: no-store`. Azure SDK HTTP body logging kapalı. |
| Enjeksiyon & XSS | Top 10 A03 / ASVS V5 | Sıkı girdi doğrulama (Azure ad kuralları, 25 KB UTF-8 boyut sınırı), Angular strict template escaping, `Content-Security-Policy` (`default-src 'self'; frame-ancestors 'none'; object-src 'none'`), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`. |
| Güvenlik Yapılandırması & CSRF | Top 10 A05 / ASVS V14 | Spring Security CSRF, CORS tamamen kapalı, strict `Host`/`Origin`/`Referer` doğrulaması (DNS rebinding koruması), Trusted Proxy CIDR sınırı, HSTS (server profili), Actuator yalnızca detaysız `/actuator/health` (`env`, `configprops`, `heapdump`, `beans` kapalı). |
| SSRF Savunması | Top 10 A10 / ASVS V12.6 | Kullanıcıdan serbest URL alınmaz; yalnızca ARM discovery veya yönetici statik yapılandırması kullanılır. HTTPS, `.vault.azure.net` suffix ve port 443 doğrulanır; cross-host HTTP redirect ile bearer token sızıntısı engellenir. TLS sertifika doğrulaması asla kapatılmaz. |
| Kayıt & İzleme (Audit) | Top 10 A09 / ASVS V7 | Elasticsearch uyumlu structured JSON audit (`@timestamp` UTC, `subject`, `vaultId`, `secretName`, `secretVersion`, `action`, `outcome`, `correlationId`). Başarısız ve reddedilmiş işlemler de kaydedilir. Secret değeri, tag ve `contentType` asla audit loguna yazılmaz. |
| Tasarım Güvenliği | Top 10 A04 / ASVS V1 | Permanent purge tamamen kapsam dışı; soft-delete varsayılan kapalı (`APP_DELETE_ENABLED=false`) ve yalnızca `ADMIN` + isim yazarak onay ile çalışır; mutasyonlarda kör retry ile fazladan versiyon üretimi engellenir. |

---

## 2. Hassas Veri Hijyeni Kuralları

- **Kod ve Konfigürasyon:** Gerçek Azure Service Principal secret, OIDC client secret, sertifika veya `.env` dosyaları Git deposuna veya Helm `values.yaml` dosyasına asla eklenmez.
- **Process ve Komut Satırı:** `AZURE_CLIENT_SECRET` hiçbir startup script'inde veya container `ENTRYPOINT`'inde CLI argümanı olarak geçirilmez; yalnızca kısıtlı mounted dosya (`AZURE_CLIENT_SECRET_FILE`) veya maskeli istem üzerinden process ortamına verilir.
- **Credential Ayrımı:** Kubernetes dağıtımlarında Azure SP secret (`azure.existingSecret`) ile OIDC secret (`oidc.existingSecret`) ayrı Kubernetes Secret nesnelerinde tutulur.
- **Metadata Gizliliği:** Secret isimleri, `tags` ve `contentType` alanları da hassas kabul edilir; `tags` ve `contentType` loglanmaz ve kalıcı saklanmaz.
- **Audit Sink Gereksinimi:** Azure Key Vault tarafındaki aktivite logları yalnızca Service Principal kimliğini gösterir; son kullanıcı izlenebilirliği uygulama audit loglarına dayanır. Server modunda `logType="audit"` kayıtlarını merkezi, erişimi kısıtlı, retention tanımlı bir depoya aktarmak dağıtım ön koşuludur.

---

## 3. Güvenlik Taramaları ve Release Kapısı

Her release öncesinde aşağıdaki taramalar çalıştırılmalıdır. **Kritik (Critical) veya Yüksek (High) bulgular çözülmeden ya da açık risk kaydı ve kullanıcı onayı olmadan release yapılmamalıdır.**

### 3.1 Git Secret Scanning (`gitleaks`)
```bash
gitleaks detect --source . --verbose --redact
```

### 3.2 Bağımlılık Güvenlik Taraması
```bash
# Frontend (npm lockfile doğrulaması)
cd frontend && npm audit --omit=dev --audit-level=high

# Backend & Filesystem (Trivy)
trivy fs --scanners vuln,secret,misconfig --severity HIGH,CRITICAL .

# Alternatif: OWASP Dependency-Check (Gradle veya CLI)
dependency-check --project azure-key-vault-operator --scan backend/build/libs/azure-key-vault-operator.jar --failOnCVSS 7
```

### 3.3 Container İmaj ve Helm Chart Taraması
```bash
# Container imaj zafiyet ve yanlış yapılandırma taraması
trivy image --severity HIGH,CRITICAL azure-key-vault-operator:1.0.0

# Dockerfile, compose.yaml ve Helm chart misconfiguration taraması
trivy config --severity HIGH,CRITICAL .
helm lint deploy/helm/azure-key-vault-operator
```

---

## 4. Bilinen Güvenlik Sınırları

1. Java/JavaScript garbage-collected bellek modeli nedeniyle RAM'deki secret string'lerinin anında sıfırlanması garanti edilemez (best-effort minimizasyon).
2. Harici yazıcıların eşzamanlı olarak aynı Key Vault'ta değişiklik yapması durumunda Azure `setSecret` upsert semantiği nedeniyle create/update kontrolleri atomik CAS değildir.
3. Tarayıcı panosu (clipboard) işletim sistemi tarafından yönetildiğinden otomatik temizlik garanti edilemez.
4. Local modda konsol/dosya logları değiştirilemez (immutable) audit sağlamaz.
5. MVP tek replica destekler; çoklu replica kurulumu harici session ve audit mimarisi tamamlanmadan desteklenmez.

---

## 5. Güvenlik Açığı Bildirimi

Bir güvenlik açığı tespit ettiğinizde lütfen herkese açık issue açmayın:
1. Etkilenen bileşen, sürüm, yeniden üretme adımları ve olası etki özetini hazırlayın (gerçek credential veya üretim secret değeri paylaşmayın).
2. Kurum içi güvenlik ekibine (`security@example.internal` — kendi kuruluş adresinizle güncelleyin) şifreli/özel kanal üzerinden iletin.
3. İlk değerlendirme 2 iş günü içinde yapılır ve düzeltme yayınlanana kadar koordineli ifşa (coordinated disclosure) uygulanır.
