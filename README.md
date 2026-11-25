# Azure Key Vault Manager (`azure-key-vault-operator`)

Self-hosted, tek executable JAR (Spring Boot 3.5 + Angular 21) olarak paketlenen, yalnızca **Azure Key Vault Secrets** (ad/değer ve metadata) yönetimine odaklanan güvenli yönetim paneli.

> **Kapsam Sınırı:** Kriptografik `Keys`, `Certificates`, toplu yazma/silme (`bulk mutation`) ve kalıcı silme (`permanent purge`) bilinçli olarak kapsam dışındadır; uygulamada purge endpoint'i, UI düğmesi veya SDK çağrısı bulunmaz. MVP sürümü veritabanı kullanmaz.

---

## 1. Mimari Özet

```text
Browser (Angular 21 SPA, Same-Origin)
  └─▶ Spring Security 6 (CSRF, Host/Origin, RateLimit, Local Bootstrap / OIDC, RBAC)
        └─▶ REST API (/api/v1/**, RFC 9457 Problem Details, Opaque Vault ID)
              └─▶ Authorization + Metadata Pagination/Caffeine Cache + Audit Logger
                    └─▶ Azure SDK for Java (ClientSecretCredentialBuilder)
                          ├─▶ Microsoft Entra ID (Token)
                          ├─▶ Azure Resource Manager (Opsiyonel Subscription/Vault Discovery)
                          └─▶ Azure Key Vault Data Plane (https://*.vault.azure.net)
```

- **Same-Origin Tek JAR:** Angular 21 production çıktısı Gradle derlemesi ile Spring Boot içine gömülür (`backend/src/main/resources/static`). CORS tamamen kapalıdır.
- **Secret Hijyeni:** Frontend Azure'a doğrudan bağlanmaz. Azure credential'ları, access token'lar ve client secret'lar hiçbir API yanıtına veya loga girmez. Secret listeleme ve arama yalnızca metadata çeker; değerler yalnızca açık `reveal` isteğiyle geçici olarak görüntülenir (30 sn otomatik temizleme).
- **Ayrıntılı mimari ve tehdit modeli:** [docs/ADR-001-architecture.md](docs/ADR-001-architecture.md), [docs/threat-model.md](docs/threat-model.md), [docs/openapi.yaml](docs/openapi.yaml).

---

## 2. Azure Kurulumu (Service Principal & En Az Yetki)

Uygulama `AzureCliCredential` veya `az login` **kullanmaz**. Yalnızca `ClientSecretCredentialBuilder` ile deterministik Service Principal kimlik doğrulaması yapar; otomatik credential fallback yoktur. MVP yalnızca **Azure Public Cloud** (`*.vault.azure.net`) hedefler.

### 2.1 Microsoft Entra ID — App Registration (Single Tenant)

1. Azure Portal → **Microsoft Entra ID** → **App registrations** → **New registration**.
2. **Name:** örn. `akv-manager-operator-dev` (ortam bazında ayrı Service Principal önerilir).
3. **Supported account types:** **Accounts in this organizational directory only (Single tenant)** seçin.
4. Kayıt sonrası **Overview** ekranından şu değerleri not alın:
   - **Directory (tenant) ID** → `AZURE_TENANT_ID`
   - **Application (client) ID** → `AZURE_CLIENT_ID`

### 2.2 Certificates & Secrets — Client Secret Oluşturma

1. Uygulama kaydında **Certificates & secrets** → **Client secrets** → **New client secret**.
2. Kısa/yönetilebilir bir geçerlilik süresi (örn. 90 veya 180 gün) belirleyin ve oluşturun.
3. Yalnızca oluşturma anında görünen **Value** sütununu kopyalayın (`AZURE_CLIENT_SECRET` veya `AZURE_CLIENT_SECRET_FILE` içeriği olarak kullanın).
   > **Dikkat:** **Secret ID** sütununu değil, **Value** sütununu kullanın. Secret ID kullanıldığında Entra ID `401` (`AZURE_CREDENTIAL_INVALID`) hatası döner.

### 2.3 IAM Rol Atamaları (RBAC — Purge Hariç En Az Yetki)

> **`Owner` veya `Contributor` rolü ASLA vermeyin.** Yerleşik `Key Vault Secrets Officer` rolü `purge` yetkisi içerdiğinden bunun yerine aşağıdaki **purge hariç Custom Role** tanımını kullanın.

#### A) Control Plane (Discovery) — Opsiyonel
- Uygulamanın erişilebilir subscription ve vault'ları ARM üzerinden otomatik keşfetmesi için **mümkün olan en dar kapsamda** (tercihen yalnızca ilgili Resource Group veya hedef Key Vault'lar üzerinde) yerleşik **`Reader`** rolünü atayın.
- ARM `Reader` vermek istemiyorsanız Bölüm 2.5'teki **Data-Plane-Only (Statik Vault)** yapılandırmasını kullanın.

#### B) Data Plane (Azure RBAC Yetkilendirmeli Vault'lar) — Özel Rol (Purge Yok)
Aşağıdaki resmi Azure Key Vault `DataActions` tanımıyla özel bir rol oluşturup Service Principal'a yalnızca hedef Key Vault (veya Resource Group) kapsamında atayın:

```json
{
  "Name": "Key Vault Secrets Operator (No Purge)",
  "IsCustom": true,
  "Description": "Manage Key Vault secrets metadata, values, versions, soft-delete and recovery without permanent purge.",
  "Actions": [],
  "NotActions": [],
  "DataActions": [
    "Microsoft.KeyVault/vaults/secrets/readMetadata/action",
    "Microsoft.KeyVault/vaults/secrets/getSecret/action",
    "Microsoft.KeyVault/vaults/secrets/setSecret/action",
    "Microsoft.KeyVault/vaults/secrets/update/action",
    "Microsoft.KeyVault/vaults/secrets/delete",
    "Microsoft.KeyVault/vaults/secrets/recover/action"
  ],
  "NotDataActions": [
    "Microsoft.KeyVault/vaults/secrets/purge/action"
  ],
  "AssignableScopes": [
    "/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RESOURCE_GROUP>"
  ]
}
```

- Salt okunur bir dağıtım planlıyorsanız yalnızca `readMetadata/action` (ve reveal gerekiyorsa `getSecret/action`) bırakabilirsiniz.
- Delete özelliğini hiç açmayacaksanız (`APP_DELETE_ENABLED=false`) `delete` ve `recover/action` izinlerini de çıkarabilirsiniz.

### 2.4 Legacy Access Policy Kullanan Vault'lar

Vault yetkilendirme modeli **Vault access policy** ise, Service Principal için **Secret permissions** altında yalnızca şu minimum izinleri tanımlayın:
- `Get`, `List`, `Set`, `Delete`, `Recover` (salt okunur kurulumda yalnızca `List` ve gerekirse `Get`)
- **`Purge` kutucuğunu ASLA işaretlemeyin.** Key ve Certificate izinleri boş bırakılmalıdır.

### 2.5 Data-Plane-Only Kullanım (ARM Reader Olmadan)

ARM `Reader` yetkisi verilmeyen ortamlarda yönetici tarafından doğrulanan güvenilir vault eşleştirmeleri ortam değişkeniyle tanımlanabilir (kullanıcıdan serbest URL alınmaz; yalnızca `https://<vault>.vault.azure.net` ve 443 portu kabul edilir):

```bash
APP_STATIC_VAULTS_0_RESOURCE_ID=/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-app/providers/Microsoft.KeyVault/vaults/kv-example-dev
APP_STATIC_VAULTS_0_VAULT_URI=https://kv-example-dev.vault.azure.net
APP_STATIC_VAULTS_0_ENVIRONMENT=dev
```

---

## 3. Yapılandırma ve Ortam Değişkenleri

Örnek şablon için [.env.example](.env.example) dosyasına bakın. Gerçek `.env` dosyaları `.gitignore` kapsamındadır ve asla Git'e eklenmez.

| Değişken | Zorunluluk | Varsayılan | Açıklama |
|---|---|---|---|
| `AZURE_TENANT_ID` | Zorunlu | — | Entra ID Tenant GUID |
| `AZURE_CLIENT_ID` | Zorunlu | — | App Registration Client ID |
| `AZURE_CLIENT_SECRET` | İkisinden biri | — | Client secret **Value** (`AZURE_CLIENT_SECRET_FILE` ile birlikte verilemez) |
| `AZURE_CLIENT_SECRET_FILE` | İkisinden biri | — | Mounted/kısıtlı secret dosya yolu (tercih edilen) |
| `AZURE_SUBSCRIPTION_ID` | Opsiyonel | — | ARM keşfini tek subscription ile sınırlar |
| `APP_PROFILE` | Opsiyonel | `local` | `local` veya `server` (geçersiz değerde fail-closed) |
| `SERVER_ADDRESS` | Opsiyonel | `127.0.0.1` | Local profilde yalnızca loopback (`127.0.0.1` / `::1`) |
| `SERVER_PORT` | Opsiyonel | `8765` | Dinlenen HTTP portu |
| `APP_METADATA_TTL` | Opsiyonel | `5m` | Metadata cache TTL süresi |
| `APP_DELETE_ENABLED` | Opsiyonel | `false` | `true` + `ADMIN` yetkisi olmadan soft-delete kapalı |
| `APP_ALLOWED_VAULT_IDS` | Server'da zorunlu | — | İzin verilen Azure Vault Resource ID listesi (virgüllü) |
| `APP_LOCAL_ALLOW_CONTAINER_BIND` | Opsiyonel | `false` | Yalnızca local container içinde `0.0.0.0` bind istisnası |
| `OIDC_ISSUER_URI` | Server'da zorunlu | — | HTTPS OIDC Issuer URL (Ory Hydra uyumlu) |
| `OIDC_CLIENT_ID` | Server'da zorunlu | — | OIDC client ID |
| `OIDC_CLIENT_SECRET` | Server'da zorunlu | — | OIDC client secret (Azure SP secret'tan ayrı saklanır) |
| `APP_SERVER_PUBLIC_BASE_URL` | Server'da zorunlu | — | Dış HTTPS erişim URL'si (Host/Origin/OIDC doğrulama) |
| `APP_SERVER_TRUSTED_PROXIES` | Server önerilen | — | Güvenilir reverse proxy CIDR listesi (örn. `10.0.0.0/8`) |
| `APP_SERVER_ROLE_MAPPINGS_JSON` | Server önerilen | — | Kullanıcı/grup → vault → rol JSON eşleştirmesi |

---

## 4. Derleme ve Test (Tek Komut)

Gereksinimler:
- **Java 21** (JDK 21)
- **Node.js 24 LTS** (Angular 21 uyumlu; repoda `package-lock.json` ile sabitlenmiştir)

### Windows (PowerShell)
```powershell
.\gradlew.bat testFrontend :backend:test bootJar
```

### Linux / macOS
```bash
./gradlew testFrontend :backend:test bootJar
```

Derleme sonunda Angular arayüzünü içeren tek executable JAR şu konumda oluşur:
`backend/build/libs/azure-key-vault-operator.jar`

---

## 5. Yerel (Local) Çalıştırma

Local profil yalnızca yerel operatörün tekil kullanımı içindir:
- Varsayılan olarak `127.0.0.1:8765` üzerinde dinler ve loopback dışındaki bağlantıları reddeder.
- Başlangıçta yüksek entropili (256-bit), kısa ömürlü (varsayılan 10 dk), **tek kullanımlık** bir bootstrap token üretir ve yalnızca yerel terminal çıktısında (`stdout`) gösterir. Token log dosyalarına veya URL query string'e yazılmaz.
- Oturum açılışında Session ID yenilenir (`HttpOnly`, `SameSite=Strict`), 15 dk idle timeout uygulanır.
- **Token tüketildikten veya süresi dolduktan sonra yeniden giriş:** Bootstrap token tek kullanımlıktır. Çıkış yaptıktan veya oturum zaman aşımına uğradıktan sonra yeni bir tek kullanımlık token üretmek için uygulamayı yeniden başlatın.

### 5.1 Windows PowerShell ile Çalıştırma

Script client secret'ı hiçbir zaman komut satırı argümanına veya PowerShell geçmişine yazmaz. Tercihen kısıtlı izinli bir dosya (`AZURE_CLIENT_SECRET_FILE`) kullanın veya gizli istemle (`Read-Host -AsSecureString`) girin:

```powershell
# Seçenek A (Önerilen): Kısıtlı secret dosyası
$env:AZURE_TENANT_ID = "00000000-0000-0000-0000-000000000000"
$env:AZURE_CLIENT_ID = "11111111-1111-1111-1111-111111111111"
$env:AZURE_CLIENT_SECRET_FILE = "C:\secure\akv-client-secret.txt"
.\scripts\start-local.ps1

# Seçenek B: Secret ortam değişkeni yoksa script maskeli olarak sorar
$env:AZURE_TENANT_ID = "00000000-0000-0000-0000-000000000000"
$env:AZURE_CLIENT_ID = "11111111-1111-1111-1111-111111111111"
Remove-Item Env:AZURE_CLIENT_SECRET -ErrorAction SilentlyContinue
Remove-Item Env:AZURE_CLIENT_SECRET_FILE -ErrorAction SilentlyContinue
.\scripts\start-local.ps1
```

### 5.2 Linux / macOS ile Çalıştırma

```bash
chmod +x scripts/start-local.sh

# Seçenek A (Önerilen): 0400 izinli secret dosyası
export AZURE_TENANT_ID="00000000-0000-0000-0000-000000000000"
export AZURE_CLIENT_ID="11111111-1111-1111-1111-111111111111"
export AZURE_CLIENT_SECRET_FILE="/run/secrets/azure_client_secret"
./scripts/start-local.sh

# Seçenek B: İnteraktif maskeli giriş (read -r -s)
unset AZURE_CLIENT_SECRET AZURE_CLIENT_SECRET_FILE
./scripts/start-local.sh
```

Tarayıcıda `http://127.0.0.1:8765/` adresini açın ve terminalde gösterilen tek kullanımlık bootstrap token'ı giriş formuna girin.

### 5.3 Docker / Podman Local Modu (`compose.yaml`)

Container ortamında uygulama container ağı içinden erişilebilmek için `SERVER_ADDRESS=0.0.0.0` ve açık `APP_LOCAL_ALLOW_CONTAINER_BIND=true` istisnasıyla çalışır; ancak `compose.yaml` portu **yalnızca host loopback arayüzüne (`127.0.0.1:8765:8765`)** yayınlar. Ayrıca `HostOriginValidationFilter` yalnızca `localhost`, `127.0.0.1`, `[::1]` Host başlıklarını kabul eder.

Container güvenlik sertleştirmesi:
- Multi-stage build, sabitlenmiş Alpine imaj sürümleri (`node:24.21.0-alpine`, `eclipse-temurin:21.0.5_11-jdk-alpine`, `eclipse-temurin:21.0.5_11-jre-alpine`)
- Non-root kullanıcı (`akvuser`, UID/GID `10001`)
- Read-only root filesystem (`read_only: true`) + `/tmp` `tmpfs` (`noexec,nosuid,nodev`)
- Tüm Linux yetkileri kaldırılmış (`cap_drop: [ALL]`, `no-new-privileges:true`)

```bash
# .env.example dosyasını .env olarak kopyalayıp doldurun (ya da secret file mount edin)
cp .env.example .env

# Docker Compose veya Podman Compose ile başlatma
docker compose up --build
# veya Podman ile:
podman compose up --build
```

---

## 6. Server Profili (OIDC / Ory Hydra) ve Kubernetes Helm Dağıtımı

Server profili (`APP_PROFILE=server`) çok kullanıcılı üretim/ekip ortamları içindir. Eksik OIDC ayarları, eksik HTTPS `APP_SERVER_PUBLIC_BASE_URL` veya boş `APP_ALLOWED_VAULT_IDS` durumunda uygulama **fail-closed** olarak başlamaz; asla local profile düşmez.

### 6.1 Uygulama İçi RBAC Rolleri (Deny-by-Default)

Azure Service Principal uygulamanın kimliğidir; son kullanıcı yetkilendirmesi uygulama içinde ayrıca uygulanır. Eşleşmesi olmayan OIDC kullanıcısı hiçbir vault'a erişemez.

| İşlem | `VIEWER` | `OPERATOR` | `MANAGER` | `ADMIN` |
|---|:---:|:---:|:---:|:---:|
| Liste / arama / metadata | Evet | Evet | Evet | Evet |
| Reveal / copy | Hayır | Evet | Evet | Evet |
| Create / update / restore version / properties | Hayır | Hayır | Evet | Evet |
| Soft-delete / recover (`APP_DELETE_ENABLED=true` ile) | Hayır | Hayır | Hayır | Evet |
| Permanent Purge | Hayır | Hayır | Hayır | Hayır |

Örnek `APP_SERVER_ROLE_MAPPINGS_JSON`:
```json
[
  {
    "group": "platform-sec-admins",
    "vaultResourceId": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-app/providers/Microsoft.KeyVault/vaults/kv-app-prod",
    "role": "ADMIN"
  },
  {
    "subject": "user-uuid-1234",
    "vaultResourceId": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-app/providers/Microsoft.KeyVault/vaults/kv-app-prod",
    "role": "OPERATOR"
  }
]
```

### 6.2 Ory Hydra / OIDC İstemci Kaydı
- **Redirect URI:** `<APP_SERVER_PUBLIC_BASE_URL>/login/oauth2/code/oidc`
- **Oturum başlatma yolu:** `/oauth2/authorization/oidc`
- **Scopes:** `openid`, `profile`, `email` (ve grup eşleştirme kullanıyorsanız `groups` claim'i)

### 6.3 Kubernetes Helm Chart Kurulumu

Chart konumu: `deploy/helm/azure-key-vault-operator/`

> **Önemli Kurallar:**
> 1. Azure SP secret'ı ve OIDC client secret'ı **iki ayrı Kubernetes Secret** içinde tutulmalıdır (chart aynı Secret adının verilmesini engeller).
> 2. **Bootstrap döngüsü oluşturmayın:** `akv-azure-sp` Kubernetes Secret'ını bu uygulamanın yönettiği aynı Azure Key Vault'tan çekmeye çalışmayın.
> 3. **Tek replica (`replicaCount: 1`):** Dağıtık session store ve harici audit altyapısı eklenene kadar MVP tek replica ile sınırlıdır.
> 4. **Merkezi Audit Sink:** Pod `stdout` üzerindeki `logType="audit"` JSON kayıtlarını erişimi kısıtlı, retention politikası tanımlı bir merkezi Elasticsearch/OpenSearch/SIEM hedefine (örn. Fluent Bit) aktarın.

```bash
# 1. Ayrı Kubernetes Secret'larını oluşturun (gerçek değerleri Git/values.yaml'a koymayın)
kubectl create secret generic akv-azure-sp \
  --namespace akv-operator \
  --from-file=client-secret=/path/to/azure-sp-client-secret-value

kubectl create secret generic akv-oidc \
  --namespace akv-operator \
  --from-literal=client-id="akv-manager-oidc-client" \
  --from-file=client-secret=/path/to/oidc-client-secret

# 2. Chart doğrulama
helm lint deploy/helm/azure-key-vault-operator

# 3. Kurulum (örnek; ingress varsayılan kapalıdır, TLS + trustedProxies ile açın)
helm upgrade --install akv-operator deploy/helm/azure-key-vault-operator \
  --namespace akv-operator \
  --set azure.tenantId="00000000-0000-0000-0000-000000000000" \
  --set azure.clientId="11111111-1111-1111-1111-111111111111" \
  --set azure.existingSecret="akv-azure-sp" \
  --set oidc.existingSecret="akv-oidc" \
  --set server.publicBaseUrl="https://akv-manager.example.internal" \
  --set server.oidcIssuerUri="https://hydra.example.internal" \
  --set server.trustedProxies="10.244.0.0/16" \
  --set "allowedVaultIds[0]=/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-app/providers/Microsoft.KeyVault/vaults/kv-app-prod" \
  --set-string server.roleMappingsJson='[{"group":"platform-ops","vaultResourceId":"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-app/providers/Microsoft.KeyVault/vaults/kv-app-prod","role":"OPERATOR"}]'
```

---

## 7. Credential Rotasyonu ve Süre Sonu (Expiration) Yönetimi

### Kesintisiz (Overlapping) Rotasyon Prosedürü
1. Entra ID → App Registration → **Certificates & secrets** bölümünde mevcut secret silinmeden **yeni** bir client secret oluşturun ve **Value** değerini güvenli kasaya alın.
2. Kubernetes Secret (`akv-azure-sp`) veya `AZURE_CLIENT_SECRET_FILE` hedef dosyasını yeni secret değeriyle güncelleyin.
3. Uygulamayı / Pod'u yeniden başlatın (`kubectl rollout restart deployment/...` — `ClientSecretCredential` başlangıçta tek kez okunur ve SDK token'larını otomatik yeniler).
4. Uygulama üzerinden en az bir vault metadata yenilemesinin başarılı olduğunu doğrulayın.
5. Eski client secret'ı Entra ID üzerinden kaldırın.

### Süre Sonu / Geçersiz Kimlik Belirtileri
- Uygulama, Azure servis kimliği hatalarını kullanıcı oturum hatasından (`AUTH_REQUIRED`) ayırır:
  - **`AZURE_CREDENTIAL_INVALID` (HTTP 401):** Client secret süresi dolmuş, iptal edilmiş, Secret ID yanlışlıkla Value yerine yazılmış veya Tenant/Client ID hatalıdır.
  - **`AZURE_PERMISSION_DENIED` (HTTP 403):** Service Principal geçerlidir ancak hedef Key Vault üzerinde gerekli RBAC / Access Policy iznine sahip değildir.

---

## 8. Canlı Azure Doğrulaması (Opt-In)

Varsayılan tüm otomatik testler (`./gradlew testFrontend :backend:test`) mock Azure / WireMock ile çalışır ve gerçek Azure kaynağına bağlanmaz.

Canlı Azure doğrulaması **yalnızca kullanıcının açık onayıyla** ve **tek kullanımlık (disposable) bir test Key Vault** üzerinde yapılmalıdır:
- Production vault üzerinde create/update/delete testi **kesinlikle yasaktır**.
- Disposable test vault için ayrı, dar yetkili bir test Service Principal oluşturun.
- `APP_ALLOWED_VAULT_IDS` değişkenini yalnızca test vault'un Resource ID'si ile sınırlayın.
- Test sonrasında oluşturulan sentetik secret'ları temizleyin ve test Service Principal secret'ını iptal edin.

---

## 9. Sorun Giderme (Troubleshooting)

| Belirti / Hata Kodu | Olası Neden | Çözüm |
|---|---|---|
| Startup hatası: `Both AZURE_CLIENT_SECRET and AZURE_CLIENT_SECRET_FILE are configured` | İki secret kaynağı aynı anda verilmiş | Yalnızca birini tanımlayın; diğerini kaldırın |
| Startup hatası: `Local profile requires loopback SERVER_ADDRESS` | Local profilde `0.0.0.0` bind denenmiş | Host çalıştırmada `127.0.0.1` kullanın; container local modunda `APP_LOCAL_ALLOW_CONTAINER_BIND=true` + host `127.0.0.1:8765` publish kullanın |
| Startup hatası: `Server profile requires an explicit non-empty APP_ALLOWED_VAULT_IDS` | Server modunda zorunlu allowlist/OIDC/publicBaseUrl eksik | Tüm zorunlu server değişkenlerini eksiksiz sağlayın |
| `HOST_HEADER_INVALID` (403) | İzin verilmeyen `Host` başlığı veya ters proxy `Host` iletmiyor | Local'de `localhost`/`127.0.0.1` kullanın; server'da `APP_SERVER_PUBLIC_BASE_URL` ile proxy `Host` başlığını eşleştirin |
| `AZURE_CREDENTIAL_INVALID` (401) | Secret süresi dolmuş veya Value yerine Secret ID girilmiş | Entra ID'den yeni secret Value üretin ve güncelleyin |
| `AZURE_PERMISSION_DENIED` (403) | Vault RBAC/Access Policy veya Key Vault firewall/private endpoint engeli | Bölüm 2.3/2.4 rollerini ve ağ/private endpoint erişimini doğrulayın |
| `AZURE_RATE_LIMITED` (429) | Azure Key Vault throttling | Uygulama `Retry-After` başlığına uyar; kısa süre bekleyip yeniden deneyin |
| `VERSION_CONFLICT` (409) | Secret başka bir kullanıcı/sistem tarafından güncellenmiş | Metadata'yı yenileyin, güncel sürümü inceleyip tekrar kaydedin |

---

## 10. Güvenlik Sınırlamaları ve Bilinen Varsayımlar

1. **Bellek Temizliği (Best-Effort):** Java `String` ve tarayıcı JavaScript string nesneleri garbage collected ve immutable olduğundan secret değerlerinin bellekten anında sıfırlanması garanti edilemez. Uygulama gereksiz kopyaları azaltır, `Cache-Control: no-store` uygular ve `/actuator/heapdump` / `/actuator/env` uçlarını kapalı tutar.
2. **Non-Atomic Create/Update Yarışı:** Azure Key Vault `setSecret` işlemi upsert semantiğindedir. Uygulama aynı JVM içinde `(vaultId, secretName)` kilidi ve ön sürüm/ad kontrolü uygular; ancak harici yazıcılara (Azure Portal, CLI, başka bir pipeline) karşı atomik Compare-And-Swap (CAS) garantisi yoktur.
3. **Clipboard Temizliği:** Tarayıcı güvenlik kısıtlamaları nedeniyle panoya kopyalanan secret değerinin otomatik temizleneceği garanti edilemez; kopyalama yalnızca açık kullanıcı tıklamasıyla yapılır.
4. **Local Audit Logları Değiştirilemez Değildir:** Yerel çalışma modunda terminal/dosya logları operatör tarafından silinebilir veya değiştirilebilir. Uyumluluk gerektiren server dağıtımlarında merkezi, erişimi kısıtlı ve retention tanımlı audit sink zorunludur.
5. **Tek Replica Sınırı:** MVP dağıtık session store içermediğinden server dağıtımları tek replica (`replicaCount: 1`) ile çalıştırılmalıdır.
6. **Sovereign Cloud:** MVP yalnızca Azure Public Cloud (`*.vault.azure.net`) uçlarını doğrular; sovereign cloud desteği otomatik varsayılmaz.
