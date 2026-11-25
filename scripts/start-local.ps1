#Requires -Version 5.1
<#
.SYNOPSIS
    Starts Azure Key Vault Manager locally on Windows (loopback 127.0.0.1).
.DESCRIPTION
    Loads Azure Service Principal configuration securely without passing secrets
    via command-line arguments or terminal history.
    Supports AZURE_CLIENT_SECRET_FILE (preferred) or interactive masked prompt.
#>
[CmdletBinding()]
param(
    [string]$JarPath = "",
    [string]$BindAddress = "",
    [int]$Port = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-JavaExecutable {
    $candidates = @()
    if (-not [string]::IsNullOrWhiteSpace($env:JAVA_HOME)) {
        $candidates += (Join-Path $env:JAVA_HOME "bin\java.exe")
    }
    $pathJava = Get-Command java -ErrorAction SilentlyContinue
    if ($pathJava) {
        $candidates += $pathJava.Source
    }

    foreach ($candidate in ($candidates | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $candidate)) {
            continue
        }
        $versionOutput = & $candidate -version 2>&1 | Out-String
        if ($versionOutput -match 'version\s+"(\d+)(?:\.(\d+))?') {
            $major = [int]$Matches[1]
            if ($major -ge 21) {
                return $candidate
            }
        }
    }
    return $null
}

$repoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($JarPath)) {
    $JarPath = Join-Path $repoRoot "backend\build\libs\azure-key-vault-operator.jar"
}

if (-not (Test-Path -LiteralPath $JarPath)) {
    Write-Error "Executable JAR not found at '$JarPath'. Build it first with: .\gradlew.bat bootJar"
    exit 1
}

$javaExe = Resolve-JavaExecutable
if (-not $javaExe) {
    Write-Error "Java 21 or newer is required. Set JAVA_HOME to a JDK/JRE 21 installation or add Java 21 to PATH."
    exit 1
}

# Validate required Azure Service Principal identifiers (non-secret)
if ([string]::IsNullOrWhiteSpace($env:AZURE_TENANT_ID)) {
    Write-Error "AZURE_TENANT_ID is required. Set `$env:AZURE_TENANT_ID before running this script."
    exit 1
}
if ([string]::IsNullOrWhiteSpace($env:AZURE_CLIENT_ID)) {
    Write-Error "AZURE_CLIENT_ID is required. Set `$env:AZURE_CLIENT_ID before running this script."
    exit 1
}

# Validate client secret source (strictly one source; never CLI args)
$hasEnvSecret = -not [string]::IsNullOrWhiteSpace($env:AZURE_CLIENT_SECRET)
$hasSecretFile = -not [string]::IsNullOrWhiteSpace($env:AZURE_CLIENT_SECRET_FILE)
$promptedSecret = $false

if ($hasEnvSecret -and $hasSecretFile) {
    Write-Error "Both AZURE_CLIENT_SECRET and AZURE_CLIENT_SECRET_FILE are set. Configure exactly one secret source."
    exit 1
}

if ($hasSecretFile) {
    if (-not (Test-Path -LiteralPath $env:AZURE_CLIENT_SECRET_FILE -PathType Leaf)) {
        Write-Error "AZURE_CLIENT_SECRET_FILE does not exist or is not a regular file: '$($env:AZURE_CLIENT_SECRET_FILE)'"
        exit 1
    }
} elseif (-not $hasEnvSecret) {
    Write-Host "AZURE_CLIENT_SECRET / AZURE_CLIENT_SECRET_FILE is not set." -ForegroundColor Yellow
    $secureSecret = Read-Host -Prompt "Enter Azure Service Principal Client Secret VALUE (masked)" -AsSecureString
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureSecret)
    try {
        $plainSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        if ([string]::IsNullOrWhiteSpace($plainSecret)) {
            Write-Error "Client secret value cannot be empty."
            exit 1
        }
        $env:AZURE_CLIENT_SECRET = $plainSecret
        $promptedSecret = $true
    } finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
        $secureSecret.Dispose()
        Remove-Variable -Name plainSecret -ErrorAction SilentlyContinue
    }
}

# Apply secure local defaults without overwriting explicit operator overrides
if ([string]::IsNullOrWhiteSpace($env:APP_PROFILE)) {
    $env:APP_PROFILE = "local"
}
if (-not [string]::IsNullOrWhiteSpace($BindAddress)) {
    $env:SERVER_ADDRESS = $BindAddress
} elseif ([string]::IsNullOrWhiteSpace($env:SERVER_ADDRESS)) {
    $env:SERVER_ADDRESS = "127.0.0.1"
}
if ($Port -gt 0) {
    $env:SERVER_PORT = [string]$Port
} elseif ([string]::IsNullOrWhiteSpace($env:SERVER_PORT)) {
    $env:SERVER_PORT = "8765"
}
if ([string]::IsNullOrWhiteSpace($env:APP_DELETE_ENABLED)) {
    $env:APP_DELETE_ENABLED = "false"
}
if ([string]::IsNullOrWhiteSpace($env:APP_METADATA_TTL)) {
    $env:APP_METADATA_TTL = "5m"
}

Write-Host "Starting Azure Key Vault Manager (profile=$($env:APP_PROFILE), bind=$($env:SERVER_ADDRESS):$($env:SERVER_PORT))..." -ForegroundColor Cyan
Write-Host "UI URL: http://$($env:SERVER_ADDRESS):$($env:SERVER_PORT)/" -ForegroundColor Green

try {
    # Secret is passed strictly through process environment or mounted file, NEVER via JVM/CLI arguments.
    & $javaExe -jar $JarPath
    exit $LASTEXITCODE
} finally {
    if ($promptedSecret) {
        Remove-Item Env:AZURE_CLIENT_SECRET -ErrorAction SilentlyContinue
    }
}
