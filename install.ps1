# ================================================================
# NRTG — Installateur universel Windows (PowerShell)
# Détecte l'environnement et installe toutes les dépendances.
# Usage : powershell -ExecutionPolicy Bypass -File install.ps1
# ================================================================

param(
    [switch]$SkipRust,
    [switch]$SkipVS,
    [switch]$SkipNpcap,
    [switch]$DockerOnly,
    [switch]$Force
)

$ErrorActionPreference = "Continue"

# ── Couleurs ────────────────────────────────────────────────────
function Write-Info  { param($m) Write-Host "[INFO]  $m" -ForegroundColor Cyan }
function Write-OK    { param($m) Write-Host "[OK]    $m" -ForegroundColor Green }
function Write-Warn  { param($m) Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Write-Err   { param($m) Write-Host "[ERROR] $m" -ForegroundColor Red }
function Write-Step  { param($m) Write-Host "`n=== $m ===" -ForegroundColor Magenta }

# ── Détection d'élévation admin ─────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host ""
Write-Host "╔══════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   NRTG — Installateur universel Windows      ║" -ForegroundColor Cyan
Write-Host "║   Network Redteam Grapher v2.0               ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

Write-Info "OS           : $([System.Environment]::OSVersion.VersionString)"
Write-Info "Architecture : $([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture)"
Write-Info "PowerShell   : $($PSVersionTable.PSVersion)"
Write-Info "Admin        : $isAdmin"

# ================================================================
# 1. Winget disponible ?
# ================================================================
$hasWinget = $null -ne (Get-Command winget -ErrorAction SilentlyContinue)
if ($hasWinget) { Write-OK "winget disponible" }
else            { Write-Warn "winget non disponible (Windows 10 1709+ requis pour winget)" }

# ================================================================
# 2. Installer Rust / Rustup
# ================================================================
Write-Step "Vérification de Rust"

$rustOk = $null -ne (Get-Command rustc -ErrorAction SilentlyContinue)
if ($rustOk -and -not $Force) {
    Write-OK "Rust déjà installé : $(rustc --version)"
    rustup update stable 2>$null | Out-Null
} elseif (-not $SkipRust) {
    Write-Info "Installation de Rust via rustup-init..."
    $rustupUrl = "https://win.rustup.rs/x86_64"
    $rustupExe = "$env:TEMP\rustup-init.exe"
    Invoke-WebRequest -Uri $rustupUrl -OutFile $rustupExe -UseBasicParsing
    & $rustupExe -y --default-toolchain stable --default-host x86_64-pc-windows-msvc 2>&1
    # Recharger PATH
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("PATH", "User")
    if (Get-Command rustc -ErrorAction SilentlyContinue) {
        Write-OK "Rust installé : $(rustc --version)"
    } else {
        Write-Warn "Rust installé mais nécessite un nouveau terminal. Relancez ce script."
    }
}

# ================================================================
# 3. Détecter link.exe (VS Build Tools C++)
# ================================================================
Write-Step "Vérification de Visual C++ Build Tools"

function Find-LinkExe {
    # Chercher via vswhere
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
        if ($vsPath) {
            $candidates = Get-ChildItem "$vsPath\VC\Tools\MSVC\*\bin\HostX64\x64\link.exe" -ErrorAction SilentlyContinue
            if ($candidates) { return $candidates[0].DirectoryName }
        }
    }
    # Chemins hardcodés connus
    $knownPaths = @(
        "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\*\bin\HostX64\x64",
        "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\*\bin\HostX64\x64",
        "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\*\bin\HostX64\x64",
        "C:\Program Files\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC\*\bin\HostX64\x64"
    )
    foreach ($p in $knownPaths) {
        $found = Get-ChildItem $p -Filter "link.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) { return $found.DirectoryName }
    }
    return $null
}

$linkDir = Find-LinkExe
if ($linkDir) {
    Write-OK "link.exe trouvé : $linkDir"
    $env:PATH = "$linkDir;" + $env:PATH
    $vsOk = $true
} else {
    Write-Warn "link.exe non trouvé — Visual C++ Build Tools non installé"
    $vsOk = $false

    if (-not $SkipVS) {
        Write-Step "Installation de VS Build Tools 2022 avec C++ workload"
        if ($hasWinget) {
            Write-Info "Installation via winget..."
            winget install --id Microsoft.VisualStudio.2022.BuildTools `
                --override "--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --passive --wait" `
                --accept-package-agreements --accept-source-agreements
        } elseif ($isAdmin) {
            Write-Info "Téléchargement de VS Build Tools..."
            $vsUrl = "https://aka.ms/vs/17/release/vs_buildtools.exe"
            $vsExe = "$env:TEMP\vs_buildtools.exe"
            Invoke-WebRequest -Uri $vsUrl -OutFile $vsExe -UseBasicParsing
            Write-Info "Installation en cours (peut prendre 5-10 minutes)..."
            Start-Process -FilePath $vsExe -ArgumentList `
                "--add Microsoft.VisualStudio.Workload.VCTools",
                "--includeRecommended", "--passive", "--wait", "--norestart" `
                -Wait -NoNewWindow
        } else {
            Write-Warn "Droits administrateur requis pour installer VS Build Tools."
            Write-Warn "Relancez PowerShell en tant qu'administrateur ou utilisez :"
            Write-Warn "  winget install Microsoft.VisualStudio.2022.BuildTools"
        }

        # Revérifier après installation
        $linkDir = Find-LinkExe
        if ($linkDir) {
            Write-OK "link.exe disponible après installation : $linkDir"
            $env:PATH = "$linkDir;" + $env:PATH
            $vsOk = $true
        } else {
            Write-Warn "VS Build Tools installé — relancez ce script pour finir."
        }
    }
}

# ================================================================
# 4. Vérifier / installer NPCAP (pour la capture réseau live)
# ================================================================
Write-Step "Vérification de NPCAP (capture réseau live)"

$npcapInstalled = Test-Path "C:\Windows\System32\Npcap" -PathType Container
if (-not $npcapInstalled) {
    $npcapDll = Test-Path "C:\Windows\System32\wpcap.dll"
    $npcapInstalled = $npcapDll
}

if ($npcapInstalled) {
    Write-OK "NPCAP déjà installé"
} else {
    Write-Warn "NPCAP non installé — la capture réseau live (--capture-iface) ne fonctionnera pas"
    Write-Info "Le scanner TCP/HTTP fonctionne SANS NPCAP"

    if (-not $SkipNpcap) {
        $resp = Read-Host "Installer NPCAP maintenant ? (recommandé pour la capture live) [O/n]"
        if ($resp -match '^[Oo]?$') {
            Write-Info "Téléchargement de NPCAP 1.80..."
            $npcapUrl = "https://npcap.com/dist/npcap-1.80.exe"
            $npcapExe = "$env:TEMP\npcap-installer.exe"
            try {
                Invoke-WebRequest -Uri $npcapUrl -OutFile $npcapExe -UseBasicParsing
                Write-Info "Lancement de l'installateur NPCAP..."
                Write-Warn "IMPORTANT : Cochez 'Install Npcap in WinPcap API-compatible Mode' !"
                Start-Process -FilePath $npcapExe -Wait
                Write-OK "NPCAP installé"
            } catch {
                Write-Warn "Téléchargement NPCAP échoué. Installez manuellement depuis : https://npcap.com"
            }
        } else {
            Write-Info "NPCAP ignoré — build continuera sans capture live"
        }
    }
}

# ================================================================
# 5. Docker disponible ?
# ================================================================
Write-Step "Vérification de Docker"
$dockerOk = $null -ne (Get-Command docker -ErrorAction SilentlyContinue)
if ($dockerOk) {
    Write-OK "Docker disponible : $(docker --version)"
} else {
    Write-Info "Docker non installé — méthode Docker non disponible"
    Write-Info "Installez Docker Desktop depuis : https://www.docker.com/products/docker-desktop/"
}

# ================================================================
# 6. Choisir la méthode de build
# ================================================================
Write-Step "Compilation de NRTG"

if (-not (New-Item -ItemType Directory -Path "out" -Force -ErrorAction SilentlyContinue | Out-Null; Test-Path "out")) {
    New-Item -ItemType Directory -Path "out" | Out-Null
}

$cargoOk = $null -ne (Get-Command cargo -ErrorAction SilentlyContinue)

if ($DockerOnly -and $dockerOk) {
    # Méthode Docker
    Write-Info "Build via Docker..."
    docker build -t nrtg .
    Write-OK "Image Docker nrtg:latest construite"
    Write-Info "Test :"
    docker run --rm nrtg --features
} elseif ($cargoOk -and $vsOk) {
    # Méthode Rust native MSVC
    Write-Info "Build Rust natif MSVC..."
    cargo build --release -j2
    if (Test-Path ".\target\release\nrtg.exe") {
        Write-OK "Binaire : .\target\release\nrtg.exe"
        & ".\target\release\nrtg.exe" --features
    } else {
        Write-Err "Compilation échouée"
    }
} elseif ($cargoOk -and -not $vsOk) {
    # Essayer toolchain GNU si disponible
    $gnuAvailable = (rustup toolchain list 2>$null) -match "gnu"
    if ($gnuAvailable) {
        Write-Info "VS Build Tools absent — tentative avec toolchain GNU..."
        # Ajouter llvm-mingw au PATH si présent localement
        $mingwBin = ".\tools\mingw\llvm-mingw-20240619-ucrt-x86_64\bin"
        if (Test-Path $mingwBin) {
            $env:PATH = (Resolve-Path $mingwBin).Path + ";" + $env:PATH
            Write-Info "llvm-mingw ajouté au PATH"
        }
        cargo +stable-x86_64-pc-windows-gnu build --release -j2
        if (Test-Path ".\target\x86_64-pc-windows-gnu\release\nrtg.exe") {
            Write-OK "Binaire : .\target\x86_64-pc-windows-gnu\release\nrtg.exe"
        }
    } elseif ($dockerOk) {
        Write-Warn "Rust/VS non prêts — build via Docker à la place..."
        docker build -t nrtg .
        Write-OK "Image Docker nrtg:latest construite"
        docker run --rm nrtg --features
    } else {
        Write-Err "Impossible de compiler : ni VS Build Tools ni Docker disponibles."
        Write-Info "Solutions :"
        Write-Info "  1. Relancer ce script (VS Build Tools vient peut-être d'être installé)"
        Write-Info "  2. Installer Docker Desktop : https://www.docker.com/products/docker-desktop/"
        Write-Info "  3. Installer manuellement VS Build Tools :"
        Write-Info "     winget install Microsoft.VisualStudio.2022.BuildTools"
    }
} elseif ($dockerOk) {
    Write-Info "Cargo absent — build via Docker..."
    docker build -t nrtg .
    docker run --rm nrtg --features
} else {
    Write-Err "Aucune méthode de build disponible."
    Write-Info "Installez l'une des options suivantes :"
    Write-Info "  A) Rust + VS Build Tools : https://rustup.rs + winget install Microsoft.VisualStudio.2022.BuildTools"
    Write-Info "  B) Docker Desktop        : https://www.docker.com/products/docker-desktop/"
}

# ================================================================
# 7. Récapitulatif final
# ================================================================
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║   NRTG — Récapitulatif de l'installation             ║" -ForegroundColor Green
Write-Host "╠══════════════════════════════════════════════════════╣" -ForegroundColor Green
$rustStatus  = if ($cargoOk)   { "✓ OK" } else { "✗ Manquant" }
$vsStatus    = if ($vsOk)      { "✓ OK" } else { "✗ Manquant" }
$npcapStatus = if ($npcapInstalled) { "✓ OK (capture live activée)" } else { "○ Optionnel (scan TCP/HTTP OK)" }
$dockerStatus= if ($dockerOk)  { "✓ OK" } else { "○ Non installé" }
Write-Host "║  Rust/Cargo   : $rustStatus" -ForegroundColor Green
Write-Host "║  VS C++ Tools : $vsStatus" -ForegroundColor Green
Write-Host "║  NPCAP        : $npcapStatus" -ForegroundColor Green
Write-Host "║  Docker       : $dockerStatus" -ForegroundColor Green
Write-Host "╠══════════════════════════════════════════════════════╣" -ForegroundColor Green
Write-Host "║  Commandes après installation :                       ║" -ForegroundColor Green
Write-Host "║    .\target\release\nrtg.exe --features              ║" -ForegroundColor Green
Write-Host "║    .\target\release\nrtg.exe --examples              ║" -ForegroundColor Green
Write-Host "║    .\target\release\nrtg.exe --tutorial              ║" -ForegroundColor Green
Write-Host "║    start dashboard.html                              ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Green
