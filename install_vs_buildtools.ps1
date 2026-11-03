# ================================================================
# DIAPILE — Installation automatique VS Build Tools C++
# Lance ce script UNE SEULE FOIS pour pouvoir compiler DIAPILE sur Windows
#
# Ce script installe UNIQUEMENT les composants C++ nécessaires à Rust :
#   - link.exe (MSVC linker)
#   - Windows SDK headers/libs
# Taille : ~400MB — PAS d'IDE Visual Studio
#
# Usage : powershell -ExecutionPolicy Bypass -File install_vs_buildtools.ps1
# ================================================================

Write-Host ""
Write-Host "  ██████╗ ██╗ █████╗ ██████╗ ██╗██╗     ███████╗" -ForegroundColor Red
Write-Host "  ██╔══██╗██║██╔══██╗██╔══██╗██║██║     ██╔════╝" -ForegroundColor Red
Write-Host "  ██║  ██║██║███████║██████╔╝██║██║     █████╗  " -ForegroundColor Red
Write-Host "  ██║  ██║██║██╔══██║██╔═══╝ ██║██║     ██╔══╝  " -ForegroundColor Red
Write-Host "  ██████╔╝██║██║  ██║██║     ██║███████╗███████╗" -ForegroundColor Red
Write-Host "  ╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝" -ForegroundColor Red
Write-Host ""
Write-Host "  Installation VS Build Tools C++ (requis pour cargo build sur Windows)" -ForegroundColor Yellow
Write-Host ""

# Vérifier si link.exe est déjà disponible
$linkExe = Get-Command link.exe -ErrorAction SilentlyContinue
if ($linkExe) {
    Write-Host "  [OK] link.exe déjà trouvé : $($linkExe.Source)" -ForegroundColor Green
    Write-Host "  Vous pouvez lancer : cargo build --release" -ForegroundColor Green
    exit 0
}

# Télécharger VS Build Tools bootstrapper
$installer = "$env:TEMP\vs_buildtools.exe"
$url = "https://aka.ms/vs/17/release/vs_buildtools.exe"

Write-Host "  [1/3] Téléchargement VS Build Tools..." -ForegroundColor Cyan
try {
    Invoke-WebRequest -Uri $url -OutFile $installer -UseBasicParsing
    Write-Host "  [OK] Téléchargé" -ForegroundColor Green
} catch {
    Write-Host "  [ERR] Téléchargement échoué: $_" -ForegroundColor Red
    Write-Host "  Téléchargez manuellement: $url" -ForegroundColor Yellow
    exit 1
}

# Installation silencieuse — uniquement les composants nécessaires à Rust
Write-Host "  [2/3] Installation (silencieuse, ~400MB, ~5-10 min)..." -ForegroundColor Cyan
$args = @(
    "--quiet",
    "--wait",
    "--norestart",
    "--add", "Microsoft.VisualStudio.Workload.VCTools",
    "--add", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
    "--add", "Microsoft.VisualStudio.Component.Windows10SDK.19041",
    "--includeRecommended"
)

$process = Start-Process -FilePath $installer -ArgumentList $args -Wait -PassThru
if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
    Write-Host "  [OK] VS Build Tools installé (code: $($process.ExitCode))" -ForegroundColor Green
} else {
    Write-Host "  [WARN] Code de sortie: $($process.ExitCode)" -ForegroundColor Yellow
}

# Vérifier link.exe
Write-Host "  [3/3] Vérification..." -ForegroundColor Cyan
$vsPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC"
if (Test-Path $vsPath) {
    $linkPath = Get-ChildItem -Path $vsPath -Filter "link.exe" -Recurse | Select-Object -First 1
    if ($linkPath) {
        Write-Host "  [OK] link.exe trouvé : $($linkPath.FullName)" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Vous pouvez maintenant compiler DIAPILE :" -ForegroundColor Green
        Write-Host "  cargo build --release" -ForegroundColor Cyan
    }
} else {
    Write-Host "  Redémarrez le terminal et relancez : cargo build --release" -ForegroundColor Yellow
}

# Nettoyage
Remove-Item $installer -Force -ErrorAction SilentlyContinue
Write-Host ""
Write-Host "  Installation terminée. Redémarrez le terminal si nécessaire." -ForegroundColor Green
