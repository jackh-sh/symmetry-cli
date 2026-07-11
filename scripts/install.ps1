# Symmetry installer for Windows — downloads a prebuilt release binary.
#
# Usage (PowerShell):
#   irm https://raw.githubusercontent.com/OWNER/symmetry-cli/main/scripts/install.ps1 | iex
#
# Configuration (environment variables):
#   SYMMETRY_REPO         GitHub repo to install from (default: jackh-sh/symmetry-cli)
#   SYMMETRY_VERSION      Release tag, e.g. v0.1.0 (default: latest)
#   SYMMETRY_INSTALL_DIR  Where to put the binary (default: %LOCALAPPDATA%\Programs\symmetry)
#   SYMMETRY_NO_VERIFY=1  Install even without checksum/signature verification

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Repo = if ($env:SYMMETRY_REPO) { $env:SYMMETRY_REPO } else { 'jackh-sh/symmetry-cli' }
$Version = if ($env:SYMMETRY_VERSION) { $env:SYMMETRY_VERSION } else { 'latest' }
$InstallDir = if ($env:SYMMETRY_INSTALL_DIR) { $env:SYMMETRY_INSTALL_DIR } else {
    Join-Path $env:LOCALAPPDATA 'Programs\symmetry'
}

# Public key whose signature release checksums must carry (ssh-keygen -Y).
# Keep in sync with scripts/install.sh.
$SigningPubkey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBKhBx3y2nLJBz/JltVJ7U4rhazQaOcGd7Rvy1FpsB/t'

switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { $target = 'x86_64-pc-windows-msvc' }
    'ARM64' {
        Write-Host 'note: no arm64 Windows build yet; installing the x64 binary (runs under emulation)'
        $target = 'x86_64-pc-windows-msvc'
    }
    default { throw "unsupported Windows architecture: $env:PROCESSOR_ARCHITECTURE" }
}

$asset = "symmetry-$target.tar.gz"
$base = if ($Version -eq 'latest') {
    "https://github.com/$Repo/releases/latest/download"
} else {
    "https://github.com/$Repo/releases/download/$Version"
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("symmetry-install-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "Downloading symmetry ($Version, $target) from $Repo..."
    $assetPath = Join-Path $tmp $asset
    Invoke-WebRequest -Uri "$base/$asset" -OutFile $assetPath

    if ($env:SYMMETRY_NO_VERIFY -eq '1') {
        Write-Host 'warning: skipping checksum and signature verification (SYMMETRY_NO_VERIFY=1)'
    } else {
        $checksumPath = Join-Path $tmp "$asset.sha256"
        try {
            Invoke-WebRequest -Uri "$base/$asset.sha256" -OutFile $checksumPath
        } catch {
            throw 'release has no checksum file; refusing to install (set SYMMETRY_NO_VERIFY=1 to override)'
        }

        # Verify the SSH signature on the checksum file: it proves the
        # checksums come from this project's release key, not merely that
        # the download arrived intact. Windows 10+ ships ssh-keygen, but
        # only versions with -Y support (OpenSSH 8.0+) can check it.
        $sigPath = Join-Path $tmp "$asset.sha256.sig"
        $haveSig = $true
        try {
            Invoke-WebRequest -Uri "$base/$asset.sha256.sig" -OutFile $sigPath
        } catch {
            Write-Host 'warning: release has no signature (predates release signing); verifying checksum only'
            $haveSig = $false
        }
        if ($haveSig) {
            $supportsSig = $false
            if (Get-Command ssh-keygen -ErrorAction SilentlyContinue) {
                $probe = (& ssh-keygen -Y check-novalidate 2>&1) | Out-String
                if ($probe -notmatch 'unknown option|illegal option') { $supportsSig = $true }
            }
            if ($supportsSig) {
                $signersPath = Join-Path $tmp 'allowed_signers'
                [IO.File]::WriteAllText($signersPath, "release@symmetry $SigningPubkey`n")
                # cmd's < redirection feeds the file to stdin byte-for-byte.
                cmd /c "ssh-keygen -Y verify -f `"$signersPath`" -I release@symmetry -n symmetry-release -s `"$sigPath`" < `"$checksumPath`"" | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "signature verification failed for $asset.sha256" }
                Write-Host 'Signature verified.'
            } else {
                Write-Host 'warning: ssh-keygen with signature support not found; skipping signature check'
            }
        }

        $expected = ((Get-Content $checksumPath -Raw) -split '\s+')[0].ToLower()
        $actual = (Get-FileHash $assetPath -Algorithm SHA256).Hash.ToLower()
        if ($actual -ne $expected) { throw "checksum verification failed for $asset" }
        Write-Host 'Checksum verified.'
    }

    # tar.exe ships with Windows 10 1803+.
    & tar -xzf $assetPath -C $tmp
    if ($LASTEXITCODE -ne 0) { throw "failed to extract $asset" }
    $binPath = Join-Path $tmp 'symmetry.exe'
    if (-not (Test-Path $binPath)) { throw "archive did not contain symmetry.exe" }

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item $binPath (Join-Path $InstallDir 'symmetry.exe') -Force
    Write-Host "Installed $InstallDir\symmetry.exe"

    if (($env:Path -split ';') -notcontains $InstallDir) {
        Write-Host ''
        Write-Host "note: $InstallDir is not on your PATH. Add it (then open a new terminal) with:"
        Write-Host "  [Environment]::SetEnvironmentVariable('Path', '$InstallDir;' + [Environment]::GetEnvironmentVariable('Path', 'User'), 'User')"
    }

    Write-Host ''
    Write-Host "Done. Run 'symmetry --help' to get started."
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
