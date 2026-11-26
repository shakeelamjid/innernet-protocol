# Install innernet-provider on Windows (PowerShell 5.1+).
#   irm https://innernetcorp.com/install.ps1 | iex
# Optional: $env:INNERNET_VERSION = "provider-v0.6.0"
$ErrorActionPreference = "Stop"
$ProgressPreference = "Continue"   # show the download progress bar
$DL = if ($env:INNERNET_DL) { $env:INNERNET_DL } else { "https://innernetcorp.com/registry/dl" }
$BinDir = if ($env:INNERNET_BIN_DIR) { $env:INNERNET_BIN_DIR } else { Join-Path $env:LOCALAPPDATA "innernet\bin" }

Write-Host ""
Write-Host " INNERNET " -NoNewline -ForegroundColor Black -BackgroundColor White
Write-Host "  provider installer"
Write-Host ""
Write-Host "  This installs one program, innernet-provider, into $BinDir."
Write-Host "  It needs no admin rights. Remove it any time: innernet-provider uninstall" -ForegroundColor DarkGray
Write-Host ""

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
  "AMD64" { "amd64" }
  "ARM64" { "arm64" }
  default { throw "unsupported CPU $($env:PROCESSOR_ARCHITECTURE)" }
}

$tag = $env:INNERNET_VERSION
if (-not $tag) {
  try { $tag = ([string](Invoke-RestMethod "$DL/latest")).Trim() } catch { $tag = $null }
  if (-not $tag) { throw "could not find the latest release; set `$env:INNERNET_VERSION = 'provider-vX.Y.Z'" }
}
if ($tag -notlike "provider-v*") { throw "bad version tag: $tag" }

$asset = "innernet-provider-windows-$arch.exe"
$base = "$DL/$tag"
$tmp = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid())
New-Item -ItemType Directory $tmp | Out-Null
try {
  Write-Host "  Downloading $asset ($tag)"
  Invoke-WebRequest "$base/$asset" -OutFile (Join-Path $tmp $asset) -UseBasicParsing
  Invoke-WebRequest "$base/SHA256SUMS" -OutFile (Join-Path $tmp "SHA256SUMS") -UseBasicParsing
  $line = Get-Content (Join-Path $tmp "SHA256SUMS") | Where-Object { $_ -match " $([regex]::Escape($asset))$" }
  if (-not $line) { throw "no checksum listed for $asset" }
  $expected = ($line -split "\s+")[0].ToLower()
  $actual = (Get-FileHash (Join-Path $tmp $asset) -Algorithm SHA256).Hash.ToLower()
  if ($expected -ne $actual) { throw "checksum mismatch: expected $expected, got $actual" }
  Write-Host "  ✓ " -NoNewline -ForegroundColor Green; Write-Host "Checksum verified"
  New-Item -ItemType Directory -Force $BinDir | Out-Null
  Copy-Item (Join-Path $tmp $asset) (Join-Path $BinDir "innernet-provider.exe") -Force
} finally {
  Remove-Item -Recurse -Force $tmp
}

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (($userPath -split ";") -notcontains $BinDir) {
  [Environment]::SetEnvironmentVariable("Path", "$userPath;$BinDir", "User")
  Write-Host "  Added $BinDir to your PATH. Open a new terminal." -ForegroundColor DarkGray
}
$exe = Join-Path $BinDir 'innernet-provider.exe'
Write-Host "  ✓ " -NoNewline -ForegroundColor Green; Write-Host "Installed $exe"
# Start setup straight away unless INNERNET_NO_START is set (scripts) or the build predates "start".
if (-not $env:INNERNET_NO_START -and ((& $exe help) -match ' start ')) {
  Write-Host ""
  & $exe start
} else {
  Write-Host "  Next:  innernet-provider start"
}
