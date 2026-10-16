$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName System.IO.Compression
function Get-TaskSHA256([string]$LiteralPath) {
  $stream = [IO.File]::OpenRead($LiteralPath)
  $sha = [Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','').ToLowerInvariant() }
  finally { $stream.Dispose(); $sha.Dispose() }
}
$taskRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$releaseRoot = [IO.Path]::GetFullPath((Join-Path $taskRoot 'release'))
if (-not $releaseRoot.StartsWith($taskRoot + [IO.Path]::DirectorySeparatorChar)) { throw 'Release path must stay within this project.' }
New-Item -ItemType Directory -Force -Path $releaseRoot | Out-Null

# An allowlist prevents future private files from silently entering releases.
$relativeFiles = @(
  '.gitignore', 'package.json', 'package-lock.json', 'wrangler.toml', 'schema.sql',
  'README.md', 'API.md', 'SECURITY.md', 'AUDIT.md', 'PLAN.md', 'LICENSE',
  'public/index.html', 'src/worker.js', 'playwright.config.mjs',
  '.github/workflows/ci.yml', '.github/workflows/deploy.yml',
  'scripts/agent.mjs', 'scripts/check.mjs', 'scripts/package.ps1', 'scripts/preview.mjs',
  'scripts/lib/local-d1.mjs', 'tests/api.test.mjs', 'tests/crypto.test.mjs', 'tests/browser/vault.spec.mjs'
)
$utf8 = New-Object System.Text.UTF8Encoding($false)
$forbidden = @(
  '[A-Za-z]:[\\/]Users[\\/]',
  'ouneed|kdns\.fr',
  '(?i)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
  '\b(?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{20,}',
  '(?i)(?:SERVER_SECRET|SETUP_TOKEN)\s*=\s*["'']?[a-f0-9]{32,}',
  '"enc_key"\s*:\s*"[a-f0-9]{64}"'
)
# This script necessarily names the sensitive paths it rejects. Scan packaged
# source, excluding this scanner's own literal denylist, for those values.
$manifest = @()
foreach ($relative in $relativeFiles) {
  $absolute = [IO.Path]::GetFullPath((Join-Path $taskRoot $relative))
  if (-not $absolute.StartsWith($taskRoot + [IO.Path]::DirectorySeparatorChar)) { throw "Unsafe source path: $relative" }
  if (-not (Test-Path -LiteralPath $absolute -PathType Leaf)) { throw "Missing release file: $relative" }
  if ((Get-Item -LiteralPath $absolute).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Links are not allowed: $relative" }
  $text = [IO.File]::ReadAllText($absolute)
  if ($relative -ne 'scripts/package.ps1') {
    foreach ($pattern in $forbidden) { if ($text -match $pattern) { throw "Private data pattern found in $relative" } }
  }
  $manifest += [pscustomobject]@{ path=$relative; bytes=(Get-Item -LiteralPath $absolute).Length; sha256=(Get-TaskSHA256 $absolute) }
}
$config = [IO.File]::ReadAllText((Join-Path $taskRoot 'wrangler.toml'))
if ($config -notmatch 'database_id\s*=\s*"00000000-0000-0000-0000-000000000000"') { throw 'Replace the real D1 ID with the release placeholder before packaging.' }

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$zipPath = Join-Path $releaseRoot "still-cf-totp-sanitized-$stamp.zip"
$archive = [IO.Compression.ZipFile]::Open($zipPath, [IO.Compression.ZipArchiveMode]::Create)
try {
  foreach ($file in $manifest) {
    [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive,(Join-Path $taskRoot $file.path),$file.path,[IO.Compression.CompressionLevel]::Optimal) | Out-Null
  }
  $entry = $archive.CreateEntry('MANIFEST.json')
  $writer = New-Object IO.StreamWriter($entry.Open(),$utf8)
  try { $writer.Write(($manifest | ConvertTo-Json -Depth 3)) } finally { $writer.Dispose() }
} finally { $archive.Dispose() }

# Verify exact file set and individual hashes by reading bytes back from the ZIP.
$check = [IO.Compression.ZipFile]::OpenRead($zipPath)
try {
  if ($check.Entries.Count -ne $manifest.Count + 1) { throw 'Archive count mismatch.' }
  foreach ($file in $manifest) {
    $entry = $check.GetEntry($file.path)
    if (-not $entry) { throw "Missing archive entry: $($file.path)" }
    $stream = $entry.Open(); $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','').ToLowerInvariant() }
    finally { $stream.Dispose(); $sha.Dispose() }
    if ($hash -ne $file.sha256) { throw "Archive hash mismatch: $($file.path)" }
  }
} finally { $check.Dispose() }
$hash = Get-TaskSHA256 $zipPath
[IO.File]::WriteAllText($zipPath + '.sha256', "$hash  $([IO.Path]::GetFileName($zipPath))`n", $utf8)
[IO.File]::WriteAllText($zipPath + '.manifest.json', ($manifest | ConvertTo-Json -Depth 3), $utf8)
Write-Output "Verified package: $zipPath"
Write-Output "Files: $($manifest.Count + 1) (including MANIFEST.json)"
Write-Output "SHA256: $hash"
