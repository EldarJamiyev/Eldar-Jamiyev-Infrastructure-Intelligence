<#
.SYNOPSIS
  EJII Universal Agent Skills Setup & Harness Interoperability Script (PowerShell)

.DESCRIPTION
  Establishes symlinks or verified directory links from EJII canonical skills (.agents/skills/)
  into targeted AI agent harnesses (Claude Code, Cursor IDE, OpenAI Codex, Google Antigravity).

.PARAMETER Agent
  Target AI agent harness: 'claude', 'cursor', 'codex', 'antigravity', or 'all' (default: 'all').

.PARAMETER Global
  Opt-in flag to install/link into user global home directory instead of current workspace.

.PARAMETER DryRun
  Preview linking operations without creating filesystem targets.

.PARAMETER Force
  Overwrite existing conflicting links or directories if confirmed.

.EXAMPLE
  .\scripts\setup-agent-skills.ps1 -Agent all -DryRun
  .\scripts\setup-agent-skills.ps1 -Agent claude
  .\scripts\setup-agent-skills.ps1 -Agent cursor -Global
#>

[CmdletBinding()]
param(
  [ValidateSet('claude', 'cursor', 'codex', 'antigravity', 'all')]
  [string]$Agent = 'all',

  [switch]$Global,
  [switch]$DryRun,
  [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$CanonicalSkillsDir = Join-Path $RepoRoot '.agents\skills'

if (-not (Test-Path $CanonicalSkillsDir)) {
  Write-Error "Canonical skills directory not found: $CanonicalSkillsDir"
  exit 1
}

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  EJII Universal Agent Skills Setup Tool (PowerShell)                   " -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "Target Harness  : $Agent"
Write-Host "Target Scope    : $(if ($Global) { 'Global (User Home)' } else { 'Project Workspace' })"
Write-Host "Execution Mode  : $(if ($DryRun) { 'DRY RUN (Preview Only)' } else { 'ACTIVE' })"
Write-Host "Source Skills   : $CanonicalSkillsDir"
Write-Host "------------------------------------------------------------------------"

$Targets = @()

if ($Agent -eq 'claude' -or $Agent -eq 'all') {
  $base = if ($Global) { Join-Path $HOME '.claude\skills' } else { Join-Path $RepoRoot '.claude\skills' }
  $Targets += [PSCustomObject]@{ Name = 'Claude Code'; TargetDir = $base }
}

if ($Agent -eq 'cursor' -or $Agent -eq 'all') {
  $base = if ($Global) { Join-Path $HOME '.cursor\skills' } else { Join-Path $RepoRoot '.cursor\skills' }
  $Targets += [PSCustomObject]@{ Name = 'Cursor IDE'; TargetDir = $base }
}

if ($Agent -eq 'codex' -or $Agent -eq 'all') {
  $base = if ($Global) { Join-Path $HOME '.codex\skills' } else { Join-Path $RepoRoot '.codex\skills' }
  $Targets += [PSCustomObject]@{ Name = 'OpenAI Codex'; TargetDir = $base }
}

if ($Agent -eq 'antigravity' -or $Agent -eq 'all') {
  $base = if ($Global) { Join-Path $HOME '.gemini\skills' } else { Join-Path $RepoRoot '.gemini\skills' }
  $Targets += [PSCustomObject]@{ Name = 'Google Antigravity'; TargetDir = $base }
}

foreach ($target in $Targets) {
  Write-Host "`nConfiguring harness: $($target.Name)" -ForegroundColor Yellow
  Write-Host "Target Location   : $($target.TargetDir)"

  if (Test-Path $target.TargetDir) {
    $existingItem = Get-Item $target.TargetDir
    if ($existingItem.LinkType) {
      Write-Host "  [Exists] Link already present pointing to: $($existingItem.Target)" -ForegroundColor Green
      continue
    } else {
      Write-Host "  [Conflict] Existing directory found at target path." -ForegroundColor Magenta
      if (-not $Force) {
        Write-Host "  [Skipping] Use -Force to overwrite existing directory." -ForegroundColor Gray
        continue
      }
    }
  }

  if ($DryRun) {
    Write-Host "  [DryRun] Would link $CanonicalSkillsDir -> $($target.TargetDir)" -ForegroundColor Cyan
    continue
  }

  $parentDir = Split-Path -Parent $target.TargetDir
  if (-not (Test-Path $parentDir)) {
    New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
  }

  try {
    # Attempt directory junction or symbolic link
    New-Item -ItemType Junction -Path $target.TargetDir -Target $CanonicalSkillsDir -ErrorAction Stop | Out-Null
    Write-Host "  [Success] Linked $($target.TargetDir) via Junction -> $CanonicalSkillsDir" -ForegroundColor Green
  } catch {
    try {
      New-Item -ItemType SymbolicLink -Path $target.TargetDir -Target $CanonicalSkillsDir -ErrorAction Stop | Out-Null
      Write-Host "  [Success] Linked $($target.TargetDir) via SymbolicLink -> $CanonicalSkillsDir" -ForegroundColor Green
    } catch {
      Write-Warning "  [Fallback] Junction/Symlink requires elevated privileges. Copying directory structure..."
      Copy-Item -Path $CanonicalSkillsDir -Destination $target.TargetDir -Recurse -Force
      Write-Host "  [Success] Copied skills to $($target.TargetDir)" -ForegroundColor Green
    }
  }
}

Write-Host "`n------------------------------------------------------------------------"
Write-Host "Setup completed successfully." -ForegroundColor Green
