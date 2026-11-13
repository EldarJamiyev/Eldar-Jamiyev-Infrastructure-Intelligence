#!/usr/bin/env bash
# ==============================================================================
# EJII Universal Agent Skills Setup & Harness Interoperability Script (Bash)
#
# Non-destructive integration bridge linking EJII canonical skills (.agents/skills/)
# to Claude Code, Cursor IDE, OpenAI Codex, and Google Antigravity workspaces.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CANONICAL_SKILLS_DIR="${REPO_ROOT}/.agents/skills"

AGENT="all"
GLOBAL=false
DRY_RUN=false
FORCE=false

print_usage() {
  echo "Usage: $0 [options]"
  echo "Options:"
  echo "  --agent <name>   Target harness: claude, cursor, codex, antigravity, or all (default: all)"
  echo "  --global         Install/link into user global home directory instead of workspace"
  echo "  --dry-run        Preview linking actions without modifying the filesystem"
  echo "  --force          Overwrite conflicting existing targets"
  echo "  --help           Show this message"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --agent)
      AGENT="$2"
      shift 2
      ;;
    --global)
      GLOBAL=true
      shift
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --force)
      FORCE=true
      shift
      ;;
    --help)
      print_usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      print_usage
      exit 1
      ;;
  esac
done

if [[ ! -d "${CANONICAL_SKILLS_DIR}" ]]; then
  echo "Error: Canonical skills directory not found: ${CANONICAL_SKILLS_DIR}" >&2
  exit 1
fi

echo "========================================================================"
echo "  EJII Universal Agent Skills Setup Tool (Bash)                         "
echo "========================================================================"
echo "Target Harness  : ${AGENT}"
echo "Target Scope    : $(if [[ "${GLOBAL}" == true ]]; then echo 'Global (User Home)'; else echo 'Project Workspace'; fi)"
echo "Execution Mode  : $(if [[ "${DRY_RUN}" == true ]]; then echo 'DRY RUN (Preview Only)'; else echo 'ACTIVE'; fi)"
echo "Source Skills   : ${CANONICAL_SKILLS_DIR}"
echo "------------------------------------------------------------------------"

declare -a TARGETS=()

if [[ "${AGENT}" == "claude" || "${AGENT}" == "all" ]]; then
  if [[ "${GLOBAL}" == true ]]; then
    TARGETS+=("Claude Code:${HOME}/.claude/skills")
  else
    TARGETS+=("Claude Code:${REPO_ROOT}/.claude/skills")
  fi
fi

if [[ "${AGENT}" == "cursor" || "${AGENT}" == "all" ]]; then
  if [[ "${GLOBAL}" == true ]]; then
    TARGETS+=("Cursor IDE:${HOME}/.cursor/skills")
  else
    TARGETS+=("Cursor IDE:${REPO_ROOT}/.cursor/skills")
  fi
fi

if [[ "${AGENT}" == "codex" || "${AGENT}" == "all" ]]; then
  if [[ "${GLOBAL}" == true ]]; then
    TARGETS+=("OpenAI Codex:${HOME}/.codex/skills")
  else
    TARGETS+=("OpenAI Codex:${REPO_ROOT}/.codex/skills")
  fi
fi

if [[ "${AGENT}" == "antigravity" || "${AGENT}" == "all" ]]; then
  if [[ "${GLOBAL}" == true ]]; then
    TARGETS+=("Google Antigravity:${HOME}/.gemini/skills")
  else
    TARGETS+=("Google Antigravity:${REPO_ROOT}/.gemini/skills")
  fi
fi

for entry in "${TARGETS[@]}"; do
  NAME="${entry%%:*}"
  TARGET_DIR="${entry##*:}"

  echo ""
  echo "Configuring harness: ${NAME}"
  echo "Target Location   : ${TARGET_DIR}"

  if [[ -L "${TARGET_DIR}" ]]; then
    CURRENT_LINK="$(readlink "${TARGET_DIR}" || true)"
    echo "  [Exists] Symlink already present pointing to: ${CURRENT_LINK}"
    continue
  elif [[ -d "${TARGET_DIR}" ]]; then
    echo "  [Conflict] Existing directory found at target path."
    if [[ "${FORCE}" != true ]]; then
      echo "  [Skipping] Use --force to overwrite existing directory."
      continue
    fi
    if [[ "${DRY_RUN}" == false ]]; then
      rm -rf "${TARGET_DIR}"
    fi
  fi

  if [[ "${DRY_RUN}" == true ]]; then
    echo "  [DryRun] Would symlink ${CANONICAL_SKILLS_DIR} -> ${TARGET_DIR}"
    continue
  fi

  mkdir -p "$(dirname "${TARGET_DIR}")"
  ln -sfn "${CANONICAL_SKILLS_DIR}" "${TARGET_DIR}"
  echo "  [Success] Symlinked ${TARGET_DIR} -> ${CANONICAL_SKILLS_DIR}"
done

echo ""
echo "------------------------------------------------------------------------"
echo "Setup completed successfully."
