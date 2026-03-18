#!/usr/bin/env bash
# Generate release notes from merged PRs, grouped by label.
# Label mapping: bug, bug-fix -> Bug Fix; enhancement -> Enhancement; document -> Document.
# Usage: run in GitHub Actions with GITHUB_TOKEN, REPO_OWNER, REPO_NAME, TAG_NAME set; optional PREV_TAG.

set -euo pipefail

# Label -> section heading (first matching label wins per PR)
# Format: "label1|label2|...:Section Title"
LABEL_SECTIONS=(
  "bug|bug-fix:Bug Fixes"
  "enhancement:Enhancement"
  "documentation:Documentation"
  "refactor:Refactor"
  "test:Test"
  "ci:CI"
  "perf:Performance"
  "security:Security"
)

section_for_labels() {
  local labels="$1"
  local lower
  lower=$(echo "$labels" | tr '[:upper:]' '[:lower:]')
  for entry in "${LABEL_SECTIONS[@]}"; do
    local pattern="${entry%%:*}"
    local section="${entry#*:}"
    IFS='|' read -ra LABS <<< "$pattern"
    for l in "${LABS[@]}"; do
      if echo ",${lower}," | grep -q ",${l},"; then
        echo "$section"
        return
      fi
    done
  done
  echo ""
}

REPO="${REPO_OWNER}/${REPO_NAME}"
TAG_NAME="${TAG_NAME:?TAG_NAME required}"
PREV_TAG="${PREV_TAG:-}"

if [[ -z "${PREV_TAG}" ]]; then
  # Compare from default branch (e.g. first release or when PREV_TAG not set)
  DEFAULT_BRANCH=$(gh api "repos/${REPO}" --jq '.default_branch')
  COMPARE_URL="repos/${REPO}/compare/${DEFAULT_BRANCH}...${TAG_NAME}"
  FROM_REF="${DEFAULT_BRANCH}"
else
  COMPARE_URL="repos/${REPO}/compare/${PREV_TAG}...${TAG_NAME}"
  FROM_REF="${PREV_TAG}"
fi

FULL_CHANGELOG_URL="https://github.com/${REPO}/compare/${FROM_REF}...${TAG_NAME}"

# Collect unique PR numbers from commits in the range
PR_NUMS=$(gh api "$COMPARE_URL" --jq '.commits[] | .sha' 2>/dev/null | while read -r sha; do
  gh api "repos/${REPO}/commits/${sha}/pulls" --jq '.[].number' 2>/dev/null || true
done | sort -nu)

declare -A SECTION_PR
SECTION_OTHER="Other"

for num in $PR_NUMS; do
  pr_json=$(gh api "repos/${REPO}/pulls/${num}" 2>/dev/null || true)
  if [[ -z "${pr_json}" ]]; then continue; fi
  title=$(echo "$pr_json" | jq -r '.title')
  html_url=$(echo "$pr_json" | jq -r '.html_url')
  author=$(echo "$pr_json" | jq -r '.user.login')
  labels=$(echo "$pr_json" | jq -r '[.labels[].name] | join(",")')
  section=$(section_for_labels "$labels")
  if [[ -z "$section" ]]; then
    section="$SECTION_OTHER"
  fi
  line="- ${title} [#${num}](${html_url}) by @${author}"
  if [[ -z "${SECTION_PR[$section]+x}" ]]; then
    SECTION_PR[$section]="$line"
  else
    SECTION_PR[$section]="${SECTION_PR[$section]}"$'\n'"$line"
  fi
done

# Build markdown in desired order
ORDERED_SECTIONS=("Bug Fix" "Enhancement" "Document" "Other")
BODY=""
for sec in "${ORDERED_SECTIONS[@]}"; do
  if [[ -n "${SECTION_PR[$sec]+x}" ]]; then
    BODY="${BODY}### ${sec}"$'\n\n'
    BODY="${BODY}${SECTION_PR[$sec]}"
    BODY="${BODY}"$'\n\n'
  fi
done
BODY="${BODY%%$'\n\n'}"

if [[ -n "$BODY" ]]; then
  BODY="${BODY}"$'\n\n'"**Full Changelog**: ${FULL_CHANGELOG_URL}"
  gh release edit "$TAG_NAME" --repo "$REPO" --notes "$BODY"
  echo "Release notes updated for $TAG_NAME"
else
  echo "No PRs found for this release range; release body unchanged."
fi
