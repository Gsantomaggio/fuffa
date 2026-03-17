#!/usr/bin/env bash
# Generate GitHub release notes from merged PRs, grouped by labels (bug, enhancement, document)
# and including milestone when present.
# Usage: generate-release-notes.sh <repo_owner> <repo_name> <current_tag> [previous_tag]
# If previous_tag is omitted, all merged PRs that are in the current tag are considered.

set -euo pipefail

OWNER="${1:?Missing owner}"
REPO="${2:?Missing repo}"
CURRENT_TAG="${3:?Missing current tag}"
PREVIOUS_TAG="${4:-}"

# Label to section mapping: label_name -> "### Section Title"
declare -A LABEL_SECTIONS=(
  ["bug"]="### Bug Fix"
  ["enhancement"]="### Enhancement"
  ["document"]="### Document"
)

# Order of sections in the output
SECTION_ORDER=(bug enhancement document)

# Accept header for commits/pulls API (required for List pull requests for a commit)
ACCEPT_HEADER="Accept: application/vnd.github+json"
API_VERSION_HEADER="X-GitHub-Api-Version: 2022-11-28"

if [[ -z "$PREVIOUS_TAG" ]]; then
  # First release: no comparison possible, output nothing or placeholder
  echo "First release."
  exit 0
fi

COMPARE_URL="https://api.github.com/repos/${OWNER}/${REPO}/compare/${PREVIOUS_TAG}...${CURRENT_TAG}"

# Collect unique PR numbers from commits in the compare range
pr_numbers=()
compare_json=$(gh api "${COMPARE_URL}" 2>/dev/null || true)
[[ -z "$compare_json" ]] && echo "No changes." && exit 0

commits=$(echo "$compare_json" | jq -r '.commits[]? | .sha // empty')
[[ -z "$commits" ]] && echo "No changes." && exit 0

while IFS= read -r sha; do
  [[ -z "$sha" ]] && continue
  pulls=$(gh api "repos/${OWNER}/${REPO}/commits/${sha}/pulls" -H "$ACCEPT_HEADER" -H "$API_VERSION_HEADER" 2>/dev/null || echo "[]")
  nums=$(echo "$pulls" | jq -r '.[] | select(.merged_at != null) | .number // empty')
  for n in $nums; do
    pr_numbers+=("$n")
  done
done <<< "$commits"

# Deduplicate PR numbers (preserve order)
declare -A seen
unique_prs=()
for n in "${pr_numbers[@]}"; do
  if [[ -z "${seen[$n]:-}" ]]; then
    seen[$n]=1
    unique_prs+=("$n")
  fi
done

# Fetch each PR and group by label
declare -A section_bug section_enhancement section_document section_other

for pr_num in "${unique_prs[@]}"; do
  pr_json=$(gh api "repos/${OWNER}/${REPO}/pulls/${pr_num}" 2>/dev/null || true)
  [[ -z "$pr_json" ]] && continue

  title=$(echo "$pr_json" | jq -r '.title // ""')
  html_url=$(echo "$pr_json" | jq -r '.html_url // ""')
  milestone=$(echo "$pr_json" | jq -r '.milestone.title // empty')
  labels=$(echo "$pr_json" | jq -r '.labels[]? | .name // empty')

  # Build line: "- PR #N: Title (Milestone: X)" or "- PR #N: Title"
  line="- [#${pr_num}](${html_url}) ${title}"
  if [[ -n "$milestone" ]]; then
    line="${line} *(Milestone: ${milestone})*"
  fi

  placed=false
  for lbl in $labels; do
    lbl_lower=$(echo "$lbl" | tr '[:upper:]' '[:lower:]')
    if [[ -n "${LABEL_SECTIONS[$lbl_lower]:-}" ]]; then
      case "$lbl_lower" in
        bug) section_bug["$pr_num"]="$line" ;;
        enhancement) section_enhancement["$pr_num"]="$line" ;;
        document) section_document["$pr_num"]="$line" ;;
      esac
      placed=true
      break
    fi
  done
  if [[ "$placed" == false ]]; then
    section_other["$pr_num"]="$line"
  fi
done

# Output release notes in order: Bug Fix, Enhancement, Document, then Other
output=""

print_section() {
  local -n arr=$1
  local title=$2
  if [[ ${#arr[@]} -gt 0 ]]; then
    output+="${title}"$'\n'$'\n'
    for k in $(echo "${!arr[@]}" | tr ' ' '\n' | sort -n); do
      output+="${arr[$k]}"$'\n'
    done
    output+=$'\n'
  fi
}

print_section section_bug "### Bug Fix"
print_section section_enhancement "### Enhancement"
print_section section_document "### Document"
if [[ ${#section_other[@]} -gt 0 ]]; then
  output+="### Other"$'\n'$'\n'
  for k in $(echo "${!section_other[@]}" | tr ' ' '\n' | sort -n); do
    output+="${section_other[$k]}"$'\n'
  done
fi

# Trim trailing newlines and print
echo -n "$output" | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}'
