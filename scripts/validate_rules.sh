#!/usr/bin/env bash
# Simple validator for Clash rule lists in this repo.
# Exits with non-zero if issues found.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RULE_DIR="${ROOT_DIR}"

# Patterns
ALLOWED_PREFIX='^(DOMAIN(-SUFFIX|-KEYWORD)?|IP-CIDR),'
IP_CIDR_REGEX='^IP-CIDR,([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}(,.*)?$'

errors=0

echo "Scanning .list files under ${RULE_DIR} ..."

shopt -s nullglob
for f in "${RULE_DIR}"/*.list; do
  echo "Checking: $(basename "$f")"
  # Find lines starting with a digit but not IP-CIDR
  awk 'NR==FNR{next} {print}' "$f" >/dev/null 2>&1 || true

  # invalid prefix lines
  while IFS= read -r ln; do
    ln_no_comment=$(echo "$ln" | sed 's/#.*$//')
    ln_trim=$(echo "$ln_no_comment" | sed 's/^[ \t]*//;s/[ \t]*$//')
    [ -z "$ln_trim" ] && continue

    if ! echo "$ln_trim" | grep -Eq "$ALLOWED_PREFIX"; then
      echo "  [ERROR] invalid prefix in $(basename "$f"): '$ln_trim'"
      errors=$((errors+1))
      continue
    fi

    if echo "$ln_trim" | grep -Eq '^IP-CIDR,'; then
      if ! echo "$ln_trim" | grep -Eq "$IP_CIDR_REGEX"; then
        echo "  [ERROR] malformed IP-CIDR in $(basename "$f"): '$ln_trim'"
        errors=$((errors+1))
      fi
    fi

    if echo "$ln_trim" | grep -Eq '[0-9]+\.[0-9]+\.[0-9]+\.$'; then
      echo "  [ERROR] bare IP fragment ending with dot in $(basename "$f"): '$ln_trim'"
      errors=$((errors+1))
    fi

    if echo "$ln" | grep -Eq '[[:space:]]$'; then
      echo "  [WARN] trailing whitespace in $(basename "$f"): '$ln'"
    fi
  done < "$f"
done

# Validate Custom_Clash.ini for basic correctness and linkage to rulesets
INI_FILE="${ROOT_DIR}/config/Clash/Custom_Clash.ini"
if [ -f "$INI_FILE" ]; then
  echo "Checking Custom_Clash.ini ..."
  tmp_ruleset_file="$(mktemp)"
  trap 'rm -f "$tmp_ruleset_file"' EXIT

  # collect ruleset names (text before first comma on ruleset= lines)
  grep -E '^ruleset=' "$INI_FILE" | sed -E 's/^ruleset=([^,]+).*/\1/' | sed 's/^[ \t]*//;s/[ \t]*$//' > "$tmp_ruleset_file" || true

  # check custom_proxy_group names exist as a ruleset
  while IFS= read -r line; do
    grp=$(echo "$line" | sed -E 's/^custom_proxy_group=([^`]+).*/\1/')
    grp_trim=$(echo "$grp" | sed 's/^[ \t]*//;s/[ \t]*$//')
    [ -z "$grp_trim" ] && continue
    if ! grep -Fxq "$grp_trim" "$tmp_ruleset_file"; then
      echo "  [ERROR] custom_proxy_group name not found in ruleset list: '$grp_trim'"
      errors=$((errors+1))
    fi
  done < <(grep -E '^custom_proxy_group=' "$INI_FILE" || true)

  # check ruleset sources: allow []GEOSITE/[]GEOIP, http(s) URLs, or local file paths (must exist)
  while IFS= read -r line; do
    src=$(echo "$line" | sed -E 's/^ruleset=[^,]+,([^,]+).*/\1/')
    src_trim=$(echo "$src" | sed 's/^[ \t]*//;s/[ \t]*$//')
    [ -z "$src_trim" ] && continue
    if echo "$src_trim" | grep -Eq '^\['; then
      # e.g. []GEOSITE or []GEOIP — skip checks
      continue
    fi
    if echo "$src_trim" | grep -Eq '^https?://'; then
      # remote URL — skip existence check
      continue
    fi
    # treat as local path relative to ROOT_DIR
    localpath="${ROOT_DIR}/${src_trim}"
    if [ ! -f "$localpath" ]; then
      echo "  [ERROR] ruleset source file not found (expected local): '$src_trim' (checked: $localpath)"
      errors=$((errors+1))
    fi
  done < <(grep -E '^ruleset=' "$INI_FILE" || true)
else
  echo "  [WARN] Custom_Clash.ini not found at ${INI_FILE}"
fi

if [ "$errors" -ne 0 ]; then
  echo
  echo "Validation failed: $errors issue(s) found."
  exit 2
else
  echo "Validation passed."
  exit 0
fi