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

if [ "$errors" -ne 0 ]; then
  echo
  echo "Validation failed: $errors issue(s) found."
  exit 2
else
  echo "Validation passed."
  exit 0
fi