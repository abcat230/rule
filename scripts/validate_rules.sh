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

echo "=== Starting validation ==="
echo "Scanning .list files under ${RULE_DIR} ..."
echo "Step 1: Checking rule syntax and format..."

shopt -s nullglob
for f in "${RULE_DIR}"/*.list; do
  echo "  Checking file: $(basename "$f")"
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

# --- Duplicate checks: within each .list and across .list files ---
echo "Step 2: Checking for duplicate rules..."
tmp_all_rules="$(mktemp)"
trap 'rm -f "$tmp_all_rules"' EXIT

echo "  Checking for duplicates within files..."
for f in "${RULE_DIR}"/*.list; do
  tmp_perfile="$(mktemp)"
  # extract non-empty non-comment trimmed lines into tmp_perfile and tmp_all_rules
  while IFS= read -r ln; do
    ln_no_comment=$(echo "$ln" | sed 's/#.*$//')
    ln_trim=$(echo "$ln_no_comment" | sed 's/^[ \t]*//;s/[ \t]*$//')
    [ -z "$ln_trim" ] && continue
    echo "$ln_trim" >> "$tmp_perfile"
    printf '%s\t%s\n' "$ln_trim" "$(basename "$f")" >> "$tmp_all_rules"
  done < "$f"

  # duplicates within the same file
  if [ -s "$tmp_perfile" ]; then
    dup=$(sort "$tmp_perfile" | uniq -d || true)
    if [ -n "$dup" ]; then
      echo "  [ERROR] duplicate rule(s) inside $(basename "$f"):"
      echo "$dup" | sed 's/^/    - /'
      errors=$((errors+1))
    fi
  fi
  rm -f "$tmp_perfile"
done

# duplicates across different files
echo "  Checking for duplicates across files..."
if [ -s "$tmp_all_rules" ]; then
  crossdup=$(sort "$tmp_all_rules" | awk -F'\t' '
    {
      if (files[$1]=="") files[$1]=$2;
      else {
        n=split(files[$1],arr,",");
        found=0;
        for(i=1;i<=n;i++){ if (arr[i]==$2) { found=1; break } }
        if (!found) files[$1]=files[$1]","$2;
      }
    }
    END {
      for (r in files) {
        n=split(files[r],arr,",");
        if (n>1) print r "\t" files[r];
      }
    }' || true)

  if [ -n "$crossdup" ]; then
    echo "  [ERROR] duplicate rule(s) across .list files (rule -> files):"
    echo "$crossdup" | while IFS=$'\t' read -r rule files; do
      echo "    - $rule -> $files"
    done
    errors=$((errors+1))
  fi
fi
# --- end duplicate checks ---

# Validate Custom_Clash.ini for basic correctness and linkage to rulesets and node groups
echo "Step 3: Validating Custom_Clash.ini configuration..."
INI_FILE="${ROOT_DIR}/config/Clash/Custom_Clash.ini"
if [ -f "$INI_FILE" ]; then
  echo "  Checking file structure and syntax..."
  tmp_ruleset_file="$(mktemp)"
  tmp_custom_lines="$(mktemp)"
  tmp_all_groups="$(mktemp)"
  tmp_node_groups="$(mktemp)"
  trap 'rm -f "$tmp_ruleset_file" "$tmp_custom_lines" "$tmp_all_groups" "$tmp_node_groups" "$tmp_all_rules"' EXIT

  # collect ruleset names (text before first comma on ruleset= lines)
  grep -E '^ruleset=' "$INI_FILE" | sed -E 's/^ruleset=([^,]+).*/\1/' | sed 's/^[ \t]*//;s/[ \t]*$//' > "$tmp_ruleset_file" || true

  # collect custom_proxy_group lines with line numbers
  grep -nE '^custom_proxy_group=' "$INI_FILE" > "$tmp_custom_lines" || true

  # determine first "Node" header line (if any) - comment lines like "; Node" or "# Node"
  node_header_lineno=$(grep -nE '^[[:space:]]*[;#].*Node' "$INI_FILE" | head -n1 | cut -d: -f1 || true)

  # build list of all custom group names and node group names (those after Node header)
  while IFS=: read -r lineno line; do
    # extract only the group name (text before first backtick ` )
    grp_full=$(echo "$line" | sed -E 's/^custom_proxy_group=//')
    grp_name=$(echo "$grp_full" | awk -F'`' '{print $1}' | sed -E 's/^[ \t]*//;s/[ \t]*$//')
    [ -z "$grp_name" ] && continue
    echo "$grp_name" >> "$tmp_all_groups"
    # if line is after node header, it's a node definition
    if [ -n "$node_header_lineno" ] && [ "$lineno" -gt "$node_header_lineno" ]; then
      echo "$grp_name" >> "$tmp_node_groups"
    fi
  done < "$tmp_custom_lines"

  echo "  Checking ruleset definitions..."
  # check duplicates in ruleset list -> INFO only (duplicates allowed)
  if [ -s "$tmp_ruleset_file" ]; then
    dup_rules=$(sort "$tmp_ruleset_file" | uniq -d || true)
    if [ -n "$dup_rules" ]; then
      echo "  [INFO] duplicate ruleset name(s) found (allowed):"
      echo "$dup_rules" | sed 's/^/    - /'
      # no error increment
    fi
  fi

  echo "  Checking custom proxy group definitions..."
  # check duplicates in custom_proxy_group names
  if [ -s "$tmp_all_groups" ]; then
    dup_groups=$(sort "$tmp_all_groups" | uniq -d || true)
    if [ -n "$dup_groups" ]; then
      echo "  [ERROR] duplicate custom_proxy_group name(s) found:"
      echo "$dup_groups" | sed 's/^/    - /'
      errors=$((errors+1))
    fi
  fi

  # validate option references in flow / selector groups (those BEFORE Node header)
  # allowed terminal actions for []-options
  allow_actions="DIRECT REJECT NULL FINAL"

  while IFS=: read -r lineno line; do
    # skip node definitions (we validate options only for groups before Node header)
    if [ -n "$node_header_lineno" ] && [ "$lineno" -gt "$node_header_lineno" ]; then
      continue
    fi

    grp_full=$(echo "$line" | sed -E 's/^custom_proxy_group=//')
    # split by backtick, get fields after first two (mode and possibly others)
    # use awk to split
    fields=$(echo "$grp_full" | awk -F'`' '{
      out="";
      for(i=2;i<=NF;i++){ out=out "|" $i }
      sub(/^\|/,"",out); print out
    }')
    # iterate tokens separated by '|'
    IFS='|' read -r -a toks <<< "$(echo "$fields")"
    for tok in "${toks[@]}"; do
      # interested only tokens that start with []
      if echo "$tok" | grep -qE '^\[\]'; then
        ref=$(echo "$tok" | sed -E 's/^\[\]//; s/[[:space:]]*$//')
        [ -z "$ref" ] && continue
        # allow direct/reject/final/null
        if echo "$allow_actions" | grep -q -w "$ref"; then
          continue
        fi
        # if referenced name exists in node groups OR ruleset names, OK
        if grep -Fxq "$ref" "$tmp_node_groups" || grep -Fxq "$ref" "$tmp_ruleset_file"; then
          continue
        fi
        echo "  [ERROR] custom_proxy_group option references non-existent node/ruleset at line $lineno: '[]$ref'"
        errors=$((errors+1))
      fi
    done
  done < "$tmp_custom_lines"

  echo "  Validating ruleset URLs and file paths..."
  # check ruleset sources: allow []GEOSITE/[]GEOIP, http(s) URLs, or local file paths (must exist)
  while IFS= read -r line; do
    src=$(echo "$line" | sed -E 's/^ruleset=[^,]+,([^,]+).*/\1/')
    src_trim=$(echo "$src" | sed 's/^*//;s/*$//')
    [ -z "$src_trim" ] && continue
    
    if echo "$src_trim" | grep -Eq '^\['; then
      # e.g. []GEOSITE or []GEOIP — skip checks
      continue
    fi
    
    # Validate URLs and check for 404 responses
    if echo "$src_trim" | grep -Eq '^https?://'; then
      if ! echo "$src_trim" | grep -Eq '^https://'; then
        echo "  [ERROR] ruleset URL must use HTTPS: '$src_trim'"
        errors=$((errors+1))
        continue
      fi
      
      # Check if URL is accessible (not 404)
      if ! curl --silent --head --fail "$src_trim" >/dev/null 2>&1; then
        echo "    [ERROR] ruleset URL not accessible (HTTP error): '$src_trim'"
        errors=$((errors+1))
        continue
      fi

      # Known good domains and patterns
      if echo "$src_trim" | grep -Eq '^https://raw\.githubusercontent\.com/[^/]+/[^/]+/(main|master|refs/heads/[^/]+)/'; then
        # GitHub raw content URL - valid pattern
        continue
      elif echo "$src_trim" | grep -Eq '^https://(cdn\.jsdelivr\.net/gh/|gist\.githubusercontent\.com/)'; then
        # Other known good CDNs
        continue
      else
        echo "  [ERROR] ruleset URL not from known trusted source: '$src_trim'"
        echo "         Allowed patterns:"
        echo "         - https://raw.githubusercontent.com/USER/REPO/(main|master|refs/heads/BRANCH)/PATH"
        echo "         - https://cdn.jsdelivr.net/gh/USER/REPO@VERSION/PATH"
        echo "         - https://gist.githubusercontent.com/USER/GIST/raw/VERSION/PATH"
        errors=$((errors+1))
      fi
    else
      # treat as local path relative to ROOT_DIR
      localpath="${ROOT_DIR}/${src_trim}"
      if [ ! -f "$localpath" ]; then
        echo "  [ERROR] ruleset source file not found (expected local): '$src_trim' (checked: $localpath)"
        errors=$((errors+1))
      fi
    fi
  done < <(grep -E '^ruleset=' "$INI_FILE" || true)
else
  echo "  [WARN] Custom_Clash.ini not found at ${INI_FILE}"
fi

echo "=== Validation complete ==="
if [ "$errors" -ne 0 ]; then
  echo
  echo "❌ Validation failed: $errors issue(s) found."
  exit 2
else
  echo "✅ All checks passed successfully."
  exit 0
fi