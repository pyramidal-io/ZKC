#!/usr/bin/env bash
# Fail closed unless the public tree exactly matches its two policy manifests.
set -euo pipefail

fail() {
  printf 'public surface error: %s\n' "$1" >&2
  exit 1
}

for policy in PUBLIC_ALLOWLIST PUBLIC_SURFACE; do
  [[ -f "$policy" ]] || fail "required policy is absent: $policy"
done

policy_entries() {
  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$1" \
    | grep -vE '^(#|$)' || true
}

allowlist="$(policy_entries PUBLIC_ALLOWLIST)"
surface="$(policy_entries PUBLIC_SURFACE)"

for policy_name in PUBLIC_ALLOWLIST PUBLIC_SURFACE; do
  duplicate="$(policy_entries "$policy_name" | LC_ALL=C sort | uniq -d | head -n 1)"
  [[ -z "$duplicate" ]] || fail "duplicate policy entry: $duplicate"
done

overlap="$(comm -12 \
  <(printf '%s\n' "$allowlist" | LC_ALL=C sort) \
  <(printf '%s\n' "$surface" | LC_ALL=C sort) \
  | head -n 1)"
[[ -z "$overlap" ]] || fail "policy overlap: $overlap"

expected="$(printf '%s\n%s\n' "$allowlist" "$surface" | LC_ALL=C sort)"
actual="$(git ls-files | LC_ALL=C sort)"
if ! diff -u <(printf '%s\n' "$expected") <(printf '%s\n' "$actual") >&2; then
  fail "tracked tree does not match PUBLIC_ALLOWLIST + PUBLIC_SURFACE"
fi

while IFS=$' \t' read -r mode _object _stage path; do
  case "$mode" in
    100644|100755) ;;
    *) fail "non-regular Git mode: $path ($mode)" ;;
  esac
done < <(git ls-files -s)

while IFS= read -r path; do
  [[ -n "$path" ]] || continue
  mode="$(git ls-files -s -- "$path" | awk '{print $1}')"
  expected_mode=100644
  if [[ "$path" == ".github/scripts/check-public-surface.sh" ]]; then
    expected_mode=100755
  fi
  [[ "$mode" == "$expected_mode" ]] \
    || fail "overlay mode mismatch: $path ($mode != $expected_mode)"
done <<< "$surface"

internal_reference='(req|epic)_[a-z0-9_]+_[0-9a-f]{8,12}|(observationatom|coordinationatom)_[0-9a-f]{8,12}|(git|dgp|vault)[.]adamas[.]network|100[.]94[.]180[.]107'
internal_reference="(^|[^[:alnum:]_])($internal_reference)([^[:alnum:]_]|$)"
if affected="$(git grep --cached -I -l -i -E "$internal_reference")"; then
  printf '%s\n' "$affected" >&2
  fail "tracked files contain internal tracker references or private endpoints"
else
  [[ $? -eq 1 ]] || fail "could not scan tracked files for internal references"
fi

while IFS= read -r workflow; do
  if ! ruby - "$workflow" <<'RUBY'
require "yaml"

class ActionPinError < StandardError; end

def validate_action_pins(node, workflow)
  case node
  when Hash
    node.each do |key, value|
      if key == "uses" &&
          (!value.is_a?(String) || !value.match?(/\A\S+@[0-9a-f]{40}\z/))
        raise ActionPinError,
              "workflow action is not pinned to forty hex digits: " \
              "#{workflow}: #{value.inspect}"
      end
      validate_action_pins(value, workflow)
    end
  when Array
    node.each { |value| validate_action_pins(value, workflow) }
  end
end

workflow = ARGV.fetch(0)
begin
  document = YAML.safe_load(
    File.read(workflow, encoding: "UTF-8"),
    permitted_classes: [],
    permitted_symbols: [],
    aliases: false
  )
  unless document.is_a?(Hash)
    raise TypeError, "top-level workflow document is not a mapping"
  end
  validate_action_pins(document, workflow)
rescue ActionPinError => error
  warn error.message
  exit 1
rescue StandardError => error
  warn "workflow YAML could not be parsed safely: " \
       "#{workflow}: #{error.class}: #{error.message}"
  exit 1
end
RUBY
  then
    fail "workflow action validation failed: $workflow"
  fi
done < <(git ls-files '.github/workflows/*.yml' '.github/workflows/*.yaml')

tracked_count="$(git ls-files | wc -l | tr -d '[:space:]')"
printf 'public surface verified: %s tracked files\n' "$tracked_count"
