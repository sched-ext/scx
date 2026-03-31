#!/usr/bin/env bash
set -euo pipefail

BINDIR="${1:-./target/debug}"
PASS=0
FAIL=0
SHELLS=(bash zsh fish)

BINS=(
    scx_beerland scx_bpfland scx_cake scx_chaos scx_cosmos
    scx_flash scx_lavd scx_layered scx_mitosis scx_p2dq
    scx_pandemonium scx_rustland scx_rusty scx_tickless
    scx_wd40 scxcash
)

pass() { PASS=$((PASS + 1)); echo "  PASS  $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL  $1"; }

for bin in "${BINS[@]}"; do
    exe="$BINDIR/$bin"
    if [[ ! -x "$exe" ]]; then
        fail "$bin: binary not found at $exe"
        continue
    fi

    echo "=== $bin ==="

    # 1) --completions exits 0 and produces output for each shell
    for sh in "${SHELLS[@]}"; do
        output=$("$exe" --completions "$sh" 2>&1) || true
        if [[ -z "$output" ]]; then
            fail "$bin --completions $sh: empty output"
        else
            pass "$bin --completions $sh: produces output"
        fi
    done

    # 2) Bash completions reference the correct binary name
    bash_output=$("$exe" --completions bash 2>&1)
    if echo "$bash_output" | grep -q "$bin"; then
        pass "$bin: binary name found in bash completions"
    else
        fail "$bin: binary name NOT found in bash completions"
    fi

    # 3) --completions is hidden from --help
    help_output=$("$exe" --help 2>&1) || true
    if echo "$help_output" | grep -q "\-\-completions"; then
        fail "$bin: --completions visible in --help (should be hidden)"
    else
        pass "$bin: --completions hidden from --help"
    fi

    # 4) Completions contain at least some real options (not an empty stub)
    line_count=$(echo "$bash_output" | wc -l)
    if (( line_count > 20 )); then
        pass "$bin: bash completions have $line_count lines"
    else
        fail "$bin: bash completions suspiciously short ($line_count lines)"
    fi
done

# 5) Scheduler-specific: ValueEnum variants appear in completions
echo ""
echo "=== ValueEnum checks ==="

cake_output=$("$BINDIR/scx_cake" --completions bash 2>&1)
for val in esports gaming battery legacy default; do
    if echo "$cake_output" | grep -qi "$val"; then
        pass "scx_cake: ValueEnum '$val' in completions"
    else
        fail "scx_cake: ValueEnum '$val' NOT in completions"
    fi
done

echo ""
echo "==============================="
echo "Results: $PASS passed, $FAIL failed"
(( FAIL == 0 )) && echo "ALL TESTS PASSED" || echo "SOME TESTS FAILED"
exit $FAIL
