#!/usr/bin/env bash
# Summarize scx_cake policy benchmark artifacts into reviewable evidence.
set -Eeuo pipefail
umask 077

SCRIPT_NAME="$(basename "$0")"

usage() {
	cat <<EOF
Usage: ${SCRIPT_NAME} <policy-benchmark-dir>

Creates:
  analysis.md
  analysis_metrics.tsv
  analysis_diag.tsv

The input may be a single scx_cake_policy_bench.sh run directory, a multi-run
storm plan directory, or a scheduler-matrix directory.
EOF
}

die() {
	echo "error: $*" >&2
	exit 1
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
	usage
	exit 0
fi

ROOT="${1:-}"
[[ -n "${ROOT}" ]] || {
	usage >&2
	exit 2
}
[[ -d "${ROOT}" ]] || die "not a directory: ${ROOT}"

REPORT="${ROOT}/analysis.md"
METRICS="${ROOT}/analysis_metrics.tsv"
DIAG="${ROOT}/analysis_diag.tsv"
IS_MATRIX=0
if find "${ROOT}" -mindepth 1 -maxdepth 1 -type d -name '*_scheduler-*' | grep -q .; then
	IS_MATRIX=1
fi

md_escape() {
	local s="${1:-}"
	s="${s//|/\\|}"
	printf '%s' "${s}"
}

variant_from_dir() {
	local base
	base="$(basename "$1")"
	if [[ "${base}" =~ ^(.*)_seq[0-9]+$ ]]; then
		base="${BASH_REMATCH[1]}"
	fi
	if [[ "${base}" =~ _scheduler-(.+)$ ]]; then
		printf '%s' "${BASH_REMATCH[1]}"
	elif [[ "${base}" =~ _storm-([a-z]+) ]]; then
		printf '%s' "${BASH_REMATCH[1]}"
	else
		printf 'unknown'
	fi
}

seq_from_dir() {
	local base
	base="$(basename "$1")"
	if [[ "${base}" =~ _seq([0-9]+) ]]; then
		printf '%s' "${BASH_REMATCH[1]}"
	else
		printf '-'
	fi
}

suite_dir_for_run() {
	local run_dir="$1"
	if [[ -d "${run_dir}/suite" ]]; then
		find "${run_dir}/suite" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1
	else
		printf ''
	fi
}

summary_for_suite() {
	local suite_dir="$1"
	if [[ -n "${suite_dir}" && -f "${suite_dir}/summary.md" ]]; then
		printf '%s' "${suite_dir}/summary.md"
	else
		printf ''
	fi
}

status_count() {
	local summary="$1"
	local status="$2"
	[[ -f "${summary}" ]] || {
		printf '0'
		return
	}
	grep -Ec "\\|[[:space:]]+[^|]+[[:space:]]+\\|[[:space:]]+${status}([[:space:]][^|]*)?[[:space:]]+\\|" "${summary}" || true
}

elapsed_to_seconds() {
	local file="$1"
	local elapsed
	elapsed="$(awk -F': ' '/Elapsed \(wall clock\)/ { print $2; exit }' "${file}" 2>/dev/null || true)"
	[[ -n "${elapsed}" ]] || {
		printf ''
		return
	}
	awk -v t="${elapsed}" '
		BEGIN {
			n = split(t, a, ":")
			if (n == 3)
				s = a[1] * 3600 + a[2] * 60 + a[3]
			else if (n == 2)
				s = a[1] * 60 + a[2]
			else
				s = t + 0
			printf "%.6f", s
		}'
}

first_time_file() {
	local run_dir="$1"
	local file
	[[ -d "${run_dir}/perf" ]] || {
		printf ''
		return
	}
	for pattern in 'repeat_*_stat.time.txt' 'repeat_*_time.time.txt' '*.time.txt' '*.bpf_time.txt' '*.sched_time.txt'; do
		file="$(find "${run_dir}/perf" -maxdepth 1 -type f -name "${pattern}" | sort | head -n 1)"
		if [[ -n "${file}" ]]; then
			printf '%s' "${file}"
			return
		fi
	done
	printf ''
}

first_perf_stat_csv() {
	local run_dir="$1"
	[[ -d "${run_dir}/perf" ]] || {
		printf ''
		return
	}
	find "${run_dir}/perf" -maxdepth 1 -type f -name '*.perf_stat.csv' | sort | head -n 1
}

perf_stat_value() {
	local csv="$1"
	local event="$2"
	[[ -f "${csv}" ]] || {
		printf ''
		return
	}
	awk -F',' -v ev="${event}" '
		$3 == ev {
			gsub(/^[ \t]+|[ \t]+$/, "", $1)
			print $1
			exit
		}' "${csv}"
}

bench_log_file() {
	local run_dir="$1"
	if [[ -f "${run_dir}/benchmark.log" ]]; then
		printf '%s' "${run_dir}/benchmark.log"
	elif [[ -d "${run_dir}/logs" ]]; then
		find "${run_dir}/logs" -maxdepth 1 -type f \
			\( -name 'repeat_1_stat.log' -o -name 'repeat_1_time.log' -o -name 'repeat_1_sched.log' -o -name '*.log' \) |
			sort |
			head -n 1
	else
		printf ''
	fi
}

normalize_benchmark_name() {
	local bench="$1"
	if [[ "${bench}" =~ ^(.+)\.[[:alnum:]]{6}$ ]]; then
		bench="${BASH_REMATCH[1]}"
	fi
	printf '%s' "${bench}"
}

output_metric() {
	local bench="$1"
	local log="$2"
	local value=''
	local metric='output'
	local direction='higher'
	local unit='value'

	[[ -f "${log}" ]] || {
		printf '\t\t\t'
		return
	}

	case "${bench}" in
		perf-sched-fork|perf-sched-thread)
			value="$(awk '/^[[:space:]]*[0-9]+([.][0-9]+)?[[:space:]]*$/ { v=$1 } END { print v }' "${log}")"
			metric='runtime'
			direction='lower'
			unit='s'
			;;
		perf-memcpy)
			value="$(awk '
				/bytes\/sec/ {
					for (i = 1; i <= NF; i++) {
						if ($i ~ /^[0-9]+([.][0-9]+)?$/)
							v = $i
					}
				}
				END { print v }' "${log}")"
			metric='throughput'
			direction='higher'
			unit='bytes/s'
			;;
		stress-ng-cpu-cache-mem)
			value="$(awk '
				/cache[[:space:]]+[0-9]/ && /bogo ops\/s/ {
					for (i = 1; i <= NF; i++)
						if ($i ~ /^[0-9]+([.][0-9]+)?$/)
							v = $i
				}
				END { print v }' "${log}")"
			metric='cache_ops'
			direction='higher'
			unit='bogo_ops/s'
			;;
		prime-numbers)
			value="$(awk '
				/cpu[[:space:]]+[0-9]/ && /bogo ops\/s/ {
					for (i = 1; i <= NF; i++)
						if ($i ~ /^[0-9]+([.][0-9]+)?$/)
							v = $i
				}
				END { print v }' "${log}")"
			metric='prime_ops'
			direction='higher'
			unit='bogo_ops/s'
			;;
		argon2-hashing)
			value="$(awk -F': ' '/Seconds/ { v=$2 } END { gsub(/^[ \t]+|[ \t]+$/, "", v); print v }' "${log}")"
			metric='runtime'
			direction='lower'
			unit='s'
			;;
	esac

	printf '%s\t%s\t%s\t%s\n' "${metric}" "${value}" "${direction}" "${unit}"
}

diag_file_for_run() {
	local run_dir="$1"
	if [[ -d "${run_dir}/diag" ]]; then
		find "${run_dir}/diag" -type f -name 'cake_diag_latest.txt' | sort | tail -n 1
	else
		printf ''
	fi
}

extract_kv() {
	local line="$1"
	local key="$2"
	awk -v line="${line}" -v key="${key}" '
		BEGIN {
			n = split(line, a, " ")
			for (i = 1; i <= n; i++) {
				split(a[i], kv, "=")
				if (kv[1] == key) {
					print kv[2]
					exit
				}
			}
		}'
}

diag_fields() {
	local file="$1"
	local snapshot=''
	local storm=''
	local route=''
	local native=''
	local claim_fail=''
	local wake_ge5=''
	local decision=''
	local trained=''

	if [[ -f "${file}" ]]; then
		snapshot="$(grep -E '^live_data\.snapshot:' "${file}" | tail -n 1 || true)"
		storm="$(grep -E '^accelerator\.life\.storm_guard:' "${file}" | tail -n 1 || true)"
		trained="$(extract_kv "${snapshot}" 'trained')"
		route="$(extract_kv "${snapshot}" 'route_pred60')"
		native="$(extract_kv "${snapshot}" 'native60')"
		claim_fail="$(extract_kv "${snapshot}" 'score_claim_fail60')"
		wake_ge5="$(extract_kv "${snapshot}" 'wake_ge5ms60')"
		decision="$(sed -nE 's/.*decisions=\[([^]]*)\].*/\1/p' <<<"${storm}")"
	fi

	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
		"${route:-}" "${native:-}" "${claim_fail:-}" "${wake_ge5:-}" \
		"${trained:-}" "${decision:-}" "${file:-}"
}

collect_run_dirs() {
	if [[ -d "${ROOT}/suite" ]]; then
		printf '%s\n' "${ROOT}"
	else
		find "${ROOT}" -mindepth 1 -maxdepth 1 -type d \
			\( -name '*_storm-*' -o -name '*_scheduler-*' \) |
			while IFS= read -r path; do
				base="$(basename "${path}")"
				seq="$(sed -nE 's/.*_seq([0-9]+)(\..*)?$/\1/p' <<<"${base}")"
				if [[ -z "${seq}" ]]; then
					seq=999999
				fi
				printf '%06d\t%s\n' "$((10#${seq}))" "${path}"
			done |
			sort -k1,1n -k2,2 |
			cut -f2-
	fi
}

collect_metrics() {
	printf 'seq\tvariant\tbenchmark\tmetric\tvalue\tdirection\tunit\tsource\twall_seconds\toutput_metric\toutput_value\toutput_direction\toutput_unit\ttask_clock_ms\tcontext_switches\tcpu_migrations\trun_dir\n' >"${METRICS}"
	printf 'seq\tvariant\tbenchmark\troute_pred60\tnative60\tscore_claim_fail60\twake_ge5ms60\ttrained\tstorm_decisions\tdiag_file\trun_dir\n' >"${DIAG}"

	while IFS= read -r policy_dir; do
		[[ -n "${policy_dir}" ]] || continue
		local_variant="$(variant_from_dir "${policy_dir}")"
		local_seq="$(seq_from_dir "${policy_dir}")"
		suite_dir="$(suite_dir_for_run "${policy_dir}")"
		[[ -n "${suite_dir}" && -d "${suite_dir}/runs" ]] || continue

		while IFS= read -r bench_dir; do
			[[ -n "${bench_dir}" ]] || continue
			bench="$(basename "${bench_dir}")"
			bench="${bench#*_}"
			bench="$(normalize_benchmark_name "${bench}")"
			perf_csv="$(first_perf_stat_csv "${bench_dir}")"
			time_file="$(first_time_file "${bench_dir}")"
			wall=''
			if [[ -n "${time_file}" ]]; then
				wall="$(elapsed_to_seconds "${time_file}")"
			fi

			task_clock="$(perf_stat_value "${perf_csv}" 'task-clock')"
			context_switches="$(perf_stat_value "${perf_csv}" 'context-switches')"
			cpu_migrations="$(perf_stat_value "${perf_csv}" 'cpu-migrations')"

			log_file="$(bench_log_file "${bench_dir}")"
			IFS=$'\t' read -r out_metric out_value out_direction out_unit < <(output_metric "${bench}" "${log_file}")

			metric='task_clock'
			value="${task_clock}"
			direction='lower'
			unit='ms'
			source="${perf_csv}"
			if [[ -n "${wall}" ]]; then
				metric='wall_time'
				value="${wall}"
				direction='lower'
				unit='s'
				source="${time_file}"
			elif [[ -n "${out_value}" ]]; then
				metric="${out_metric}"
				value="${out_value}"
				direction="${out_direction}"
				unit="${out_unit}"
				source="${log_file}"
			fi

			printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
				"${local_seq}" "${local_variant}" "${bench}" "${metric}" "${value}" "${direction}" \
				"${unit}" "${source}" "${wall}" "${out_metric}" "${out_value}" "${out_direction}" \
				"${out_unit}" "${task_clock}" "${context_switches}" "${cpu_migrations}" "${bench_dir}" \
				>>"${METRICS}"

			diag_file="$(diag_file_for_run "${bench_dir}")"
			IFS=$'\t' read -r route native claim_fail wake_ge5 trained decision diag_path < <(diag_fields "${diag_file}")
			printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
				"${local_seq}" "${local_variant}" "${bench}" "${route}" "${native}" \
				"${claim_fail}" "${wake_ge5}" "${trained}" "${decision}" "${diag_path}" "${bench_dir}" \
				>>"${DIAG}"
		done < <(find "${suite_dir}/runs" -mindepth 1 -maxdepth 1 -type d | sort)
	done < <(collect_run_dirs)
}

write_run_inventory() {
	{
		echo '| Seq | Variant | Passed | Failed | Skipped | Suite |'
		echo '|---:|---|---:|---:|---:|---|'
		while IFS= read -r policy_dir; do
			[[ -n "${policy_dir}" ]] || continue
			variant="$(variant_from_dir "${policy_dir}")"
			seq_no="$(seq_from_dir "${policy_dir}")"
			suite_dir="$(suite_dir_for_run "${policy_dir}")"
			summary="$(summary_for_suite "${suite_dir}")"
			passed="$(status_count "${summary}" 'passed')"
			failed="$(status_count "${summary}" 'failed')"
			skipped="$(status_count "${summary}" 'skipped')"
			printf '| %s | %s | %s | %s | %s | `%s` |\n' \
				"$(md_escape "${seq_no}")" "$(md_escape "${variant}")" "${passed}" "${failed}" "${skipped}" \
				"$(md_escape "${suite_dir}")"
		done < <(collect_run_dirs)
	} >>"${REPORT}"
}

write_skips() {
	local tmp
	tmp="$(mktemp -p "${ROOT}" ".analysis_skips.XXXXXX")"
	cleanup_skips_tmp() {
		rm -f "${tmp}"
	}
	trap cleanup_skips_tmp RETURN

	while IFS= read -r policy_dir; do
		[[ -n "${policy_dir}" ]] || continue
		suite_dir="$(suite_dir_for_run "${policy_dir}")"
		summary="$(summary_for_suite "${suite_dir}")"
		[[ -f "${summary}" ]] || continue
		awk -F'|' '
			$3 ~ /skipped/ {
				gsub(/^[ \t]+|[ \t]+$/, "", $2)
				gsub(/`/, "", $2)
				if ($2 != "Benchmark")
					print $2
			}' "${summary}" >>"${tmp}"
	done < <(collect_run_dirs)

	if [[ -s "${tmp}" ]]; then
		echo '| Skipped workload | Count |' >>"${REPORT}"
		echo '|---|---:|' >>"${REPORT}"
		sort "${tmp}" | uniq -c | awk '{ c=$1; $1=""; sub(/^ /, ""); printf "| %s | %d |\n", $0, c }' >>"${REPORT}"
	else
		echo 'No skipped workloads were reported.' >>"${REPORT}"
	fi
	rm -f "${tmp}"
	trap - RETURN
}

write_primary_metrics() {
	{
		echo '| Seq | Variant | Benchmark | Primary metric | Value | Unit | Direction | task-clock ms | cs | migrations |'
		echo '|---:|---|---|---|---:|---|---|---:|---:|---:|'
		awk -F'\t' '
			NR > 1 {
				printf "| %s | %s | %s | %s | %.6g | %s | %s | %s | %s | %s |\n", \
					$1, $2, $3, $4, $5, $7, $6, ($14 == "" ? "-" : $14), \
					($15 == "" ? "-" : $15), ($16 == "" ? "-" : $16)
			}' "${METRICS}" | sort
	} >>"${REPORT}"
}

write_delta_table() {
	{
		echo '| Benchmark | Variant | Mean | Unit | Direction | Baseline | Delta vs baseline | Interpretation |'
		echo '|---|---|---:|---|---|---:|---:|---|'
		awk -F'\t' '
			NR == 1 { next }
			$5 == "" { next }
			{
				key = $3 SUBSEP $2
				sum[key] += $5
				cnt[key] += 1
				bench[$3] = 1
				variant[$2] = 1
				dir[$3] = $6
				unit[$3] = $7
				if (!(($3) in first_guard))
					first_guard[$3] = $2
			}
			END {
				for (b in bench) {
					if (cnt[b SUBSEP "shadow"] > 0)
						base_guard = "shadow"
					else if (cnt[b SUBSEP "cake-baseline"] > 0)
						base_guard = "cake-baseline"
					else if (cnt[b SUBSEP "scx_cake"] > 0)
						base_guard = "scx_cake"
					else
						base_guard = first_guard[b]
					base = sum[b SUBSEP base_guard] / cnt[b SUBSEP base_guard]
					for (g in variant) {
						k = b SUBSEP g
						if (!(k in cnt))
							continue
						mean = sum[k] / cnt[k]
						if (base == 0)
							pct = 0
						else if (dir[b] == "higher")
							pct = (mean - base) * 100 / base
						else
							pct = (base - mean) * 100 / base
						label = (pct >= 0) ? "better" : "worse"
						printf "| %s | %s | %.6g | %s | %s | %.6g | %.2f%% | %s than %s |\n", \
							b, g, mean, unit[b], dir[b], base, pct, label, base_guard
					}
				}
			}' "${METRICS}" | sort
	} >>"${REPORT}"
}

write_diag_table() {
	{
		echo '| Seq | Variant | Benchmark | route_pred60 | native60 | claim_fail60 | wake_ge5ms60 | trained | storm decisions |'
		echo '|---:|---|---|---:|---:|---:|---:|---:|---|'
		awk -F'\t' '
			NR > 1 {
				printf "| %s | %s | %s | %s | %s | %s | %s | %s | %s |\n", \
					$1, $2, $3, ($4 == "" ? "-" : $4), ($5 == "" ? "-" : $5), \
					($6 == "" ? "-" : $6), ($7 == "" ? "-" : $7), ($8 == "" ? "-" : $8), \
					($9 == "" ? "-" : $9)
			}' "${DIAG}" | sort
	} >>"${REPORT}"
}

collect_metrics

{
	echo '# scx Benchmark Analysis'
	echo
	echo "Source: \`${ROOT}\`"
	echo
	echo '## How To Read This'
	echo
	if [[ "${IS_MATRIX}" == "1" ]]; then
		echo '- Matrix runs compare scheduler or Cake-config variants on the same benchmark sequence.'
		echo '- Cake variants collect Cake diagnostics; sibling schedulers provide benchmark and perf baselines only.'
		echo '- Use sibling scheduler wins to identify workload shapes Cake should learn from, then use Cake diagnostics to explain Cake-specific decisions.'
	else
		echo '- `shadow` is the record-only storm-guard control: it computes the candidate decision but should not change CPU placement.'
		echo '- Use a balanced plan such as `shadow,shield,shield,shadow` when judging whether `shield` really helped; fixed one-pass ordering can mix policy effects with cache, thermal, and benchmark warmup effects.'
	fi
	echo '- `wall_time` is preferred when present because the original comparison chart is time-based. Older captures fall back to benchmark output or `perf stat` task-clock.'
	echo '- Skipped optional workloads mean the run cannot yet explain the full original chart for NAMD, y-cruncher, FFmpeg, xz, Blender, or x265.'
	echo
	echo '## Run Inventory'
	echo
} >"${REPORT}"

write_run_inventory

{
	echo
	echo '## Optional Workload Coverage'
	echo
} >>"${REPORT}"
write_skips

{
	echo
	echo '## Primary Metrics'
	echo
} >>"${REPORT}"
write_primary_metrics

{
	echo
	echo '## Delta Table'
	echo
} >>"${REPORT}"
write_delta_table

{
	echo
	echo '## Diagnostic Signals'
	echo
} >>"${REPORT}"
write_diag_table

{
	echo
	echo '## Next Benchmark Command'
	echo
	echo
	echo '```bash'
	if [[ "${IS_MATRIX}" == "1" ]]; then
		echo 'sudo scheds/rust/scx_cake/bench/scx_cake_scheduler_matrix.sh --schedulers cake,pandemonium,lavd,p2dq,flash --all'
	else
		echo 'sudo scheds/rust/scx_cake/bench/scx_cake_policy_bench.sh --storm-abba --all'
	fi
	echo '```'
	echo
	echo 'For the original chart workloads, configure the optional environment variables printed by the suite (`YCRUNCHER_CMD`, `NAMD_CONFIG`, `FFMPEG_BUILD_CMD`, `XZ_INPUT`, `BLENDER_CMD` or `BLENDER_SCENE`, and `X265_INPUT`) before running the same command.'
} >>"${REPORT}"

echo "analysis: ${REPORT}"
echo "metrics:  ${METRICS}"
echo "diag:     ${DIAG}"
