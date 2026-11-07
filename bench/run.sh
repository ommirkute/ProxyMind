#!/usr/bin/env bash
# Benchmark ProxyMind on a deliberately vulnerable app and score the result.
#
#   bench/run.sh vampi | juice-shop | vulnshop
#
# Steps: start the app (Docker compose, unless BENCH_NO_START=1), browse it
# through the proxy as two users, capture their sessions, crawl, run the
# model-free access-control pass (`bench auto`), the passive scan, and an
# optional agent (BENCH_AGENT: a command run with PROXYMIND_PROJECT set),
# then score against bench/ground-truth/<app>.yaml.
#
# Results: $OUT/<app>.json (score) and $OUT/<app>.md (summary + report).
# Run only on an isolated machine: these apps are vulnerable on purpose.
set -euo pipefail

APP=${1:?usage: bench/run.sh <app>}
HERE=$(cd "$(dirname "$0")" && pwd)
PM=${PROXYMIND:-proxymind}
PROXY_PORT=${PROXY_PORT:-18080}
WORK=${WORK:-$(mktemp -d)}
OUT=${OUT:-$WORK/results}
mkdir -p "$OUT"
P=("$PM" -p "$WORK/$APP.pmproj" --home "$WORK/home")
CURL=(curl -s --noproxy "" -x "http://127.0.0.1:$PROXY_PORT")
PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null || true' EXIT

[ -f "$HERE/apps/$APP.sh" ] || { echo "unknown app $APP (see bench/apps/)"; exit 2; }
# shellcheck source=/dev/null
source "$HERE/apps/$APP.sh"
step() { printf '\n== %s\n' "$*" >&2; }

step "start $APP_NAME"
if declare -F app_start >/dev/null; then
  app_start
elif [ "${BENCH_NO_START:-0}" != 1 ]; then
  docker compose -f "$HERE/docker-compose.yml" up -d "$APP_SERVICE"
fi
for _ in $(seq 1 90); do
  curl -s --noproxy '*' -o /dev/null -f "$APP_URL$APP_READY" && break
  sleep 2
done
curl -s --noproxy '*' -o /dev/null -f "$APP_URL$APP_READY" || { echo "$APP_NAME is not answering at $APP_URL"; exit 1; }

step "browse through the proxy"
"${P[@]}" proxy --listen "127.0.0.1:$PROXY_PORT" 2>/dev/null &
PIDS+=($!)
sleep 1
app_browse
sleep 1
# The apps are throwaway and isolated, so the sweep may also run the checks
# that normally need approval (request smuggling, file upload, races).
printf 'version: 1\nengagement:\n  name: "bench %s"\nscope:\n  include: ["%s/"]\ntiers:\n  human:\n    destructive: allow\n' \
  "$APP" "$APP_URL" > "$WORK/roe.yaml"
"${P[@]}" roe use "$WORK/roe.yaml" >/dev/null

step "capture identities"
id_of() { "${P[@]}" history --path "$1" -n 500 | awk 'NR>1 {print $1}' | sort -n | sed -n "${2:-1}p"; }
for spec in "${APP_IDENTITIES[@]}"; do
  read -r who path nth <<<"$spec"
  name=${who%%:*}; role=user
  [[ $who == *:* ]] && role=${who#*:}
  "${P[@]}" identity capture "$name" --from "$(id_of "$path" "$nth")" --role "$role" >/dev/null
done
"${P[@]}" identity list >&2

step "crawl"
# In a browser when there is one (single-page apps), else links only.
"${P[@]}" crawl "$APP_URL/" --max-pages "${BENCH_CRAWL_PAGES:-60}" --browser 2>/dev/null | tail -1 >&2 ||
  "${P[@]}" crawl "$APP_URL/" --max-pages "${BENCH_CRAWL_PAGES:-60}" | tail -1 >&2

step "OAST listener (for out-of-band checks)"
# Reachable from Docker containers (docker0) and the host alike.
OAST_HOST=${BENCH_OAST_HOST:-$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || true)}
OAST_HOST=${OAST_HOST:-127.0.0.1}
"${P[@]}" oast-server --listen "$OAST_HOST:${BENCH_OAST_PORT:-18085}" >/dev/null 2>&1 &
PIDS+=($!)
sleep 1

step "automatic access-control pass"
"${P[@]}" bench auto --write-checks | tee "$OUT/$APP-auto.txt" >&2

if [ -n "${BENCH_AGENT:-}" ]; then
  step "agent: $BENCH_AGENT"
  PROXYMIND_PROJECT="$WORK/$APP.pmproj" PROXYMIND_HOME="$WORK/home" bash -c "$BENCH_AGENT" >&2
fi

step "passive scan"
"${P[@]}" scan --json > "$OUT/$APP-issues.json"
issues=$(grep -c '"check"' "$OUT/$APP-issues.json" || true)

step "score"
"${P[@]}" bench score --app "$APP" --json > "$OUT/$APP.json"
"${P[@]}" bench score --app "$APP" | tee "$OUT/$APP-score.txt" >&2
requests=$("${P[@]}" history -n 100000 | tail -n +2 | wc -l)
{
  echo "## $APP_NAME"
  echo
  echo '```'
  cat "$OUT/$APP-score.txt"
  echo '```'
  echo
  echo "Requests in project: $requests · passive issues: $issues · agent: ${BENCH_AGENT:-none (model-free baseline)}"
} > "$OUT/$APP.md"
"${P[@]}" audit verify >&2
echo "$OUT/$APP.md"
