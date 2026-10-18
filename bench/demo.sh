#!/usr/bin/env bash
# The ProxyMind demo: find and prove access-control bugs in VulnShop.
#
#   cargo build --release && PROXYMIND=./target/release/proxymind bench/demo.sh
#
# Everything runs on 127.0.0.1. Override ports with SHOP_PORT / PROXY_PORT.
set -euo pipefail

PM=${PROXYMIND:-proxymind}
SHOP_PORT=${SHOP_PORT:-8899}
PROXY_PORT=${PROXY_PORT:-8080}
WORK=${WORK:-$(mktemp -d)}
SHOP="http://127.0.0.1:$SHOP_PORT"
P=("$PM" -p "$WORK/demo.pmproj" --home "$WORK/home")
CURL=(curl -s --noproxy "" -x "http://127.0.0.1:$PROXY_PORT")

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

"${P[@]}" demo-target --listen "127.0.0.1:$SHOP_PORT" 2>/dev/null & DEMO=$!
"${P[@]}" proxy --listen "127.0.0.1:$PROXY_PORT" 2>/dev/null & PROXY=$!
trap 'kill $DEMO $PROXY 2>/dev/null || true' EXIT
sleep 1

step "1. Browse VulnShop through ProxyMind as alice, bob and admin"
for u in alice bob admin; do
  "${CURL[@]}" -c "$WORK/$u.jar" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$u\",\"password\":\"${u}123\"}" "$SHOP/api/login" >/dev/null
  "${CURL[@]}" -b "$WORK/$u.jar" "$SHOP/api/me" >/dev/null
done
"${CURL[@]}" -b "$WORK/alice.jar" "$SHOP/api/orders" >/dev/null
"${CURL[@]}" -b "$WORK/alice.jar" "$SHOP/api/orders/1001" >/dev/null
"${CURL[@]}" -b "$WORK/alice.jar" "$SHOP/api/invoices/5001" >/dev/null
"${CURL[@]}" -b "$WORK/admin.jar" "$SHOP/api/admin/users" >/dev/null
sleep 0.5
"${P[@]}" history

# Id of the Nth (oldest first) exchange whose path contains $1.
id_of() { "${P[@]}" history --path "$1" -n 100 | awk 'NR>1 {print $1}' | sort -n | sed -n "${2:-1}p"; }

step "2. Set the rules of engagement and capture the three sessions"
printf 'version: 1\nscope:\n  include: ["%s/"]\n' "$SHOP" > "$WORK/roe.yaml"
"${P[@]}" roe use "$WORK/roe.yaml"
"${P[@]}" identity capture alice --from "$(id_of /api/me 1)"
"${P[@]}" identity capture bob --from "$(id_of /api/me 2)"
"${P[@]}" identity capture admin --from "$(id_of /api/me 3)" --role admin

step "3. The app model ProxyMind built from that traffic"
"${P[@]}" model --objects

ORDER=$(id_of /api/orders/1001)
INVOICE=$(id_of /api/invoices/5001)
USERS=$(id_of /api/admin/users)

step "4. Replay alice's requests as bob and as an anonymous user"
"${P[@]}" authz check "$ORDER" --as bob
"${P[@]}" authz check "$INVOICE" --as bob
"${P[@]}" authz check "$USERS" --as bob

step "5. Record findings and let ProxyMind prove them"
"${P[@]}" findings add --title "Any user can read any order" --class idor --severity high --evidence "$ORDER"
"${P[@]}" proof authz "$ORDER" --attacker bob --finding 1
"${P[@]}" findings add --title "Users can list all accounts" --class bfla --severity high --evidence "$USERS"
"${P[@]}" proof authz "$USERS" --attacker bob --finding 2
echo "And the correctly protected invoice:"
"${P[@]}" proof authz "$INVOICE" --attacker bob || true

step "6. Score against VulnShop's known bugs, verify the audit log, write the report"
"${P[@]}" bench score
"${P[@]}" audit verify
"${P[@]}" report --out "$WORK/report.md"
echo
echo "Project: $WORK/demo.pmproj"
echo "Next: connect an agent (docs/agents.md) and ask it to find the other two bugs (VS-3, VS-4)."
