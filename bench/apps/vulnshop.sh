# VulnShop profile for bench/run.sh (built into proxymind; no Docker).
APP_NAME=vulnshop
APP_URL=${APP_URL:-http://127.0.0.1:8899}
APP_SERVICE=
APP_READY=/

app_start() {
  "${P[@]}" demo-target --listen "${APP_URL#http://}" 2>/dev/null &
  PIDS+=($!)
}

app_browse() {
  for u in alice bob admin; do
    "${CURL[@]}" -c "$WORK/$u.jar" -H 'Content-Type: application/json' \
      -d "{\"username\":\"$u\",\"password\":\"${u}123\"}" "$APP_URL/api/login" >/dev/null
    "${CURL[@]}" -b "$WORK/$u.jar" "$APP_URL/api/me" >/dev/null
    "${CURL[@]}" -b "$WORK/$u.jar" "$APP_URL/api/orders" >/dev/null
  done
  "${CURL[@]}" -b "$WORK/alice.jar" "$APP_URL/api/orders/1001" >/dev/null
  "${CURL[@]}" -b "$WORK/bob.jar" "$APP_URL/api/orders/2001" >/dev/null
  "${CURL[@]}" -b "$WORK/alice.jar" "$APP_URL/api/invoices/5001" >/dev/null
  "${CURL[@]}" -b "$WORK/admin.jar" "$APP_URL/api/admin/users" >/dev/null
  "${CURL[@]}" -b "$WORK/alice.jar" -d 'name=alice&message=Great+tea' "$APP_URL/api/guestbook" >/dev/null
  "${CURL[@]}" -b "$WORK/alice.jar" -d 'email=alice%40example.org' "$APP_URL/api/profile" >/dev/null
  "${CURL[@]}" -b "$WORK/alice.jar" -d 'newsletter=1' "$APP_URL/api/settings" >/dev/null
  jwt=$("${CURL[@]}" -H 'Content-Type: application/json' -d '{"username":"alice","password":"alice123"}' \
    "$APP_URL/api/login" | sed -n 's/.*"jwt":"\([^"]*\)".*/\1/p')
  "${CURL[@]}" -H "Authorization: Bearer $jwt" "$APP_URL/api/v3/profile" >/dev/null
  "${CURL[@]}" -b "$WORK/alice.jar" -H 'Content-Type: application/json' -d '{"query":"{ me { id username } }"}' \
    "$APP_URL/graphql" >/dev/null
  "${CURL[@]}" "$APP_URL/api/banner?lang=en" >/dev/null
  "${CURL[@]}" "$APP_URL/api/notice?lang=en" >/dev/null
  "${CURL[@]}" -b "$WORK/alice.jar" "$APP_URL/api/account/settings" >/dev/null
  "${CURL[@]}" -b "$WORK/alice.jar" "$APP_URL/api/account/keys" >/dev/null
  "${CURL[@]}" -H 'Content-Type: application/json' -d '{"username":"carol","password":"carol123"}' "$APP_URL/api/register" >/dev/null
  "${CURL[@]}" -H 'Content-Type: application/json' -d '{"username":"dave","password":"dave123"}' "$APP_URL/api/signup" >/dev/null
  "${CURL[@]}" -b "$WORK/alice.jar" -H 'Content-Type: application/json' -d '{"theme":"dark"}' "$APP_URL/api/preferences" >/dev/null
}

APP_IDENTITIES=("alice /api/me 1" "bob /api/me 2" "admin:admin /api/me 3")
