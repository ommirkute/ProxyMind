# OWASP Juice Shop profile for bench/run.sh. Registers two users.
APP_NAME=juice-shop
APP_URL=${APP_URL:-http://127.0.0.1:3000}
APP_SERVICE=juice-shop
APP_READY=/rest/admin/application-version

app_browse() {
  for u in alice bob; do
    pw="Bench-${u}-Passw0rd"
    "${CURL[@]}" -H 'Content-Type: application/json' \
      -d "{\"email\":\"bench-$u@juice.test\",\"password\":\"$pw\",\"passwordRepeat\":\"$pw\",\"securityQuestion\":{\"id\":1},\"securityAnswer\":\"x\"}" \
      "$APP_URL/api/Users" >/dev/null
    login=$("${CURL[@]}" -H 'Content-Type: application/json' -d "{\"email\":\"bench-$u@juice.test\",\"password\":\"$pw\"}" "$APP_URL/rest/user/login")
    tok=$(printf '%s' "$login" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
    bid=$(printf '%s' "$login" | sed -n 's/.*"bid":\([0-9]*\).*/\1/p')
    A=(-H "Authorization: Bearer $tok" -b "token=$tok")
    "${CURL[@]}" "${A[@]}" "$APP_URL/rest/user/whoami" >/dev/null
    "${CURL[@]}" "${A[@]}" "$APP_URL/rest/basket/$bid" >/dev/null
    "${CURL[@]}" "${A[@]}" "$APP_URL/api/Products" >/dev/null
    "${CURL[@]}" "${A[@]}" "$APP_URL/rest/products/search?q=apple" >/dev/null
    "${CURL[@]}" "${A[@]}" "$APP_URL/api/Feedbacks" >/dev/null
  done
}

APP_IDENTITIES=("alice /rest/user/whoami 1" "bob /rest/user/whoami 2")
