# VAmPI profile for bench/run.sh. Users name1/pass1 and name2/pass2.
APP_NAME=vampi
APP_URL=${APP_URL:-http://127.0.0.1:5002}
APP_SERVICE=vampi
APP_READY=/createdb

app_browse() {
  "${CURL[@]}" "$APP_URL/createdb" >/dev/null
  for u in 1 2; do
    tok=$("${CURL[@]}" -H 'Content-Type: application/json' -d "{\"username\":\"name$u\",\"password\":\"pass$u\"}" \
      "$APP_URL/users/v1/login" | sed -n 's/.*"auth_token": *"\([^"]*\)".*/\1/p')
    A=(-H "Authorization: Bearer $tok")
    "${CURL[@]}" "${A[@]}" "$APP_URL/me" >/dev/null
    "${CURL[@]}" "${A[@]}" "$APP_URL/books/v1" >/dev/null
    "${CURL[@]}" "${A[@]}" -H 'Content-Type: application/json' -d "{\"book_title\":\"bench-book-$u\",\"secret\":\"secret-of-name$u\"}" "$APP_URL/books/v1" >/dev/null
    "${CURL[@]}" "${A[@]}" "$APP_URL/books/v1/bench-book-$u" >/dev/null
    "${CURL[@]}" "${A[@]}" "$APP_URL/users/v1/name$u" >/dev/null
  done
  "${CURL[@]}" "$APP_URL/users/v1" >/dev/null
}

# identity name, path of a request made with its credentials, nth match
APP_IDENTITIES=("name1 /me 1" "name2 /me 2")
