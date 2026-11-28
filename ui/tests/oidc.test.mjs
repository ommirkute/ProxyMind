// Unit tests for src/oidc.ts. Run with `npm run test:unit`.
import assert from "node:assert/strict";
import * as O from "../src/oidc.ts";

let failures = 0;
const test = (name, fn) => {
  try {
    fn();
    console.log(`  ok   ${name}`);
  } catch (e) {
    failures++;
    console.log(`  FAIL ${name}\n       ${e.message.split("\n").join("\n       ")}`);
  }
};

test("the notice is read from the query and removed from it", () => {
  assert.deepEqual(O.splitOidcNotice("?oidc_error=no_account"), { error: "no_account", linked: false, rest: "" });
  assert.deepEqual(O.splitOidcNotice("?a=1&oidc_linked=1"), { error: null, linked: true, rest: "?a=1" });
  assert.deepEqual(O.splitOidcNotice(""), { error: null, linked: false, rest: "" });
  assert.equal(O.splitOidcNotice("?oidc_linked=2").linked, false);
});

test("every code the server sends has a sentence, and an unknown one a plain one", () => {
  for (const code of [
    "denied", "provider_error", "provider_unreachable", "invalid_state", "invalid_token", "assurance_not_met", "no_account",
    "not_permitted", "owner_needs_local_factor", "owner_invite", "account_exists", "identity_in_use", "already_linked",
    "invalid_invite", "link_expired", "throttled", "unknown_provider", "internal",
  ]) {
    assert.ok(O.oidcErrorText(code).length > 20, code);
  }
  assert.match(O.oidcErrorText("<script>"), /did not work/);
  // Nothing from the URL is ever shown as it is.
  assert.ok(!O.oidcErrorText("<script>alert(1)</script>").includes("script"));
});

test("the start URL encodes the provider and the next path", () => {
  assert.equal(O.startUrl("op_ab", "/#/account"), "/api/v1/auth/oidc/op_ab/start?next=%2F%23%2Faccount");
  assert.equal(O.startUrl("a/b", "/"), "/api/v1/auth/oidc/a%2Fb/start?next=%2F");
});

test("group mappings accept tester and viewer and refuse owner", () => {
  assert.deepEqual(O.parseGroupRoles("pm-testers = tester\n# comment\n\nreaders=Viewer\n a b = viewer "), [
    { value: "pm-testers", role: "tester" },
    { value: "readers", role: "viewer" },
    { value: "a b", role: "viewer" },
  ]);
  for (const bad of ["g = owner", "g = admin", "g", "= tester", "g = "]) {
    assert.throws(() => O.parseGroupRoles(bad), Error, bad);
  }
  assert.throws(() => O.parseGroupRoles("g = owner"), /never owner/);
  assert.equal(O.formatGroupRoles([{ value: "x", role: "tester" }]), "x = tester");
});

test("lists are split on spaces, commas and lines", () => {
  assert.deepEqual(O.parseList("a.example, b.example\nc.example  "), ["a.example", "b.example", "c.example"]);
  assert.deepEqual(O.parseList(""), []);
});

if (failures) {
  console.log(`${failures} failed`);
  process.exit(1);
}
