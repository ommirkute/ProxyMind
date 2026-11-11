---
name: business_logic
title: Business-logic abuse
description: Find where the app trusts the client on prices, quantities, coupons, limits, roles and workflow order, and test the abuse cases a scanner can't judge.
args: focus
---
Goal: find rules the business relies on that the server doesn't enforce. {{focus}}

1. Browse the app's money and state flows first (cart, checkout, coupons, transfers, signup, profile, booking) so traffic shows every step. Then run `engage_logic`: it lists parameters that look like prices, quantities, discounts, limits, identities, roles or workflow state, each with abuse cases, and URLs that look like steps of a flow.
2. Write down each flow's intended rule before testing ("the total is computed by the server", "a coupon works once per account", "an order can't be paid twice"). A logic bug is the gap between that rule and what happens, so the response code alone proves nothing: check the resulting state (the order, the balance, the cart) with a follow-up GET.
3. Parameter tampering, with `replay_send` on a copy of the recorded request: negative and zero quantities, tiny or negative prices, another currency, a discount above 100%, a limit past its maximum, a higher role or plan on signup or profile update (also a field the request didn't send: mass assignment).
4. Workflow order, with `replay_send` or `replay_group` (sequential): skip a step (go from cart straight to the confirmation call), repeat a step (confirm twice, reuse a one-time token), go backwards (cancel or edit after payment or shipping), and mix two sessions' steps (identity A's cart with identity B's payment).
5. One-time actions and limits (coupon, redeem, vote, transfer, withdraw): first explain to the person what you'll send and what it changes, and wait for approval; then follow the `race_conditions` skill.
6. Cross-account rules: replay identity-bearing parameters (recipient, account id, owner) with another identity's value using `authz_check`.
7. Record each broken rule with `finding_create`: the rule, what you sent, the resulting state (exchange ids for both), and the business impact (free goods, unlimited credit, someone else's order). Use synthetic test accounts and the smallest amounts; never complete a real payment. Chains (a price change plus a coupon reuse) go in `attack_path_record`.
