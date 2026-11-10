---
name: race_conditions
title: Race conditions on one-time actions
description: Find actions meant to happen once (redeem, vote, transfer, apply a coupon) and test whether parallel requests all succeed. Needs approval.
args: focus
---
Goal: find limits the server checks and updates without a lock. {{focus}}

1. Look in `model_get` and the API description for actions meant to happen once per user or within a limit: redeem, claim, coupon, voucher, vote, like, transfer, withdraw, invite, apply.
2. For each, explain to the person what you'll send and what it changes (credits, balances, votes), and wait for approval. These tests change data and run at the destructive tier.
3. Use a request that has not been used yet for that user (a fresh coupon, a second test user). `race_send` it 10-20 times with the single-packet attack (HTTP/2) or the last-byte technique (HTTP/1.1).
4. Count the successes against the rule (one redemption, balance not negative). Then send it once more alone: if that is refused but several parallel copies succeeded, it's a race condition. `finding_create` with all the exchanges as evidence.
5. `replay_group` in parallel covers multi-step races (two different requests that must not both succeed).
