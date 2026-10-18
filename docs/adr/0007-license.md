# ADR-0007: AGPL-3.0 core, Apache-2.0 SDKs

**Status:** Accepted

## Context
ProxyMind should stay open, and a company should not be able to take the core, run it as a closed hosted service and give nothing back. At the same time, companies need to build integrations, agents and plugins without licensing worries.

## Decision
- The core (everything in this repository unless stated otherwise) is **AGPL-3.0-only**.
- SDKs and plugin interfaces (`sdk/`, published separately) will be **Apache-2.0**.
- Contributions are accepted under the same license as the code they change (inbound = outbound). No CLA for now.

## Consequences
- Hosted forks must publish their changes.
- Some companies avoid AGPL dependencies. Since users run ProxyMind as a tool rather than linking it into products, this matters little; the Apache-2.0 SDKs cover integration.
