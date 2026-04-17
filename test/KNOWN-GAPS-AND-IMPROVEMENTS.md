# Auditex Known Gaps And Improvement Targets

## Current High-Value Gaps

- native Office 365 Management Activity API export path is not yet the primary Purview export implementation
- eDiscovery depth is present but still depends heavily on command-backed surfaces
- large-tenant validation is not yet proven by a dedicated high-scale fixture matrix
- Entra governance depth is still thinner than the architecture target
- Exchange response breadth is still limited
- Windows 365 and Intune cross-linking can be pushed further
- docs still need periodic reality-sync as implementation moves

## Where A Senior Reviewer Should Add Value

- replace weak adapter-backed export paths with stronger native API adapters where feasible
- tighten the separation between inventory, export, and response even further if any leakage exists
- improve checkpoint durability and resume semantics under interruption
- add stress fixtures and memory-bound validation
- add more operator-safe response actions with stronger gating and richer evidence contracts
- deepen governance collectors:
  - PIM
  - access reviews
  - entitlement management
  - app consent posture
- improve Exchange and Purview evidence depth for real customer investigations
- harden the blocker taxonomy so escalation advice is more precise

## Questions The Reviewer Should Explicitly Answer

- Is the current runtime credible for customer-facing read-only audits now?
- Which surfaces are production-ready today?
- Which surfaces are experimental?
- Which surfaces should be disabled until improved?
- Is the current evidence model strong enough for customer handoff?
- Are the current MCP and CLI boundaries the right product boundaries?
- Should any adapter be demoted, replaced, or isolated further?

## Expected Improvement Style

- prefer better contracts over more surface area
- prefer stronger tests over optimistic claims
- prefer clearer blockers over silent partials
- prefer native APIs over shelling out when the API path is robust
- prefer explicit product boundaries over convenience shortcuts
