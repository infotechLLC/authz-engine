# DECISIONS

## 2026-05-29
- Preserved the README's code-defined policy model instead of introducing a YAML or DSL interpreter.
- Implemented first-deny-wins evaluation with explicit-allow required, matching the repo's stated security posture.
- Treated `Decision.not_applicable()` and the canonical `not applicable` reason as the non-applicable branch so policy functions stay explicit and readable.
