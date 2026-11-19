---
name: slopguard
description: Enforce zero-slop engineering by researching the most recent official practices before coding, avoiding hallucinated packages and structural bloat, and gating every change with `slopguard check`.
---

# SlopGuard Agent Workflow

Follow these three steps whenever writing, editing, or reviewing code:

## 1. Research Most Recent Practices First
Before writing new code, installing a package, or adopting a framework pattern:
- **Verify current APIs & conventions:** Check the latest official documentation or release notes for the target library/framework (do not rely solely on stale training-data patterns or deprecated APIs).
- **Verify every dependency before importing:** Confirm exact package names on PyPI or npm before adding imports—never guess a package name from memory.
- **Check current security & hook standards:** Verify the latest recommended defaults (TLS verification, safe deserialization, parameterized queries, and minimal permissions).

## 2. Implement Cleanly (Zero Slop)
- Write small, focused functions (<= 80 lines, <= 4 levels of nesting) with no mutable default arguments, unreachable code, or copy-pasted duplicate bodies.
- Never leave `pass`, `...`, `NotImplementedError`, or unresolved `TODO`/`FIXME` stubs in production paths.
- Handle errors explicitly—never write bare `except:`, `except Exception: pass`, or empty `catch {}` blocks.
- Write real tests with meaningful assertions (never `assert True` or zero-assertion tests).

## 3. Gate with SlopGuard Before Finishing
Run SlopGuard on your changes before concluding:

```bash
# Scan only your changed lines (or full repo on greenfield projects)
slopguard check --diff origin/main --verify-registry
slopguard check . --fail-on low
```

Fix every finding until the scan reports **Grade A+ (0/100)** and all unit/integration tests pass.
