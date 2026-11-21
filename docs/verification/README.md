# Verification captures

This directory holds the raw command output that backs the project's
verification claims.

## Immutable history

Files named `00-*` through `54-*` under [`raw/`](raw/) are **immutable captures**
from earlier milestones. They are the historical record and are never edited to
match later code. Scenario ids, evidence ids, report filenames, counts and
outcomes in them may differ from the current 0.2.0 behaviour; that is expected
and is why the current claims live in
[`hardening-report.md`](hardening-report.md) instead.

Do not edit, regenerate, or "correct" an existing raw capture.

## New captures

Captures made for 0.2.0 and later use the `60-*` prefix and carry a header
before the command output:

```
date=<YYYY-MM-DD>
command=<exact command line>
cwd=<working directory>
interpreter=<Python version>
platform=<OS / build>
commit=<git commit SHA, or NOT_A_GIT_REPO>
exit=<process exit code>
---
<captured stdout/stderr>
```

The current hardening captures are `raw/60-*` through `raw/69-*`.

## Claim policy

A claim without a raw capture in `raw/` is **NOT VERIFIED**. A claim that cannot
be reproduced on the recorded host is reported as `NOT VERIFIED` rather than
estimated or inferred. See the hardening report's scope and limitations for the
items that remain unverified by design (CI execution, Docker/G6/G9, Linux and
Python 3.11/3.12).
