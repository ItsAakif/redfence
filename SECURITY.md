# Security policy

RedFence and RedFenceBench are **research software**. They are not a production
service, not a scanner, and not a certification tool. Please read the safe-use
warning below before pointing any adapter at a live system.

## Supported versions

| Version | Supported |
|---|---|
| 0.3.x | yes (current release line) |
| 0.2.x and earlier | no; historical reference only |

Only the current release line receives security fixes. Historical verification
captures and ADRs are kept for the record and are not patched.

## Reporting a vulnerability

Please do **not** open a public issue for a suspected vulnerability. Use the
repository host's **private vulnerability reporting** feature (for example a
private security advisory) and include:

- the affected version and commit;
- the command or contract file that reproduces the issue;
- whether the issue is in the deterministic core, a contract adapter, the
  loader, or optional integrations;
- the impact you believe it has, and any suggested fix.

Do not include real secrets, live credentials, customer data or third-party
system details in a report. RedFence's own tests use synthetic canaries only.

We aim to acknowledge a report, confirm scope, and agree a disclosure timeline
before any public write-up. There is no bug-bounty programme.

## Scope

In scope:

- the bounded contract loader (JSON/YAML parsing, size/depth/list limits, tag,
  anchor, alias and duplicate-key rejection);
- redaction of configured secret values and corpus canaries in stored
  observations and reports;
- the HTTP adapter boundary (egress allowlist, scheme/loopback checks, redirects
  off, response caps) and the claim that it never raises;
- optional-import isolation (`import redfence` must not import optional extras);
- deterministic-core regressions that could turn a violation into a pass.

Out of scope:

- vulnerabilities in a third-party system under test;
- live HTTP, Inspect or OTel deployments (these are **NOT VERIFIED** in 0.3.0);
- Docker/G6/G9 infrastructure fixtures (historical, not re-run);
- denial of service against a target you do not own;
- model-weight, training-data or multimodal attacks.

## Safe use

- All bundled data is synthetic. Canaries are non-secret markers.
- The default path opens no network connection and requires no Docker.
- Before pointing an adapter at a live system, get written authorization from its
  owner, use a non-production tenant, set a minimal `limits.egress_allowlist`,
  keep `max_requests`/`timeout_ms`/`max_response_bytes` small, and name only
  environment variables (never literal values) in `redaction.secrets`.
- A passing contract run means the declared cells matched their declared
  expectations on that adapter. It is not a security certification.
