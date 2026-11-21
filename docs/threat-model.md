# Threat model

## Assets

- Confidential documents and their chunks/embeddings (tenant-scoped).
- Synthetic canary secrets embedded in documents.
- Response cache entries derived from authorized context.
- Persistent agent memory records.
- Tool execution capability and its side effects.
- Authorization metadata (ACLs, epochs, provenance).

## Adversaries

| Adversary | Capability | Tested by |
|---|---|---|
| Malicious or compromised user | valid identity in one tenant, low privilege | intern query, cross-tenant query |
| Revoked user | previously authorized, then revoked | post-revocation replay |
| Malicious document author | controls document content | indirect injection doc, retrieval poisoning |
| Malicious tool output | controls tool results persisted to memory | untrusted-source trust check |
| Compromised/confused deputy | can influence tool invocation | tool policy oracle |

## Trust boundaries

1. **Untrusted input → trusted instructions.** Retrieved documents and tool
   outputs are untrusted; they must not silently become trusted memory
   (AISVS C8.2.3).
2. **Model → authorization.** The model never authorizes access. Authorization is
   enforced before context assembly.
3. **Tenant → tenant.** No chunk from another tenant may be admitted, cached, or
   recalled.
4. **Cache → requester.** Cache reuse must revalidate current authorization and
   freshness (SSC-style validity constraints).
5. **Agent → tool side effect.** Every tool call passes an independent PDP; high
   impact actions require approval bound to actor + call.

## In scope (0.3.0)

Stateful revocation across index, cache, memory and tool paths, on secured and
vulnerable configs, with deterministic oracles. 0.3.0 adds a bounded contract
boundary for external targets, lineage/derivative, existence, repair, capability,
MCP-fixture and in-memory retention/replica oracles, plus a mutation self-test.
Security and benign utility are reported together; a zero-unit facet is
`UNSUPPORTED`, never a pass.

## External targets (0.3.0)

Contract v1 lets RedFence point at a system it did not write. That adds risks on
the **assessment host**, not only in the target:

| Risk | Mitigation |
|---|---|
| SSRF / unintended egress | `http` requires `https` or loopback and a host in `limits.egress_allowlist` (default empty); redirects are disabled; the URL host is checked before a request is sent |
| YAML bomb / parser abuse | JSON is stdlib-only; YAML uses a strict `SafeLoader`; explicit tags, anchors, aliases, duplicate keys, non-string keys and deep nesting are rejected; file ≤256 KiB, depth ≤32 |
| Secret leakage into reports | `redaction.secrets` lists **environment-variable names**, never values; the runner redacts those values and corpus canaries before storage; a redaction oracle re-checks stored observations |
| Hostile or broken adapter | the adapter boundary never raises; timeouts, non-2xx, redirects, invalid JSON and oversized bodies become `status="error"` or `truncated=True`; no fabricated `SATISFIED` |
| Resource exhaustion | request count, timeout and response-size caps are declared in `limits` and measured by `oracle.contract.budget` |
| Code execution through a contract | a loaded file cannot select the `callable` adapter or import code; `callable` exists only in the Python API |

**Redaction** is applied before observations are stored, not only when a report is
written. **Egress** is deny-by-default: an empty allowlist means the HTTP adapter
cannot leave the host, and loopback is the only plaintext exception. **Response
caps** truncate at `max_response_bytes` and mark the run inconclusive rather than
scoring a partial body as a pass.

RedFence is an **evaluation harness, not a vulnerability scanner**. It executes a
declared matrix and lifecycle against a target and reports boundary outcomes. It
does not enumerate endpoints, fuzz inputs, discover unknown attack surfaces, or
certify a system. A passing contract run means the declared cells matched their
declared expectations on that adapter, nothing more.

## Out of scope (declared, not claimed)

Model-weight attacks, training-data poisoning, real network exfiltration, MCP
authentication/authorization, multimodal input, distributed multi-node races,
timing side channels, retention policy windows, and live verification of the HTTP
adapter against a third-party endpoint (the adapter is fake-transport tested;
live endpoints are **NOT VERIFIED**).

## Safety and containment

- All data is fully synthetic; canaries are non-secret markers.
- In the default path, external communication from the synthetic tool runtime is
  captured by an in-process sink. The optional HTTP adapter is opt-in and
  allowlisted; the default tests use a fake transport and open no socket.
- No shell, no arbitrary file access, no external database mutation.
- Authorisation fails closed when it cannot be verified.
- Resource budgets/timeouts: the contract boundary enforces declared request,
  timeout, response-size and egress caps. The historical G9 Docker fixture is
  still not re-run; no current infrastructure-containment PASS is claimed.
