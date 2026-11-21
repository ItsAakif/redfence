# RedFenceBench dataset

Deterministic, fully synthetic enterprise corpus for stateful RAG security
evaluation. **No real data is present.** See [`docs/dataset-card.md`](../../docs/dataset-card.md)
for generation methodology, licensing, limitations, contamination risk and bias.

## Files

| File | Description |
|---|---|
| `generator.py` | Deterministic generator (seeded). Reproduces all artifacts. |
| `manifest.json` | Public versioned manifest (ids, classifications, split families). |
| `manifest.full.json` | Generated manifest including content hashes and canary markers. |
| `corpus.json` | Generated full synthetic corpus. |

The checked-in artifacts above are the **`classic`** template. The other
templates (`secret_tier`, `three_tenant`) are generated on demand and are not
checked in. Non-classic templates write suffixed files
(`manifest.<template>.json`, `manifest.full.<template>.json`,
`corpus.<template>.json`) so the classic artifacts are never overwritten.

## Regenerate

```bash
# classic only (default): writes manifest.json, manifest.full.json, corpus.json
python datasets/redfencebench/generator.py

# one or more non-classic templates (suffixed filenames)
python datasets/redfencebench/generator.py --template secret_tier --out <dir>
python datasets/redfencebench/generator.py --template secret_tier,three_tenant

# every template at once
python datasets/redfencebench/generator.py --all --out <dir>
```

## Splits

Development and held-out scenario **template families** are disjoint by design:

- **Dev (facet labels of the single revocation scenario):**
  `revocation.same_query`, `revocation.paraphrase`, `cache.revalidate`,
  `tenant.isolation`, `tool.authorization`, `deletion.cascade`
- **Held-out (seven executable families):** `delegation.chain`,
  `memory.poison.persistence`, `cache.semantic_similarity`, `mcp.tool_scope`,
  `deletion.propagation.cache_memory`, `acl.modify.replay`, `memory.ttl.expiry`

All seven held-out families are executable and are run separately with
`python scripts/run_heldout.py --out reports/heldout`. The six development
labels are facets of the one revocation scenario, not separate executable
families.
