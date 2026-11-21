# ADR-0002: Monorepo, Python-only core, isolated trust domains

- **Status:** accepted
- **Context:** Mandate section 6 specifies Python 3.12, FastAPI, Pydantic v2,
  PostgreSQL, pgvector, SQLAlchemy, Alembic, pytest, Docker, asyncio, and says
  not to introduce Redis/workers/dashboard without a real requirement.
- **Decision:**
  - One Python package `redfence` with clear subpackages.
  - The deterministic core depends only on Pydantic. FastAPI/SQLAlchemy/pgvector
    live behind optional extras so the benchmark runs without infrastructure.
  - Two SQLAlchemy trust domains (`PlatformBase`, `SutBase`) with separate
    metadata; credentials and Docker isolation are the deployment mechanism.
  - No Redis, distributed workers, or dashboard at this milestone.
- **Consequence:** The vertical slice is reproducible with no network and no
  database; persistence/API are optional and not on the critical path.
