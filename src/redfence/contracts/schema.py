"""Contract v1 schema.

Contract v1 is the declarative boundary between RedFence and a system it did
not write. Every model forbids unknown fields so a typo cannot silently weaken
a permission matrix. Structural bounds (list sizes, unique ids, limits ranges)
live in :mod:`redfence.contracts.loader`; this module owns the typed shape and
the error type shared by both halves.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

# Corpus canary labels from ``redfence.bench.dataset``. A contract refers to a
# label, never to a canary value, so a checked-in file cannot carry a secret.
CANARY_LABELS: frozenset[str] = frozenset({"alpha", "beta", "gamma", "vault"})

ID_PATTERN = r"^[a-z0-9][a-z0-9._-]{0,63}$"

_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_HOSTNAME = re.compile(
    r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$"
)

MAX_IDENTITIES = 128
MAX_SOURCES = 256
MAX_MATRIX_CELLS = 512
MAX_LIFECYCLE_STEPS = 64

TIMEOUT_MS_MIN = 1
TIMEOUT_MS_MAX = 60_000
MAX_RESPONSE_BYTES_MIN = 1
MAX_RESPONSE_BYTES_MAX = 1_048_576
MAX_REQUESTS_MIN = 1
MAX_REQUESTS_MAX = 1_000


class ContractError(ValueError):
    """A bounded-loader rejection with a stable machine-readable code."""

    code: str
    path: str

    def __init__(self, code: str, path: str, message: str = "") -> None:
        self.code = code
        self.path = path
        location = f"{code} at {path}" if path else code
        super().__init__(f"{location}: {message}" if message else location)


class _ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DatasetSpec(_ContractModel):
    version: str
    template: str
    seed: int


class IdentitySpec(_ContractModel):
    id: str = Field(pattern=ID_PATTERN)
    tenant: str
    roles: list[str] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)
    clearance: str
    revoked: bool = False


class AclSpec(_ContractModel):
    allowed_roles: list[str] = Field(default_factory=list)
    allowed_groups: list[str] = Field(default_factory=list)
    allowed_principals: list[str] = Field(default_factory=list)
    public: bool = False


class SourceSpec(_ContractModel):
    id: str = Field(pattern=ID_PATTERN)
    tenant: str
    classification: str
    acl: AclSpec
    canary_ref: str | None = None


class MatrixCell(_ContractModel):
    id: str = Field(pattern=ID_PATTERN)
    identity: str
    source: str | None = None
    action: Literal["read", "answer", "tool", "delete", "revoke"]
    tool: str | None = None
    expect: Literal["allow", "deny"]


class LifecycleStep(_ContractModel):
    id: str = Field(pattern=ID_PATTERN)
    action: Literal["revoke", "delete", "update", "expire"]
    identity: str | None = None
    source: str | None = None


class Limits(_ContractModel):
    timeout_ms: int = 2000
    max_response_bytes: int = 65536
    max_requests: int = 32
    egress_allowlist: list[str] = Field(default_factory=list)


class RedactionSpec(_ContractModel):
    # Environment-variable NAMES only, never their values.
    secrets: list[str] = Field(default_factory=list)


class TargetSpec(_ContractModel):
    # ``callable`` exists for the Python API only; a loaded file may not select it.
    adapter: Literal["mock", "callable", "http"]
    url: str | None = None
    model: str | None = None


class ContractV1(_ContractModel):
    model_config = {"extra": "forbid"}

    contract_version: Literal[1]
    id: str = Field(pattern=ID_PATTERN)
    dataset: DatasetSpec
    identities: list[IdentitySpec]
    sources: list[SourceSpec]
    matrix: list[MatrixCell]
    lifecycle: list[LifecycleStep]
    limits: Limits
    redaction: RedactionSpec
    target: TargetSpec


def _error_code(kind: str, field: str) -> str:
    if kind == "extra_forbidden":
        return "unknown_field"
    if kind == "missing":
        return "missing_field"
    if kind == "literal_error":
        if field == "contract_version":
            return "invalid_contract_version"
        if field == "action":
            return "invalid_action"
        if field == "expect":
            return "invalid_expect"
        if field == "adapter":
            return "invalid_adapter"
        return "invalid_value"
    if kind == "string_pattern_mismatch":
        return "invalid_id"
    if kind in {
        "string_type",
        "int_type",
        "bool_type",
        "list_type",
        "dict_type",
        "tuple_type",
        "set_type",
        "model_type",
        "model_attributes_type",
        "int_parsing",
        "bool_parsing",
        "string_parsing",
    }:
        return "invalid_type"
    if kind == "value_error":
        return "invalid_value"
    return "invalid_contract"


def error_from_pydantic(error: ValidationError) -> ContractError:
    """Translate the first Pydantic failure into a stable :class:`ContractError`."""

    details = error.errors()
    if not details:
        return ContractError("invalid_contract", "$")
    first = details[0]
    location = tuple(first.get("loc", ()))
    path = ".".join(str(part) for part in location) or "$"
    field = str(location[-1]) if location else ""
    code = _error_code(str(first.get("type", "")), field)
    return ContractError(code, path, str(first.get("msg", "")))


def check_limits(limits: Limits) -> None:
    """Enforce the hard-coded limits ranges."""

    if not TIMEOUT_MS_MIN <= limits.timeout_ms <= TIMEOUT_MS_MAX:
        raise ContractError(
            "limits_out_of_range",
            "limits.timeout_ms",
            f"must be between {TIMEOUT_MS_MIN} and {TIMEOUT_MS_MAX}",
        )
    if not MAX_RESPONSE_BYTES_MIN <= limits.max_response_bytes <= MAX_RESPONSE_BYTES_MAX:
        raise ContractError(
            "limits_out_of_range",
            "limits.max_response_bytes",
            f"must be between {MAX_RESPONSE_BYTES_MIN} and {MAX_RESPONSE_BYTES_MAX}",
        )
    if not MAX_REQUESTS_MIN <= limits.max_requests <= MAX_REQUESTS_MAX:
        raise ContractError(
            "limits_out_of_range",
            "limits.max_requests",
            f"must be between {MAX_REQUESTS_MIN} and {MAX_REQUESTS_MAX}",
        )


def check_egress_allowlist(hosts: list[str]) -> None:
    """Egress entries must be bare hostnames (no scheme, path or port)."""

    for index, host in enumerate(hosts):
        if not _HOSTNAME.fullmatch(host):
            raise ContractError(
                "invalid_egress_entry",
                f"limits.egress_allowlist.{index}",
                "must be a bare hostname",
            )


def check_secret_names(secrets: list[str]) -> None:
    """Redaction entries are environment-variable names, not values."""

    for index, name in enumerate(secrets):
        if not _ENV_NAME.fullmatch(name):
            raise ContractError(
                "invalid_secret_name",
                f"redaction.secrets.{index}",
                "must be an environment-variable name",
            )


def check_canary_refs(sources: list[SourceSpec]) -> None:
    """A ``canary_ref`` is a corpus label, never a canary value."""

    for index, source in enumerate(sources):
        if source.canary_ref is not None and source.canary_ref not in CANARY_LABELS:
            raise ContractError(
                "invalid_canary_ref",
                f"sources.{index}.canary_ref",
                f"must be one of {sorted(CANARY_LABELS)}",
            )


def check_unique_ids(ids: list[str], path: str) -> None:
    seen: set[str] = set()
    for index, value in enumerate(ids):
        if value in seen:
            raise ContractError("duplicate_id", f"{path}.{index}.id", value)
        seen.add(value)


def check_count(value: int, limit: int, path: str, code: str) -> None:
    if value > limit:
        raise ContractError(code, path, f"at most {limit} allowed, got {value}")
