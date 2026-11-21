"""Bounded JSON/YAML loader for contract v1.

JSON is always available through the standard library. YAML is optional: the
``yaml`` import happens inside :func:`load_contract` and a missing extra is a
typed :class:`ContractError`, never an import-time failure.

The loader is deliberately paranoid. A contract file is untrusted input that
will be pointed at external systems, so size, nesting, key shape, YAML
constructs, path strings and list sizes are all checked before a model is
returned.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from redfence.contracts.schema import (
    MAX_IDENTITIES,
    MAX_LIFECYCLE_STEPS,
    MAX_MATRIX_CELLS,
    MAX_SOURCES,
    ContractError,
    ContractV1,
    check_canary_refs,
    check_count,
    check_egress_allowlist,
    check_limits,
    check_secret_names,
    check_unique_ids,
    error_from_pydantic,
)

MAX_FILE_BYTES = 256 * 1024
MAX_DEPTH = 32

_SUPPORTED_SUFFIXES = frozenset({".json", ".yaml", ".yml"})
_ENV_INTERPOLATION = re.compile(r"\$\{")


def load_contract(path: Path | str) -> ContractV1:
    """Read, bound and validate a contract file."""

    path = Path(path)
    source = str(path)
    suffix = path.suffix.lower()
    if suffix not in _SUPPORTED_SUFFIXES:
        raise ContractError("unsupported_format", source, f"unsupported suffix {suffix!r}")

    try:
        size = path.stat().st_size
    except OSError as error:
        raise ContractError("unreadable_file", source, str(error)) from error
    if size > MAX_FILE_BYTES:
        raise ContractError("file_too_large", source, f"limit is {MAX_FILE_BYTES} bytes")

    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ContractError("unreadable_file", source, str(error)) from error
    if len(raw) > MAX_FILE_BYTES:
        raise ContractError("file_too_large", source, f"limit is {MAX_FILE_BYTES} bytes")

    if suffix == ".json":
        payload = _load_json(raw, source)
    else:
        payload = _load_yaml(raw, source)
    if not isinstance(payload, Mapping):
        raise ContractError("invalid_type", source, "contract must be a mapping")
    return parse_contract(payload)


def parse_contract(payload: Mapping[str, object]) -> ContractV1:
    """Validate an already-parsed mapping against contract v1."""

    if not isinstance(payload, Mapping):
        raise ContractError("invalid_type", "$", "contract must be a mapping")

    _check_raw_tree(payload)

    try:
        contract = ContractV1.model_validate(payload)
    except RecursionError:
        raise ContractError("depth_exceeded", "$", f"limit is {MAX_DEPTH}") from None
    except ValidationError as error:
        raise error_from_pydantic(error) from None

    _check_contract(contract)
    return contract


def _load_json(raw: bytes, source: str) -> object:
    text = _decode(raw, source, "invalid_json")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ContractError("duplicate_key", key)
            result[key] = value
        return result

    try:
        return json.loads(text, object_pairs_hook=reject_duplicates)
    except ContractError:
        raise
    except RecursionError:
        # A deeply nested object can overflow the C decoder before the
        # explicit depth walk sees it. Keep the boundary typed.
        raise ContractError("depth_exceeded", source, f"limit is {MAX_DEPTH}") from None
    except (json.JSONDecodeError, ValueError) as error:
        raise ContractError("invalid_json", source, str(error)) from error


def _load_yaml(raw: bytes, source: str) -> object:
    try:
        import yaml
    except ImportError:
        raise ContractError(
            "yaml_extra_missing",
            source,
            "install the optional 'contract' extra to read YAML",
        ) from None

    text = _decode(raw, source, "invalid_yaml")

    try:
        tokens = yaml.scan(text, Loader=yaml.SafeLoader)
        for token in tokens:
            if isinstance(token, yaml.TagToken):
                raise ContractError("yaml_tag_forbidden", source, "explicit YAML tags are unsafe")
            if isinstance(token, (yaml.AnchorToken, yaml.AliasToken)):
                raise ContractError(
                    "yaml_anchor_forbidden",
                    source,
                    "anchors and aliases are unsafe",
                )
    except ContractError:
        raise
    except RecursionError:
        raise ContractError("depth_exceeded", source, f"limit is {MAX_DEPTH}") from None
    except yaml.YAMLError as error:
        raise ContractError("invalid_yaml", source, str(error)) from error

    class _StrictSafeLoader(yaml.SafeLoader):
        def construct_mapping(self, node: Any, deep: bool = False) -> Any:
            if isinstance(node, yaml.MappingNode):
                self.flatten_mapping(node)
            seen: set[str] = set()
            for key_node, _value_node in node.value:
                key = self.construct_object(key_node, deep=deep)
                if not isinstance(key, str):
                    raise ContractError("non_string_key", source, repr(key))
                if key in seen:
                    raise ContractError("duplicate_key", key)
                seen.add(key)
            return super().construct_mapping(node, deep=deep)

    try:
        return yaml.load(text, Loader=_StrictSafeLoader)
    except ContractError:
        raise
    except RecursionError:
        raise ContractError("depth_exceeded", source, f"limit is {MAX_DEPTH}") from None
    except yaml.YAMLError as error:
        raise ContractError("invalid_yaml", source, str(error)) from error


def _decode(raw: bytes, source: str, code: str) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ContractError(code, source, "file must be UTF-8") from error


def _check_raw_tree(payload: Mapping[str, object]) -> None:
    """Reject cycles, non-string keys, deep nesting, env interpolation and traversal."""

    _walk_raw(payload, 1, "", set(), set())


def _walk_raw(
    value: object,
    depth: int,
    path: str,
    ancestors: set[int],
    seen: set[int],
) -> None:
    if isinstance(value, Mapping):
        if depth > MAX_DEPTH:
            raise ContractError("depth_exceeded", path or "$", f"limit is {MAX_DEPTH}")
        marker = id(value)
        if marker in ancestors:
            raise ContractError("depth_exceeded", "$", f"limit is {MAX_DEPTH}")
        if marker in seen:
            return
        seen.add(marker)
        ancestors.add(marker)
        for key, child in value.items():
            if not isinstance(key, str):
                raise ContractError("non_string_key", path or "$", repr(key))
            _walk_raw(child, depth + 1, _join(path, key), ancestors, seen)
        ancestors.remove(marker)
    elif isinstance(value, (list, tuple)):
        if depth > MAX_DEPTH:
            raise ContractError("depth_exceeded", path or "$", f"limit is {MAX_DEPTH}")
        marker = id(value)
        if marker in ancestors:
            raise ContractError("depth_exceeded", "$", f"limit is {MAX_DEPTH}")
        if marker in seen:
            return
        seen.add(marker)
        ancestors.add(marker)
        for index, child in enumerate(value):
            _walk_raw(child, depth + 1, f"{path}[{index}]", ancestors, seen)
        ancestors.remove(marker)
    elif isinstance(value, str):
        _check_string(value, path)


def _join(path: str, key: str) -> str:
    return f"{path}.{key}" if path else key


def _check_string(value: str, path: str) -> None:
    if _ENV_INTERPOLATION.search(value):
        raise ContractError("env_interpolation", path, "environment interpolation is unsafe")
    if ".." in value:
        raise ContractError("path_traversal", path, "parent-directory segments are unsafe")


def _check_references(contract: ContractV1) -> None:
    """Every matrix cell and lifecycle step must name a declared id."""

    identity_ids = {item.id for item in contract.identities}
    source_ids = {item.id for item in contract.sources}

    for index, cell in enumerate(contract.matrix):
        if cell.identity not in identity_ids:
            raise ContractError(
                "unknown_identity", f"matrix.{index}.identity", cell.identity
            )
        if cell.source is not None and cell.source not in source_ids:
            raise ContractError(
                "unknown_source", f"matrix.{index}.source", cell.source
            )

    for index, step in enumerate(contract.lifecycle):
        if step.identity is not None and step.identity not in identity_ids:
            raise ContractError(
                "unknown_identity", f"lifecycle.{index}.identity", step.identity
            )
        if step.source is not None and step.source not in source_ids:
            raise ContractError(
                "unknown_source", f"lifecycle.{index}.source", step.source
            )


def _check_contract(contract: ContractV1) -> None:
    check_count(
        len(contract.identities), MAX_IDENTITIES, "identities", "too_many_identities"
    )
    check_count(len(contract.sources), MAX_SOURCES, "sources", "too_many_sources")
    check_count(
        len(contract.matrix), MAX_MATRIX_CELLS, "matrix", "too_many_matrix_cells"
    )
    check_count(
        len(contract.lifecycle), MAX_LIFECYCLE_STEPS, "lifecycle", "too_many_lifecycle_steps"
    )

    check_unique_ids([item.id for item in contract.identities], "identities")
    check_unique_ids([item.id for item in contract.sources], "sources")
    check_unique_ids([item.id for item in contract.matrix], "matrix")
    check_unique_ids([item.id for item in contract.lifecycle], "lifecycle")
    _check_references(contract)

    check_limits(contract.limits)
    check_egress_allowlist(contract.limits.egress_allowlist)
    check_secret_names(contract.redaction.secrets)
    check_canary_refs(contract.sources)

    # ``callable`` is a Python-API adapter. A file must not select code paths.
    if contract.target.adapter == "callable":
        raise ContractError(
            "callable_adapter_forbidden",
            "target.adapter",
            "callable is available through the Python API only",
        )
