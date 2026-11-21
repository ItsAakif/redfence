"""Dataset integrity and split quality (gate G7 partial)."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from redfence.bench.dataset import (
    DEFAULT_SEED,
    DEV_FAMILIES,
    HELDOUT_FAMILIES,
    TEMPLATES,
    build_corpus,
    scenario_id,
    template_isomorphic,
)
from redfence.core.ids import content_hash, json_digest

DATASET_DIR = Path(__file__).resolve().parents[1] / "datasets" / "redfencebench"


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        "redfencebench_generator", DATASET_DIR / "generator.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_dataset_manifest_is_deterministic():
    assert build_corpus().manifest() == build_corpus().manifest()


def test_splits_are_family_disjoint():
    assert set(DEV_FAMILIES).isdisjoint(set(HELDOUT_FAMILIES))


def test_expected_tenants_and_documents_exist():
    corpus = build_corpus()
    assert {t.id for t in corpus.tenants} == {"t_alpha", "t_beta"}
    assert {d.id for d in corpus.documents} == {
        "doc_alpha_secret",
        "doc_alpha_benign",
        "doc_beta_secret",
        "doc_alpha_malicious",
    }


def test_canaries_are_synthetic_and_hashed_in_manifest():
    corpus = build_corpus()
    assert corpus.canaries["alpha"].startswith("CANARY_ALPHA_")
    manifest_text = json.dumps(corpus.manifest())
    # Cleartext canary must never appear in the manifest; only hashed markers.
    assert corpus.canaries["alpha"] not in manifest_text
    assert "sha256:" in manifest_text


# -- Template framework (redfencebench-0.4.0) ---------------------------------

# Frozen content hashes of the classic corpus at the default seed: the classic
# template must stay byte-identical across refactors (guards the pinned G2 base).
CLASSIC_CONTENT_HASHES = {
    "doc_alpha_secret": "5c14558312ff09c1de5ac861e15a118224266efa6c36cd2cde453f62160c1d2e",
    "doc_alpha_benign": "eaa62b0a8cb338f5ba04dbe18a94ffbc02c765dd5a2c48833f28eb30a49d123c",
    "doc_beta_secret": "e9f460d2f9e81e8d4d991bb6fba98f8bdaf3fc32ee350caacbfae0bb9d317ed6",
    "doc_alpha_malicious": "256f594c63e5a52ad93c53fa6ae44717674c54e251356cb0daee1ed45873dbc7",
}


def test_default_corpus_is_unchanged_classic_template():
    corpus = build_corpus()
    assert corpus.template == "classic"
    hashes = {d.id: content_hash(d.content) for d in corpus.documents}
    assert hashes == CLASSIC_CONTENT_HASHES


# Canonical SHA-256 of ``Corpus.manifest()`` per template at the default seed
# (``json_digest``: sorted keys, compact separators, ASCII). These pin both the
# manifest *schema* and its *values*; regenerate only for an intentional dataset
# change. A content-only refactor must leave these untouched.
#
# The 0.3.0 -> 0.4.0 bump changed only the ``dataset_version`` string in the
# manifest; classic document content and CLASSIC_CONTENT_HASHES are unchanged.
MANIFEST_DIGESTS = {
    "classic": "41a35dd50110068f705efa3e06e3069fb02081a6f0e19401638472bdd7e36f49",
    "secret_tier": "74d6c887c883829aba2df4a40aee2945f445fd884a3fe38849f91ec72c6b726d",
    "three_tenant": "a48f3638a45b12fcc04c62f549c6177e3448bf79cd9f0732b15c274442bf054e",
}

def _lf_digest(path: Path) -> str:
    """SHA-256 of canonical LF text; JSON line endings are not semantic."""
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


# SHA-256 of each checked-in lifecycle config *file*, pinned over LF-canonical
# bytes so Windows and Linux checkouts agree. Line endings are not semantic for
# JSON; the digest still covers formatting and key ordering.
CONFIG_DIGESTS = {
    "lineage": "ff86b6ea51785705e1b6dad8dbe4e97b970ea97300c5a3f8648d32cbcebb5567",
    "existence": "3ca8063aabad6e8beb68f9c6fecfbaf92766bbb23cf38cc840732372d74ced17",
    "repair": "8a862a97f6e376ef43c721d0e0535814f9b1fdb0abfcda0fe39a70d219384b6e",
    "replication": "6e5aad5e90e3536f6dcd18e14ae01663aa6a45f98aa6d3ec8f802acc4cff1263",
}


def test_manifest_digests_are_pinned():
    for name, expected in MANIFEST_DIGESTS.items():
        digest = json_digest(build_corpus(template=name).manifest())
        assert digest == expected, (
            f"manifest digest for {name!r} changed: regenerate only for an "
            "intentional dataset change"
        )


def test_manifest_includes_provenance_fields():
    assert build_corpus().manifest()["manifest_schema"] == 2
    for name in TEMPLATES:
        corpus = build_corpus(template=name)
        manifest = corpus.manifest()
        for document in manifest["documents"]:
            assert document["content_hash"]
            assert document["acl_fingerprint"]
            assert isinstance(document["canary_markers"], list)
        assert set(manifest["principal_entitlements"]) == {p.id for p in corpus.principals}


def test_manifest_never_contains_cleartext_canaries():
    for name in TEMPLATES:
        corpus = build_corpus(template=name)
        manifest_text = json.dumps(corpus.manifest())
        assert "CANARY_" not in manifest_text, name
        for canary in corpus.canaries.values():
            assert canary not in manifest_text, name


def test_checked_in_dataset_artifacts_match_generator(tmp_path):
    generated = _load_generator().generate(out_dir=tmp_path)
    for filename, key in (
        ("manifest.json", "manifest"),
        ("manifest.full.json", "manifest_full"),
        ("corpus.json", "corpus"),
    ):
        assert generated[key].read_bytes() == (DATASET_DIR / filename).read_bytes(), filename


def test_generator_secret_tier_uses_suffixed_artifacts(tmp_path):
    generated = _load_generator().generate(out_dir=tmp_path, template="secret_tier")
    expected = {
        "manifest": "manifest.secret_tier.json",
        "manifest_full": "manifest.full.secret_tier.json",
        "corpus": "corpus.secret_tier.json",
    }
    for key, filename in expected.items():
        assert generated[key] == tmp_path / filename
        assert (tmp_path / filename).exists(), filename
    manifest = json.loads((tmp_path / "manifest.secret_tier.json").read_text(encoding="utf-8"))
    assert manifest["template"] == "secret_tier"
    # Classic artifacts must never be written by a non-classic generation.
    for filename in ("manifest.json", "manifest.full.json", "corpus.json"):
        assert not (tmp_path / filename).exists(), filename


def test_generator_classic_matches_checked_in_artifacts(tmp_path):
    generated = _load_generator().generate(out_dir=tmp_path, template="classic")
    for filename, key in (
        ("manifest.json", "manifest"),
        ("manifest.full.json", "manifest_full"),
        ("corpus.json", "corpus"),
    ):
        assert generated[key] == tmp_path / filename
        assert generated[key].read_bytes() == (DATASET_DIR / filename).read_bytes(), filename


def test_generator_all_flag_emits_every_template(tmp_path):
    assert _load_generator().main(["--all", "--out", str(tmp_path)]) == 0
    expected = ["manifest.json", "manifest.full.json", "corpus.json"]
    for template in TEMPLATES:
        if template == "classic":
            continue
        expected.extend(
            (
                f"manifest.{template}.json",
                f"manifest.full.{template}.json",
                f"corpus.{template}.json",
            )
        )
    for filename in expected:
        assert (tmp_path / filename).exists(), filename
    assert len(expected) == 3 * len(TEMPLATES)
    # --all also emits the lifecycle configs.
    for kind in CONFIG_DIGESTS:
        assert (tmp_path / "configs" / f"{kind}.json").exists(), kind
    # Classic output is still byte-identical to the checked-in artifacts.
    for filename in ("manifest.json", "manifest.full.json", "corpus.json"):
        assert (tmp_path / filename).read_bytes() == (DATASET_DIR / filename).read_bytes(), filename


def test_generator_configs_flag_emits_only_configs(tmp_path):
    assert _load_generator().main(["--configs", "--out", str(tmp_path)]) == 0
    assert sorted(path.name for path in (tmp_path / "configs").iterdir()) == sorted(
        f"{kind}.json" for kind in CONFIG_DIGESTS
    )
    # --configs alone must not write corpus artifacts.
    assert not any(path.is_file() for path in tmp_path.iterdir())


def test_generator_output_is_deterministic(tmp_path):
    generator = _load_generator()
    first = tmp_path / "first"
    second = tmp_path / "second"
    assert generator.main(["--all", "--out", str(first)]) == 0
    assert generator.main(["--all", "--out", str(second)]) == 0
    first_files = sorted(
        path.relative_to(first).as_posix() for path in first.rglob("*") if path.is_file()
    )
    second_files = sorted(
        path.relative_to(second).as_posix() for path in second.rglob("*") if path.is_file()
    )
    assert first_files == second_files
    for filename in first_files:
        assert (first / filename).read_bytes() == (second / filename).read_bytes(), filename


def test_generate_configs_is_deterministic(tmp_path):
    generator = _load_generator()
    first = generator.generate_configs(out_dir=tmp_path / "first")
    second = generator.generate_configs(out_dir=tmp_path / "second")
    assert set(first) == set(second) == set(CONFIG_DIGESTS)
    for kind in first:
        assert first[kind].read_bytes() == second[kind].read_bytes(), kind


def test_checked_in_configs_match_generator(tmp_path):
    generated = _load_generator().generate_configs(out_dir=tmp_path)
    for kind, path in generated.items():
        assert path == tmp_path / "configs" / f"{kind}.json"
        checked_in = DATASET_DIR / "configs" / f"{kind}.json"
        assert path.read_bytes() == checked_in.read_bytes(), kind


def test_config_digests_are_pinned():
    for kind, expected in CONFIG_DIGESTS.items():
        path = DATASET_DIR / "configs" / f"{kind}.json"
        digest = _lf_digest(path)
        assert digest == expected, (
            f"config digest for {kind!r} changed: regenerate only for an "
            "intentional dataset change"
        )


def test_config_digest_is_line_ending_independent(tmp_path):
    source = DATASET_DIR / "configs" / "lineage.json"
    data = source.read_bytes().replace(b"\r\n", b"\n")
    crlf = tmp_path / "lineage.json"
    crlf.write_bytes(data.replace(b"\n", b"\r\n"))
    assert _lf_digest(crlf) == CONFIG_DIGESTS["lineage"]


def test_config_payloads_have_expected_schema():
    generator = _load_generator()
    assert generator.CONFIG_VERSION == "redfencebench-configs-0.1.0"
    assert set(generator.LIFECYCLE_CONFIGS) == set(CONFIG_DIGESTS)
    corpus = build_corpus()
    for kind in CONFIG_DIGESTS:
        payload = json.loads(
            (DATASET_DIR / "configs" / f"{kind}.json").read_text(encoding="utf-8")
        )
        assert set(payload) == {
            "config_version",
            "kind",
            "dataset_version",
            "template",
            "seed",
            "cases",
        }
        assert payload["config_version"] == generator.CONFIG_VERSION
        assert payload["kind"] == kind
        assert payload["dataset_version"] == corpus.dataset_version
        assert payload["template"] == "classic"
        assert payload["seed"] == DEFAULT_SEED
        case_ids = [case["id"] for case in payload["cases"]]
        assert len(case_ids) == len(set(case_ids)), kind
        for case in payload["cases"]:
            if kind == "lineage":
                assert set(case) == {
                    "id",
                    "source_doc",
                    "principal",
                    "derived_kind",
                    "expected",
                }
                corpus.document(case["source_doc"])
                corpus.principal(case["principal"])
                assert case["derived_kind"] in {"answer", "cache", "memory"}
                assert case["expected"] in {"descendant", "absent"}
            elif kind == "existence":
                assert set(case) == {
                    "id",
                    "query",
                    "hidden_source",
                    "visible_principal",
                    "expect",
                }
                assert case["expect"] == "same_response"
                corpus.document(case["hidden_source"])
                corpus.principal(case["visible_principal"])
            elif kind == "repair":
                assert set(case) == {"id", "document", "principal", "plan"}
                corpus.document(case["document"])
                corpus.principal(case["principal"])
                assert set(case["plan"]) == {
                    "purge_cache",
                    "delete_memory",
                    "restore_acl",
                    "reingest",
                }
                assert all(isinstance(value, bool) for value in case["plan"].values())
            else:
                assert set(case) == {"id", "store", "propagate"}
                assert case["store"] in {"replica", "backup", "retention"}
                assert isinstance(case["propagate"], bool)


def test_configs_never_contain_cleartext_canaries():
    corpus = build_corpus()
    for kind in CONFIG_DIGESTS:
        text = (DATASET_DIR / "configs" / f"{kind}.json").read_text(encoding="utf-8")
        assert "CANARY_" not in text, kind
        for canary in corpus.canaries.values():
            assert canary not in text, kind


def test_scenario_id_includes_dataset_version():
    assert scenario_id(
        "secured", DEFAULT_SEED, dataset_version="redfencebench-0.2.0"
    ) != scenario_id("secured", DEFAULT_SEED)


def test_all_templates_are_isomorphic():
    for name in TEMPLATES:
        corpus = build_corpus(template=name)
        template_isomorphic(corpus)  # must not raise


def test_templates_are_deterministic():
    for name in TEMPLATES:
        first = build_corpus(template=name).manifest()
        second = build_corpus(template=name).manifest()
        assert first == second, name


def test_template_manifest_records_template_name():
    for name in TEMPLATES:
        assert build_corpus(template=name).manifest()["template"] == name


def test_unknown_template_raises():
    with pytest.raises(ValueError):
        build_corpus(template="does_not_exist")


def test_secret_tier_template_structure():
    corpus = build_corpus(template="secret_tier")
    vault = corpus.document("doc_alpha_vault")
    assert vault.classification == "secret"
    officer = corpus.principal("p_alpha_officer")
    assert officer.clearance == "secret"
    # The confidential-clearance officer is the only principal allowed the vault.
    reader = corpus.principal_by_role("t_alpha", "reader")
    assert not vault.acl.permits(reader)
    assert vault.acl.permits(officer)


def test_three_tenant_template_structure():
    corpus = build_corpus(template="three_tenant")
    assert {t.id for t in corpus.tenants} == {"t_alpha", "t_beta", "t_gamma"}
    assert "gamma" in corpus.canaries
    gamma_conf = corpus.confidential_doc("t_gamma")
    assert corpus.canaries["gamma"] in gamma_conf.canaries
    # Variant: the secondary reader no longer carries the primary-tenant group.
    assert corpus.principal("p_beta_reader").groups == ["beta-eng"]
