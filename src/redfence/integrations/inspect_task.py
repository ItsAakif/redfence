"""Inspect AI adapter for a RedFence contract.

``inspect_ai`` is an optional extra. The import happens inside
:func:`redfence_task`, so importing this module (or ``redfence``) never requires
it. The adapter is intentionally thin: it exposes the contract matrix as Inspect
samples and uses Inspect's ``generate()`` solver plus a deterministic
string-equality scorer. It does not execute a target or open a network
connection.
"""

from __future__ import annotations

from pathlib import Path

from redfence.contracts import load_contract


def redfence_task(contract_path: Path, *, adapter: str = "mock") -> object:
    """Build an Inspect ``Task`` from a RedFence contract matrix.

    Raises:
        RuntimeError: when the optional ``inspect`` extra is not installed.
    """

    try:
        from inspect_ai import Task
        from inspect_ai.dataset import Sample
        from inspect_ai.scorer import CORRECT, INCORRECT, Score, accuracy, scorer
        from inspect_ai.solver import generate
    except ImportError:
        raise RuntimeError("inspect extra not installed") from None

    contract = load_contract(Path(contract_path))
    samples = [
        Sample(
            id=cell.id,
            input=f"{cell.id}: identity={cell.identity} action={cell.action}",
            target=cell.expect,
            metadata={"adapter": adapter, "action": cell.action},
        )
        for cell in contract.matrix
    ]

    @scorer(metrics=[accuracy()])
    def _matrix_scorer():
        async def score(state, target):
            observed = state.output.completion.strip()
            expected = str(target.text).strip()
            return Score(
                value=CORRECT if observed == expected else INCORRECT,
                answer=observed,
                explanation=f"expected {expected}",
            )

        return score

    return Task(dataset=samples, solver=generate(), scorer=_matrix_scorer())
