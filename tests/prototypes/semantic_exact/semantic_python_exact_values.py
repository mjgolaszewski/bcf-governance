"""Exact native value facts, separate from ownership and effect permission.

Copyright 2026 Michael Golaszewski. Licensed under the MIT License.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ExactValue:
    """A finite abstract value; unknown children never inherit native purity."""

    kind: str
    children: tuple[ExactValue, ...] = ()
    subject: str = ""
    fields: tuple[tuple[str, ExactValue], ...] = ()

    def member(self, name: str) -> ExactValue:
        return dict(self.fields).get(name, UNKNOWN)


UNKNOWN = ExactValue("unknown")
BOTTOM = ExactValue("never")
NONE = ExactValue("none")
BOOL = ExactValue("bool")
INT = ExactValue("int")
STR = ExactValue("str")
SCALARS = frozenset({"none", "bool", "int", "float", "complex", "str", "bytes", "date", "datetime"})
SEQUENCES = frozenset({"list", "tuple", "set", "frozenset", "view", "generator"})


def union(*values: ExactValue) -> ExactValue:
    """Join possible values without converting borrowed children to natives."""
    population: set[ExactValue] = set()
    for value in values:
        population.update(value.children if value.kind == "union" else (value,))
    population.discard(BOTTOM)
    if not population:
        return BOTTOM
    if UNKNOWN in population:
        return UNKNOWN
    if len(population) == 1:
        return next(iter(population))
    kinds = {item.kind for item in population}
    if len(kinds) == 1 and next(iter(kinds)) in SCALARS:
        return ExactValue(next(iter(kinds)))
    if kinds == {"record"} and len({item.subject for item in population}) == 1:
        rows = list(population)
        keys = set().union(*(dict(item.fields) for item in rows))
        return ExactValue("record", subject=rows[0].subject,
                          fields=tuple((key, union(*(item.member(key) for item in rows))) for key in sorted(keys)))
    if len(kinds) == 1 and next(iter(kinds)) in {"list", "dict", "tuple", "set", "frozenset", "view"}:
        rows = list(population)
        if len({len(item.children) for item in rows}) == 1:
            keys = set().union(*(dict(item.fields) for item in rows))
            return ExactValue(rows[0].kind,
                tuple(union(*(item.children[index] for item in rows)) for index in range(len(rows[0].children))),
                fields=tuple((key, union(*(item.member(key) for item in rows))) for key in sorted(keys)))
    if len(population) > 16:
        return UNKNOWN
    return ExactValue("union", tuple(sorted(population, key=repr)))


def alternatives(value: ExactValue) -> tuple[ExactValue, ...]:
    return value.children if value.kind == "union" else (value,)


def exact_kind(value: ExactValue, kind: str) -> bool:
    return all(item.kind == kind for item in alternatives(value))


def callback_free(value: ExactValue) -> bool:
    """Only deep native values qualify hashing/comparison/format protocols."""
    return all(item.kind in SCALARS | {"never"} or item.kind in SEQUENCES | {"dict"}
               and all(callback_free(child) for child in item.children)
               for item in alternatives(value))


def native_truth(value: ExactValue) -> bool:
    return all(item.kind in SCALARS | SEQUENCES | {"dict"} for item in alternatives(value))


def native_element(value: ExactValue) -> ExactValue:
    elements = []
    for item in alternatives(value):
        if item.kind in SEQUENCES and item.children:
            elements.append(item.children[0])
        elif item.kind == "dict" and item.children:
            elements.append(item.children[0])
        else:
            return UNKNOWN
    return union(*elements)


@dataclass
class ExactState:
    """Owned allocation identities and their heap are independent of types."""

    env: dict[str, ExactValue] = field(default_factory=dict)
    heap: dict[str, ExactValue] = field(default_factory=dict)
    aliases: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def copy(self) -> ExactState:
        return ExactState(dict(self.env), dict(self.heap), dict(self.aliases))

    def resolve(self, value: ExactValue) -> ExactValue:
        if value.kind == "owned":
            return self.heap.get(value.subject, UNKNOWN)
        return union(*(self.resolve(child) for child in value.children)) if value.kind == "union" else value

    def allocate(self, identity: str, shape: ExactValue) -> ExactValue:
        # Repeated allocations at a loop site represent every iteration, not
        # a reset to an optimistic empty container.
        self.heap[identity] = union(self.heap[identity], shape) if identity in self.heap else shape
        return ExactValue("owned", subject=identity)

    @classmethod
    def join(cls, states: list[ExactState]) -> ExactState:
        if not states:
            return cls()
        names = set().union(*(state.env for state in states))
        identities = set().union(*(state.heap for state in states))
        return cls(
            {name: union(*(state.env.get(name, UNKNOWN) for state in states)) for name in names},
            {name: union(*(state.heap.get(name, BOTTOM) for state in states)) for name in identities},
            {name: path for name, path in states[0].aliases.items()
             if all(state.aliases.get(name) == path for state in states)},
        )


class ExactProtocolRefusal(ValueError):
    """A required runtime protocol has no complete native source proof."""

