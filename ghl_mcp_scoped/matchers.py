"""Argument matchers.

Deliberately small and closed. Five matcher keys, no expression language,
no user-supplied code. Every matcher works on a dotted path into the
``arguments`` object of an MCP ``tools/call`` request.

Path rules
----------
``locationId``            -> arguments["locationId"]
``contact.locationId``    -> arguments["contact"]["locationId"]
``tags.0``                -> arguments["tags"][0]

A path that cannot be resolved is "absent". Absent is a failure for
``equals`` / ``in`` / ``matches`` / ``required`` and a pass for ``forbidden``,
unless the constraint sets ``optional: true``, in which case an absent path
passes for every matcher except ``required``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

MATCHER_KEYS = ("equals", "in", "matches", "required", "forbidden")

_MISSING = object()


def resolve_path(arguments: Any, path: str) -> Any:
    """Resolve a dotted path. Returns the sentinel _MISSING when absent."""
    current = arguments
    for part in path.split("."):
        if isinstance(current, dict):
            if part not in current:
                return _MISSING
            current = current[part]
        elif isinstance(current, list):
            try:
                index = int(part)
            except ValueError:
                return _MISSING
            if index < 0 or index >= len(current):
                return _MISSING
            current = current[index]
        else:
            return _MISSING
    return current


def is_missing(value: Any) -> bool:
    return value is _MISSING


@dataclass(frozen=True)
class Constraint:
    """One argument-level constraint."""

    arg: str
    kind: str
    value: Any = None
    optional: bool = False

    def describe(self) -> str:
        if self.kind == "required":
            return f"{self.arg} required"
        if self.kind == "forbidden":
            return f"{self.arg} forbidden"
        if self.kind == "in":
            return f"{self.arg} in {list(self.value)!r}"
        if self.kind == "matches":
            return f"{self.arg} matches /{self.value}/"
        return f"{self.arg} == {self.value!r}"

    def check(self, arguments: Any) -> tuple[bool, str]:
        """Return (passed, human readable explanation)."""
        found = resolve_path(arguments, self.arg)
        absent = is_missing(found)

        if self.kind == "required":
            if absent or found is None:
                return False, f"required argument '{self.arg}' is missing"
            return True, f"'{self.arg}' is present"

        if self.kind == "forbidden":
            if absent or found is None:
                return True, f"'{self.arg}' is absent"
            return False, f"forbidden argument '{self.arg}' was supplied"

        if absent or found is None:
            if self.optional:
                return True, f"'{self.arg}' is absent and the constraint is optional"
            return False, f"'{self.arg}' is missing, so {self.describe()} cannot hold"

        if self.kind == "equals":
            ok = found == self.value
            return ok, f"'{self.arg}'={found!r} {'==' if ok else '!='} {self.value!r}"

        if self.kind == "in":
            ok = found in self.value
            return ok, (
                f"'{self.arg}'={found!r} is {'' if ok else 'not '}in the permitted set"
            )

        if self.kind == "matches":
            text = found if isinstance(found, str) else str(found)
            ok = re.search(self.value, text) is not None
            return ok, (
                f"'{self.arg}'={text!r} does {'' if ok else 'not '}match /{self.value}/"
            )

        raise ValueError(f"unknown matcher kind: {self.kind}")


@dataclass
class ConstraintSet:
    """All constraints in a rule's ``when:`` block. Every one must pass."""

    constraints: list[Constraint] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.constraints)

    def check(self, arguments: Any) -> tuple[bool, str]:
        for constraint in self.constraints:
            ok, why = constraint.check(arguments)
            if not ok:
                return False, why
        return True, "all argument constraints passed"
