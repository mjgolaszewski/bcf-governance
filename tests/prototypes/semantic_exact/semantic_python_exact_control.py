"""Path and loop joins for the exact native protocol proof.

Copyright 2026 Michael Golaszewski. Licensed under the MIT License.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Protocol

from .semantic_python_exact_expressions import ExactDriver, ExactExpressions
from .semantic_python_exact_guards import set_path, value_path
from .semantic_python_exact_values import (
    NONE,
    SEQUENCES,
    UNKNOWN,
    ExactProtocolRefusal,
    ExactState,
    ExactValue,
    native_element,
    union,
)


class ExactControlDriver(ExactDriver, Protocol):
    def enter_context(self, frame: ExactFlow, value: ExactValue, asynchronous: bool) -> ExactValue: ...
    def exit_context(self, frame: ExactFlow, value: ExactValue) -> None: ...
    def returned(self, frame: ExactFlow, value: ExactValue) -> None: ...


@dataclass
class ExactOutcome:
    state: ExactState
    kind: str = "normal"
    value: ExactValue = NONE


class ExactFlow(ExactExpressions):
    driver: ExactControlDriver

    def run(self) -> tuple[ExactValue, ExactState]:
        outcomes = self.block(self.function.body, self.state)
        returns = []
        for outcome in outcomes:
            if outcome.kind in {"return", "normal"}:
                self.driver.returned(self, outcome.value)
                returns.append(outcome.value)
            elif outcome.kind in {"break", "continue"}:
                raise ExactProtocolRefusal("loop control escaped its source loop")
        return union(*returns), ExactState.join([row.state for row in outcomes if row.kind in {"normal", "return"}])

    def block(self, body: list[ast.stmt], state: ExactState) -> list[ExactOutcome]:
        outcomes = [ExactOutcome(state)]
        for statement in body:
            next_outcomes = []
            for outcome in outcomes:
                if outcome.kind == "normal":
                    self.state = outcome.state
                    next_outcomes.extend(self.statement(statement))
                else:
                    next_outcomes.append(outcome)
            outcomes = next_outcomes
            if len(outcomes) > 64:
                # Merge only equal control kinds; never turn a return or a
                # break into a continuing normal execution path.
                merged = []
                for kind in {row.kind for row in outcomes}:
                    group = [row for row in outcomes if row.kind == kind]
                    merged.append(ExactOutcome(ExactState.join([row.state for row in group]), kind,
                                               union(*(row.value for row in group))))
                outcomes = merged
        return outcomes

    def statement(self, node: ast.stmt) -> list[ExactOutcome]:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = self.expression(node.value)
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                self.assign(target, value)
                self.assignment_alias(target, node.value)
        elif isinstance(node, ast.Expr):
            self.expression(node.value)
        elif isinstance(node, ast.AugAssign):
            if not isinstance(node.target, ast.Name):
                raise self.refusal(node, "unqualified augmented receiver write")
            left = ast.Name(id=node.target.id, ctx=ast.Load())
            self.positions[id(left)] = self.positions[id(node.target)]
            expression = ast.BinOp(left=left, op=node.op, right=node.value)
            self.positions[id(expression)] = self.positions[id(node)]
            self.assign(node.target, self.expression(expression))
        elif isinstance(node, ast.Return):
            value = self.expression(node.value)
            self.driver.returned(self, value)
            return [ExactOutcome(self.state, "return", value)]
        elif isinstance(node, ast.Raise):
            if node.exc is not None:
                value = self.resolved(node.exc)
                if value.kind not in {"exception", "binding"}:
                    raise self.refusal(node, "foreign exception construction")
            if node.cause is not None:
                self.expression(node.cause)
            return [ExactOutcome(self.state, "raise")]
        elif isinstance(node, ast.If):
            yes, no = self.condition(node.test)
            return [outcome for state, body in [(row, node.body) for row in yes]
                    + [(row, node.orelse) for row in no] for outcome in self.block(body, state)]
        elif isinstance(node, ast.Assert):
            yes, _ = self.condition(node.test)
            if node.msg is not None:
                # Assertion text runs on its failure path and remains part of
                # the operation's execution proof even when it does not return.
                self.expression(node.msg)
            return [ExactOutcome(state) for state in yes]
        elif isinstance(node, ast.For):
            before = self.state.copy()
            guess = before.copy()
            exits: list[ExactOutcome] = []
            breaks: list[ExactState] = []
            for _ in range(8):
                self.state = guess.copy()
                source = self.resolved(node.iter)
                if source.kind not in SEQUENCES | {"dict"}:
                    raise self.refusal(node, "foreign loop iterator")
                self.assign(node.target, native_element(source))
                outcomes = self.block(node.body, self.state)
                exits = [row for row in outcomes if row.kind in {"return", "raise"}]
                breaks = [row.state for row in outcomes if row.kind == "break"]
                continuing = [row.state for row in outcomes if row.kind in {"normal", "continue"}]
                joined = ExactState.join([before, *continuing])
                if joined == guess:
                    break
                guess = joined
            else:
                raise self.refusal(node, "loop facts did not converge")
            path = value_path(node.iter)
            target_written = isinstance(node.target, ast.Name) and any(
                isinstance(part, ast.Name) and part.id == node.target.id and isinstance(part.ctx, (ast.Store, ast.Del))
                for statement in node.body for part in ast.walk(statement))
            iterator_written = path is not None and any(
                isinstance(part, ast.Name) and part.id == path[0] and isinstance(part.ctx, (ast.Store, ast.Del))
                for statement in node.body for part in ast.walk(statement))
            if source.kind == "tuple" and path and isinstance(node.target, ast.Name) and not target_written and not iterator_written:
                # Exhaustion of an immutable tuple checks every original item.
                # Keep break paths separate, and include every continue path;
                # replacing the loop target cannot establish a fact about it.
                element = union(*(state.env.get(node.target.id, UNKNOWN) for state in continuing))
                if element != UNKNOWN:
                    set_path(guess, path, ExactValue("tuple", (element,)))
            return [*exits, *(ExactOutcome(state) for state in breaks), *self.block(node.orelse, guess)]
        elif isinstance(node, (ast.AsyncWith, ast.With)):
            values = []
            for item in node.items:
                value = self.resolved(item.context_expr)
                yielded = self.driver.enter_context(self, value, isinstance(node, ast.AsyncWith))
                values.append(value)
                if item.optional_vars is not None:
                    self.assign(item.optional_vars, yielded)
            try:
                outcomes = self.block(node.body, self.state)
            finally:
                # The contract driver must account for all normal, exceptional
                # and cancellation exits. Presence of a with statement alone
                # grants no discharge of any one of those obligations.
                for value in reversed(values):
                    self.driver.exit_context(self, value)
            return outcomes
        elif isinstance(node, ast.Try):
            before = self.state.copy()
            outcomes = self.block(node.body, self.state)
            result = []
            for outcome in outcomes:
                result.extend(self.block(node.orelse, outcome.state) if outcome.kind == "normal" else [outcome])
            # Any prefix may have raised. Invalidate every binding written by
            # the body and every heap allocation before checking handlers.
            written = {part.id for statement in node.body for part in ast.walk(statement)
                       if isinstance(part, ast.Name) and isinstance(part.ctx, (ast.Store, ast.Del))}
            handler_state = before.copy()
            for name in written:
                handler_state.env[name] = UNKNOWN
            handler_state.heap = {name: UNKNOWN for name in handler_state.heap}
            for handler in node.handlers:
                self.state = handler_state.copy()
                if handler.type is None:
                    raise self.refusal(node, "bare exception matching is not qualified")
                match = self.resolved(handler.type)
                if match.kind not in {"binding", "tuple"}:
                    raise self.refusal(handler.type, "foreign exception matching")
                if handler.name is not None:
                    self.state.env[handler.name] = UNKNOWN
                result.extend(self.block(handler.body, self.state))
            if node.finalbody:
                result.append(ExactOutcome(handler_state, "raise"))
                final = []
                for outcome in result:
                    for closed in self.block(node.finalbody, outcome.state):
                        final.append(ExactOutcome(closed.state, outcome.kind, outcome.value)
                                     if closed.kind == "normal" else closed)
                return final
            return result
        elif isinstance(node, ast.Break):
            return [ExactOutcome(self.state, "break")]
        elif isinstance(node, ast.Continue):
            return [ExactOutcome(self.state, "continue")]
        elif not isinstance(node, ast.Pass):
            raise self.refusal(node, f"unsupported statement {type(node).__name__}")
        return [ExactOutcome(self.state)]
