"""
TSM Fabric — Policy Engine (the trust language)
===============================================
A real DSL, not config files. "What is allowed?" expressed as trust rules:

    when data.classification == "secret" then route local
    when destination.trust < 80 then block
    when action == "destructive" then require_approval
    when identity.kind == "agent" and risk >= 70 then escalate
    default allow

Grammar (one rule per line; ``#`` comments; blank lines ignored)::

    statement   := "when" condition "then" action | "default" action
    condition   := or
    or          := and ("or" and)*
    and         := unary ("and" unary)*
    unary       := "not" unary | primary
    primary     := "(" or ")" | comparison | value
    comparison  := value OP value          OP: == != < <= > >= in
    value       := DOTTED_IDENT | STRING | NUMBER | true | false
    action      := allow | block | escalate | quarantine | require_approval
                 | redact | flag | route <destination>

Identifiers are resolved against the evaluation context (a dict; dotted keys walk
nested dicts). Evaluation is deterministic and **first-match-wins**. Pure stdlib.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, List, Optional


class PolicyError(Exception):
    pass


class PolicyParseError(PolicyError):
    pass


# ── tokenizer ─────────────────────────────────────────────────────────────────

_TOKEN_RE = re.compile(
    r"""
      (?P<WS>\s+)
    | (?P<STR>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
    | (?P<OP>>=|<=|==|!=|>|<|=)
    | (?P<LP>\()
    | (?P<RP>\))
    | (?P<NUM>-?\d+(?:\.\d+)?)
    | (?P<IDENT>[A-Za-z_][A-Za-z0-9_.]*)
    """,
    re.VERBOSE,
)

_KEYWORDS = {"and", "or", "not", "in"}
_BOOLS = {"true": True, "false": False}
_MISSING = object()


@dataclass
class _Tok:
    kind: str
    val: str


def _tokenize(s: str) -> List[_Tok]:
    toks: List[_Tok] = []
    i, n = 0, len(s)
    while i < n:
        m = _TOKEN_RE.match(s, i)
        if not m:
            raise PolicyParseError(f"unexpected character near {s[i:i + 12]!r}")
        i = m.end()
        kind = m.lastgroup
        val = m.group()
        if kind == "WS":
            continue
        if kind == "IDENT":
            low = val.lower()
            if low in _KEYWORDS:
                toks.append(_Tok("KW", low))
            elif low in _BOOLS:
                toks.append(_Tok("BOOL", low))
            else:
                toks.append(_Tok("IDENT", val))
        elif kind == "OP":
            toks.append(_Tok("OP", "==" if val == "=" else val))
        else:
            toks.append(_Tok(kind, val))
    return toks


def _unquote(s: str) -> str:
    q = s[0]
    body = s[1:-1]
    return body.replace("\\" + q, q).replace("\\\\", "\\")


# ── AST nodes ─────────────────────────────────────────────────────────────────

@dataclass
class _Ref:
    path: str

    def resolve(self, ctx: Any) -> Any:
        if isinstance(ctx, dict) and self.path in ctx:
            return ctx[self.path]
        cur: Any = ctx
        for part in self.path.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return _MISSING
        return cur


@dataclass
class _Lit:
    value: Any

    def resolve(self, ctx: Any) -> Any:
        return self.value


@dataclass
class _Cmp:
    left: Any
    op: str
    right: Any

    def eval(self, ctx: Any) -> bool:
        left = self.left.resolve(ctx)
        right = self.right.resolve(ctx)
        left = None if left is _MISSING else left
        right = None if right is _MISSING else right
        if self.op == "==":
            return left == right
        if self.op == "!=":
            return left != right
        if self.op == "in":
            try:
                return left in right  # type: ignore[operator]
            except TypeError:
                return False
        try:
            lf, rf = float(left), float(right)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return False
        if self.op == "<":
            return lf < rf
        if self.op == "<=":
            return lf <= rf
        if self.op == ">":
            return lf > rf
        if self.op == ">=":
            return lf >= rf
        return False


@dataclass
class _Truthy:
    operand: Any

    def eval(self, ctx: Any) -> bool:
        value = self.operand.resolve(ctx)
        return value is not _MISSING and bool(value)


@dataclass
class _Not:
    node: Any

    def eval(self, ctx: Any) -> bool:
        return not self.node.eval(ctx)


@dataclass
class _BoolOp:
    op: str
    items: List[Any]

    def eval(self, ctx: Any) -> bool:
        if self.op == "and":
            return all(it.eval(ctx) for it in self.items)
        return any(it.eval(ctx) for it in self.items)


# ── parser ────────────────────────────────────────────────────────────────────

class _Parser:
    def __init__(self, toks: List[_Tok]) -> None:
        self.toks = toks
        self.i = 0

    def _peek(self) -> Optional[_Tok]:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def _next(self) -> Optional[_Tok]:
        tok = self._peek()
        self.i += 1
        return tok

    def _expect(self, kind: str) -> _Tok:
        tok = self._peek()
        if tok is None or tok.kind != kind:
            raise PolicyParseError(f"expected {kind}, got {tok.val if tok else 'end'}")
        self.i += 1
        return tok

    def parse(self) -> Any:
        node = self._or()
        if self._peek() is not None:
            raise PolicyParseError(f"unexpected trailing token {self._peek().val!r}")
        return node

    def _or(self) -> Any:
        items = [self._and()]
        while self._is_kw("or"):
            self._next()
            items.append(self._and())
        return items[0] if len(items) == 1 else _BoolOp("or", items)

    def _and(self) -> Any:
        items = [self._unary()]
        while self._is_kw("and"):
            self._next()
            items.append(self._unary())
        return items[0] if len(items) == 1 else _BoolOp("and", items)

    def _unary(self) -> Any:
        if self._is_kw("not"):
            self._next()
            return _Not(self._unary())
        return self._primary()

    def _primary(self) -> Any:
        tok = self._peek()
        if tok is not None and tok.kind == "LP":
            self._next()
            node = self._or()
            self._expect("RP")
            return node
        left = self._operand()
        tok = self._peek()
        if tok is not None and (tok.kind == "OP" or (tok.kind == "KW" and tok.val == "in")):
            op = tok.val if tok.kind == "OP" else "in"
            self._next()
            right = self._operand()
            return _Cmp(left, op, right)
        return _Truthy(left)

    def _operand(self) -> Any:
        tok = self._next()
        if tok is None:
            raise PolicyParseError("unexpected end of condition")
        if tok.kind == "STR":
            return _Lit(_unquote(tok.val))
        if tok.kind == "NUM":
            return _Lit(float(tok.val) if "." in tok.val else int(tok.val))
        if tok.kind == "BOOL":
            return _Lit(_BOOLS[tok.val])
        if tok.kind == "IDENT":
            return _Ref(tok.val)
        raise PolicyParseError(f"expected a value, got {tok.val!r}")

    def _is_kw(self, val: str) -> bool:
        tok = self._peek()
        return tok is not None and tok.kind == "KW" and tok.val == val


# ── actions, rules, program ───────────────────────────────────────────────────

_ACTIONS = {"allow", "block", "escalate", "quarantine", "require_approval",
            "redact", "flag", "route"}


@dataclass(frozen=True)
class Action:
    kind: str
    target: Optional[str] = None

    def __str__(self) -> str:
        return f"{self.kind} {self.target}" if self.target else self.kind


def _parse_action(text: str) -> Action:
    parts = text.strip().split()
    if not parts:
        raise PolicyParseError("missing action")
    kind = parts[0].lower()
    if kind == "require" and len(parts) > 1 and parts[1].lower() == "approval":
        return Action("require_approval")
    if kind not in _ACTIONS:
        raise PolicyParseError(f"unknown action {parts[0]!r}")
    if kind == "route":
        if len(parts) < 2:
            raise PolicyParseError("'route' needs a destination (e.g. 'route local')")
        return Action("route", parts[1].lower())
    return Action(kind)


@dataclass
class Rule:
    condition: Any
    action: Action
    raw: str

    def matches(self, ctx: Any) -> bool:
        try:
            return bool(self.condition.eval(ctx))
        except Exception:
            return False  # a malformed runtime context never crashes evaluation


@dataclass(frozen=True)
class PolicyOutcome:
    action: str
    target: Optional[str]
    matched_rule: Optional[str]
    reason: str


class PolicyProgram:
    """A compiled set of trust rules. ``evaluate`` returns the first match."""

    def __init__(self, rules: List[Rule], default: Action) -> None:
        self.rules = rules
        self.default = default

    def evaluate(self, context: dict) -> PolicyOutcome:
        for rule in self.rules:
            if rule.matches(context):
                return PolicyOutcome(rule.action.kind, rule.action.target,
                                     rule.raw, f"matched: {rule.raw}")
        return PolicyOutcome(self.default.kind, self.default.target, None,
                             f"default: {self.default}")

    def __len__(self) -> int:
        return len(self.rules)


def parse(text: str) -> PolicyProgram:
    """Compile trust-language source into an executable :class:`PolicyProgram`."""
    rules: List[Rule] = []
    default = Action("allow")
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        low = line.lower()
        if low.startswith("default "):
            default = _parse_action(line[len("default "):])
            continue
        if not low.startswith("when "):
            raise PolicyParseError(f"line {lineno}: expected 'when ...' or 'default ...': {line!r}")
        parts = re.split(r"\s+then\s+", line, maxsplit=1, flags=re.IGNORECASE)
        if len(parts) != 2:
            raise PolicyParseError(f"line {lineno}: rule needs '... then <action>'")
        cond_text = parts[0][len("when "):].strip()
        if not cond_text:
            raise PolicyParseError(f"line {lineno}: empty condition")
        condition = _Parser(_tokenize(cond_text)).parse()
        rules.append(Rule(condition, _parse_action(parts[1]), line))
    return PolicyProgram(rules, default)
