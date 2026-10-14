"""Safe, bounded expressions for querying JSON log records."""

import ast
import json
import math
import operator


class QueryError(ValueError):
    """An expression is invalid or cannot be evaluated safely."""


_BINARY_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
}
_COMPARISON_OPERATORS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.In: lambda left, right: left in right,
    ast.NotIn: lambda left, right: left not in right,
}
_MAX_EXPRESSION_LENGTH = 2048
_MAX_AST_NODES = 128
_MAX_DEPTH = 20
_MAX_STRING_LENGTH = 4096
_MAX_NUMBER = 1e100
_MAX_COUNT_WINDOW = 30 * 24 * 60 * 60


class CompiledExpression:
    def __init__(self, tree, source):
        self.tree = tree
        self.source = source

    def evaluate(self, record, count_callback=None):
        try:
            return _evaluate(self.tree.body, record, count_callback)
        except QueryError:
            raise
        except (ArithmeticError, TypeError, ValueError) as error:
            raise QueryError("could not evaluate expression: {}".format(error)) from error

    def matches(self, record, count_callback=None):
        return bool(self.evaluate(record, count_callback))


def compile_expression(source, allow_count=False):
    """Parse and validate an expression without executing Python code."""
    if not isinstance(source, str) or not source.strip():
        raise QueryError("expression must not be empty")
    if len(source) > _MAX_EXPRESSION_LENGTH:
        raise QueryError("expression is too long")
    try:
        tree = ast.parse(source, mode="eval")
    except SyntaxError as error:
        raise QueryError(
            "invalid expression at column {}".format(error.offset or 1)
        ) from error
    _validate(tree, allow_count)
    return CompiledExpression(tree, source)


def _validate(tree, allow_count):
    count = 0

    def visit(node, depth=0):
        nonlocal count
        count += 1
        if count > _MAX_AST_NODES or depth > _MAX_DEPTH:
            raise QueryError("expression is too complex")
        if isinstance(node, ast.Expression):
            visit(node.body, depth + 1)
        elif isinstance(node, ast.Constant):
            value = node.value
            if not isinstance(value, (str, int, float, bool, type(None))):
                raise QueryError("unsupported literal")
            if isinstance(value, str) and len(value) > _MAX_STRING_LENGTH:
                raise QueryError("string literal is too long")
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                if abs(value) > 1e12 or (
                    isinstance(value, float) and not math.isfinite(value)
                ):
                    raise QueryError("numeric literal is out of range")
        elif isinstance(node, ast.Name):
            if node.id.startswith("_"):
                raise QueryError("private names are not allowed")
        elif isinstance(node, ast.Attribute):
            if node.attr.startswith("_"):
                raise QueryError("private fields are not allowed")
            visit(node.value, depth + 1)
            if not isinstance(node.value, (ast.Name, ast.Attribute, ast.Subscript)):
                raise QueryError("field paths must start with a field name")
        elif isinstance(node, ast.Subscript):
            visit(node.value, depth + 1)
            index = node.slice
            if hasattr(ast, "Index") and isinstance(index, ast.Index):
                index = index.value
            if not (
                isinstance(index, ast.Constant)
                and isinstance(index.value, (str, int))
                and not isinstance(index.value, bool)
            ):
                raise QueryError("field indexes must be constant strings or integers")
        elif isinstance(node, ast.BoolOp):
            if not isinstance(node.op, (ast.And, ast.Or)) or len(node.values) < 2:
                raise QueryError("unsupported Boolean operator")
            for child in node.values:
                visit(child, depth + 1)
        elif isinstance(node, ast.UnaryOp):
            if not isinstance(node.op, (ast.Not, ast.USub, ast.UAdd)):
                raise QueryError("unsupported unary operator")
            visit(node.operand, depth + 1)
        elif isinstance(node, ast.BinOp):
            if type(node.op) not in _BINARY_OPERATORS:
                raise QueryError("unsupported arithmetic operator")
            if (
                isinstance(node.op, (ast.Div, ast.Mod))
                and isinstance(node.right, ast.Constant)
                and node.right.value == 0
            ):
                raise QueryError("division or modulo by zero is not allowed")
            visit(node.left, depth + 1)
            visit(node.right, depth + 1)
        elif isinstance(node, ast.Compare):
            if not all(type(op) in _COMPARISON_OPERATORS for op in node.ops):
                raise QueryError("unsupported comparison operator")
            visit(node.left, depth + 1)
            for child in node.comparators:
                visit(child, depth + 1)
        elif isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name) or node.keywords:
                raise QueryError("only named query functions are allowed")
            function = node.func.id
            if function not in ("has", "contains", "count_if"):
                raise QueryError("unsupported query function {!r}".format(function))
            if function == "has":
                if len(node.args) != 1:
                    raise QueryError("has() expects one argument")
                visit(node.args[0], depth + 1)
            elif function == "contains":
                if len(node.args) != 2:
                    raise QueryError("contains() expects two arguments")
                for child in node.args:
                    visit(child, depth + 1)
            else:
                if not allow_count:
                    raise QueryError("count_if() is available only in rules")
                if (
                    len(node.args) != 2
                    or not isinstance(node.args[0], ast.Constant)
                    or not isinstance(node.args[0].value, str)
                    or not isinstance(node.args[1], ast.Constant)
                    or isinstance(node.args[1].value, bool)
                    or not isinstance(node.args[1].value, int)
                    or not 1 <= node.args[1].value <= _MAX_COUNT_WINDOW
                ):
                    raise QueryError(
                        'count_if() expects a query string and a 1..2592000 second window'
                    )
                nested = compile_expression(node.args[0].value)
                node._compiled_query = nested
        else:
            raise QueryError("unsupported syntax: {}".format(type(node).__name__))

    visit(tree)


def _field_value(node, record):
    if isinstance(node, ast.Name):
        return record.get(node.id)
    if isinstance(node, ast.Attribute):
        base = _field_value(node.value, record)
        return base.get(node.attr) if isinstance(base, dict) else None
    if isinstance(node, ast.Subscript):
        base = _field_value(node.value, record)
        index = node.slice
        if hasattr(ast, "Index") and isinstance(index, ast.Index):
            index = index.value
        if isinstance(base, dict):
            return base.get(index.value)
        if isinstance(base, (list, tuple)) and isinstance(index.value, int):
            try:
                return base[index.value]
            except IndexError:
                return None
        return None
    return _UNSET


_UNSET = object()


def _evaluate(node, record, count_callback):
    value = _field_value(node, record)
    if value is not _UNSET:
        return value
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.And):
            for child in node.values:
                result = _evaluate(child, record, count_callback)
                if not result:
                    return result
            return result
        for child in node.values:
            result = _evaluate(child, record, count_callback)
            if result:
                return result
        return result
    if isinstance(node, ast.UnaryOp):
        value = _evaluate(node.operand, record, count_callback)
        if isinstance(node.op, ast.Not):
            return not value
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise QueryError("unary arithmetic requires a number")
        if not _is_bounded_number(value):
            raise QueryError("numeric value is out of range")
        return -value if isinstance(node.op, ast.USub) else value
    if isinstance(node, ast.BinOp):
        left = _evaluate(node.left, record, count_callback)
        right = _evaluate(node.right, record, count_callback)
        if isinstance(node.op, ast.Add) and isinstance(left, str) and isinstance(right, str):
            result = left + right
            if len(result) > _MAX_STRING_LENGTH:
                raise QueryError("string result is too long")
            return result
        if any(isinstance(item, bool) or not isinstance(item, (int, float)) for item in (left, right)):
            raise QueryError("arithmetic operators require numeric fields")
        if not all(_is_bounded_number(item) for item in (left, right)):
            raise QueryError("numeric value is out of range")
        result = _BINARY_OPERATORS[type(node.op)](left, right)
        if isinstance(result, (int, float)) and not _is_bounded_number(result):
            raise QueryError("numeric result is out of range")
        return result
    if isinstance(node, ast.Compare):
        left = _evaluate(node.left, record, count_callback)
        for comparison, child in zip(node.ops, node.comparators):
            right = _evaluate(child, record, count_callback)
            if left is None or right is None:
                result = (left is right) if isinstance(comparison, ast.Eq) else (
                    left is not right if isinstance(comparison, ast.NotEq) else False
                )
            else:
                result = _COMPARISON_OPERATORS[type(comparison)](left, right)
            if not result:
                return False
            left = right
        return True
    if isinstance(node, ast.Call):
        name = node.func.id
        if name == "count_if":
            if count_callback is None:
                raise QueryError("count_if() is available only in rules")
            return count_callback(node._compiled_query, node.args[1].value)
        args = [_evaluate(child, record, count_callback) for child in node.args]
        if name == "has":
            needle = str(args[0]).casefold()
            return needle in json.dumps(record, sort_keys=True, ensure_ascii=False).casefold()
        value, needle = args
        if isinstance(value, (dict, list, tuple)):
            return needle in value
        return str(needle).casefold() in str(value).casefold()
    raise QueryError("unsupported expression node")


def _is_bounded_number(value):
    return abs(value) <= _MAX_NUMBER and (
        not isinstance(value, float) or math.isfinite(value)
    )
