"""Importing this package registers every built-in rule."""

from . import deps, duplication, gaps, loose_ends, python_ast, secrets, security, slop  # noqa: F401  (registration)
from .base import Rule, RuleMeta, all_rules

__all__ = ["Rule", "RuleMeta", "all_rules"]
