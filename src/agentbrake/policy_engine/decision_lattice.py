"""Backward-compatible imports for the Constraint Product Lattice.

New code should import from :mod:`agentbrake.policy_engine.constraint_product_lattice`.
"""

from __future__ import annotations

from .constraint_product_lattice import DECISION_RANK, ConstraintProductLattice, DecisionLattice

__all__ = ["DECISION_RANK", "ConstraintProductLattice", "DecisionLattice"]
