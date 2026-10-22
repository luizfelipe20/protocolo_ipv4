"""Simulador didático de redes IPv4."""

from .simulation import SimulationError, simulate
from .topology import build_topology

__all__ = ["simulate", "build_topology", "SimulationError"]
