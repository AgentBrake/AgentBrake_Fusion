"""Formal agent integration helpers for agentbrake."""

from .connect import ConnectResult, connect_repo
from .coverage import build_coverage_report
from .doctor import DoctorReport, run_doctor, run_real_agent_smoke_test, run_smoke_test
from .start import build_start_summary

__all__ = [
    "ConnectResult",
    "DoctorReport",
    "build_coverage_report",
    "build_start_summary",
    "connect_repo",
    "run_doctor",
    "run_real_agent_smoke_test",
    "run_smoke_test",
]
