"""Report augmentation.

The deterministic assessment/report is produced by mcd_lens (the quality bar).
Core *adds* run-storage, coverage, toolchain, sandbox, tree, and graph sections
without altering the target assessment. HTML/Markdown polish of these sections is
a later milestone; for now JSON gets the full sections and Markdown gets a compact
coverage appendix.
"""

from __future__ import annotations

from unmask.report.augment import augment_json_report, markdown_coverage_appendix

__all__ = ["augment_json_report", "markdown_coverage_appendix"]
