"""Parse task log contents to extract finding summaries.

This module contains placeholder logic for parsing FIO findings from tool
task logs.

It is intended to be removed in the future once we have direct access to the
FIO SDK to format FIO analysis result data.

The parser is intentionally conservative:
- It only extracts `title`, `detector`, and `description`.
- It ignores all other log fields.
- It returns a dataclass wrapper containing the parsed findings plus total
  and per-log finding counts.

"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    title: str
    detector: str
    description: str


@dataclass(frozen=True)
class ParsedLogs:
    findings: list[Finding]
    num_findings: int
    num_findings_by_log_file_path: dict[str, int]


_FINDING_START_RE = re.compile(r"^\[(?P<severity>[^\]]+)\]\s+(?P<title>.+?)\s*$")
_DETECTOR_RE = re.compile(r"^Reported By:\s*vanguard:(?P<detector>[^\s]+)\s*$")
_DESCRIPTION_RE = re.compile(r"^Details:\s*$")


def _parse_findings_from_log_contents(log_contents: str) -> list[Finding]:
    """Parse detector findings from a single task log string.

    A finding is expected to look like:

        + [Medium] Some title
        Reported By: vanguard:some/detector
        Location: ...
        Confidence: ...
        More Info: ...
        Details:
        Description line 1
        Description line 2

    Only the title, detector, and description are preserved.
    """

    findings: list[Finding] = []
    lines = log_contents.splitlines()

    i = 0
    while i < len(lines):
        current = lines[i].lstrip()
        start_match = _FINDING_START_RE.match(current)
        if start_match is None:
            i += 1
            continue

        title = start_match.group("title").strip()
        detector = ""
        description_lines: list[str] = []

        i += 1
        while i < len(lines):
            line = lines[i]
            stripped = line.lstrip()

            # A new finding begins; stop here and let the outer loop process it.
            if _FINDING_START_RE.match(stripped):
                break

            detector_match = _DETECTOR_RE.match(stripped)
            if detector_match is not None:
                detector = detector_match.group("detector").strip()
                i += 1
                continue

            if _DESCRIPTION_RE.match(stripped):
                i += 1
                while i < len(lines):
                    desc_line = lines[i]
                    stripped_desc = desc_line.lstrip()
                    if _FINDING_START_RE.match(stripped_desc):
                        break
                    if stripped_desc.startswith("finding_counters_file="):
                        break
                    if description_lines and not stripped_desc and stripped_desc != "":
                        break
                    if stripped_desc == "":
                        description_lines.append("")
                        i += 1
                        continue
                    if stripped_desc.startswith("["):
                        break
                    description_lines.append(
                        desc_line[1:] if desc_line.startswith(" ") else desc_line
                    )
                    i += 1
                continue

            i += 1

        description = "\n".join(line.rstrip() for line in description_lines).strip()
        findings.append(Finding(title=title, detector=detector, description=description))

    return findings


def parse_logs(logs: Sequence[tuple[str, str]]) -> ParsedLogs:
    """Parse detector findings from one or more task log strings.

    Each log entry is a ``(log_file_path, log_contents)`` tuple.
    """

    findings: list[Finding] = []
    num_findings_by_log_file_path: dict[str, int] = {}
    total_findings = 0

    for log_file_path, log_contents in logs:
        log_findings = _parse_findings_from_log_contents(log_contents)
        finding_count = len(log_findings)
        findings.extend(log_findings)
        num_findings_by_log_file_path[log_file_path] = finding_count
        total_findings += finding_count

    return ParsedLogs(
        findings=findings,
        num_findings=total_findings,
        num_findings_by_log_file_path=num_findings_by_log_file_path,
    )
