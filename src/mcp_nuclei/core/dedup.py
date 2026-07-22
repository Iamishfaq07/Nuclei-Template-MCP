"""Check a new template against a local directory of existing templates for near-duplicates.

Useful for pointing at a local checkout of the official `nuclei-templates`
repo (or your team's private template library) before adding a new one —
entirely local, no network access or repo cloning performed by this tool.

Similarity is a simple, explainable heuristic (not embeddings/ML): id
substring overlap, tag overlap, and shared matcher words. Good enough to
flag "you probably already have this" without false confidence.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass
class DedupMatch:
    """A candidate existing template that looks similar to the new one."""

    path: Path
    template_id: str
    score: float
    reasons: list[str]


def _load_template(path: Path) -> dict[str, Any] | None:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    except yaml.YAMLError:
        return None
    return data if isinstance(data, dict) else None


def _tags(template: dict[str, Any]) -> set[str]:
    raw = (template.get("info") or {}).get("tags") or ""
    return {t.strip().lower() for t in str(raw).split(",") if t.strip()}


def _matcher_words(template: dict[str, Any]) -> set[str]:
    words: set[str] = set()
    for block_key in ("http", "network", "dns"):
        for block in template.get(block_key) or []:
            if not isinstance(block, dict):
                continue
            for matcher in block.get("matchers") or []:
                if isinstance(matcher, dict) and matcher.get("type") == "word":
                    words |= {str(w).lower() for w in matcher.get("words", [])}
    return words


def _similarity(new_template: dict[str, Any], other: dict[str, Any]) -> tuple[float, list[str]]:
    reasons: list[str] = []
    score = 0.0

    new_id = str(new_template.get("id", "")).lower()
    other_id = str(other.get("id", "")).lower()
    if new_id and other_id and (new_id in other_id or other_id in new_id):
        score += 0.4
        reasons.append(f"id overlap ({other_id!r})")

    new_tags, other_tags = _tags(new_template), _tags(other)
    if new_tags and other_tags:
        overlap = new_tags & other_tags
        if overlap:
            fraction = len(overlap) / max(len(new_tags), 1)
            score += 0.3 * fraction
            reasons.append(f"shared tags {sorted(overlap)}")

    new_words, other_words = _matcher_words(new_template), _matcher_words(other)
    if new_words and other_words:
        overlap = new_words & other_words
        if overlap:
            fraction = len(overlap) / max(len(new_words), 1)
            score += 0.3 * fraction
            reasons.append(f"shared matcher words {sorted(overlap)}")

    return round(min(score, 1.0), 3), reasons


def find_duplicates(
    new_template: dict[str, Any],
    search_dir: Path,
    *,
    threshold: float = 0.3,
    limit: int = 10,
) -> list[DedupMatch]:
    """Scan `search_dir` recursively for templates similar to `new_template`."""
    if not search_dir.exists() or not search_dir.is_dir():
        raise NotADirectoryError(f"Not a directory: {search_dir}")

    matches: list[DedupMatch] = []
    for path in search_dir.rglob("*.yaml"):
        other = _load_template(path)
        if other is None or not other.get("id"):
            continue
        score, reasons = _similarity(new_template, other)
        if score >= threshold:
            matches.append(DedupMatch(path=path, template_id=str(other["id"]), score=score, reasons=reasons))

    matches.sort(key=lambda m: m.score, reverse=True)
    return matches[:limit]
