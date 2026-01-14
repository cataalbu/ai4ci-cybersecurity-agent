"""LLM-based incident summarization utilities.

This package is intended to be run after the threat classifier produces per-window
predictions, and it generates human-readable incident titles and descriptions.
"""

from .summarizer import IncidentSummary, SummarizerConfig, summarize_incident_window

__all__ = ["IncidentSummary", "SummarizerConfig", "summarize_incident_window"]

