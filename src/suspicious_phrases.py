"""Find and highlight phrases that often appear in phishing messages.

The phrase list lives in config/suspicious_phrases.json. This is a simple
indicator to help users, not the classifier: legitimate messages can contain
these phrases too, so a match is never treated as proof of phishing.
"""

import html
import re
from dataclasses import dataclass, field
from pathlib import Path

from src.config import PHRASES_PATH, load_json


@dataclass
class PhraseMatch:
    phrase: str                  # phrase from the config file
    category: str                # e.g. "urgency"
    description: str             # e.g. "urgency or pressure to act quickly"
    matched_text: str            # how it actually appears in the message
    spans: list[tuple[int, int]] = field(default_factory=list)  # every (start, end) position


def load_phrase_categories(path: Path = PHRASES_PATH) -> list[dict]:
    categories = load_json(path).get("categories", [])
    for category in categories:
        if not {"name", "description", "phrases"} <= category.keys():
            raise ValueError(f"Each category in {path.name} needs 'name', 'description' and 'phrases'.")
    return categories


def _phrase_regex(phrase: str) -> re.Pattern:
    """'you've  won' -> matches "You've won", "YOU’VE   WON", "youve won", ..."""
    words = [re.escape(word).replace("'", "['’]?") for word in phrase.split()]
    return re.compile(r"\b" + r"\s+".join(words) + r"\b", re.IGNORECASE)


def find_suspicious_phrases(text, categories: list[dict] | None = None) -> list[PhraseMatch]:
    """Return one PhraseMatch per configured phrase found in the ORIGINAL message."""
    if not isinstance(text, str) or not text.strip():
        return []
    if categories is None:
        categories = load_phrase_categories()

    matches = []
    for category in categories:
        for phrase in category["phrases"]:
            found = list(_phrase_regex(phrase).finditer(text))
            if found:
                matches.append(PhraseMatch(
                    phrase=phrase,
                    category=category["name"],
                    description=category["description"],
                    matched_text=found[0].group(0),
                    spans=[(m.start(), m.end()) for m in found],
                ))
    return sorted(matches, key=lambda match: match.spans[0][0])


def highlight_phrases(text: str, matches: list[PhraseMatch]) -> str:
    """Return the message as safe HTML with matched phrases wrapped in <mark> tags.

    The message itself is HTML-escaped, so any HTML inside it is shown as
    plain text and never executed.
    """
    spans = sorted(span for match in matches for span in match.spans)
    merged = []  # combine overlapping spans
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))

    pieces, position = [], 0
    for start, end in merged:
        pieces.append(html.escape(text[position:start]))
        pieces.append(f"<mark>{html.escape(text[start:end])}</mark>")
        position = end
    pieces.append(html.escape(text[position:]))
    return "".join(pieces)
