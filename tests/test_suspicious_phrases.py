import json

import pytest

from src.suspicious_phrases import find_suspicious_phrases, highlight_phrases, load_phrase_categories

CATEGORIES = [
    {"name": "credentials", "description": "requests for login details",
     "phrases": ["verify your account", "confirm your password"]},
    {"name": "rewards", "description": "prizes", "phrases": ["you've won", "claim your reward"]},
    {"name": "call_to_action", "description": "pressure to click", "phrases": ["click here"]},
]


def test_phrases_detected_regardless_of_case_and_spacing():
    text = "Please VERIFY   your Account today. Click Here."
    found = find_suspicious_phrases(text, CATEGORIES)
    assert [m.phrase for m in found] == ["verify your account", "click here"]
    # matched_text shows the phrase exactly as it appears in the original message
    assert found[0].matched_text == "VERIFY   your Account"


def test_apostrophe_variants():
    for text in ["You've won!", "You’ve won!", "Youve won!"]:
        assert find_suspicious_phrases(text, CATEGORIES)[0].phrase == "you've won"


def test_no_phrases_found():
    assert find_suspicious_phrases("Lunch at 1pm tomorrow?", CATEGORIES) == []
    assert find_suspicious_phrases("", CATEGORIES) == []
    assert find_suspicious_phrases(None, CATEGORIES) == []


def test_whole_words_only():
    # "click hereafter" must not match "click here"
    assert find_suspicious_phrases("click hereafter", CATEGORIES) == []


def test_all_occurrences_recorded():
    match = find_suspicious_phrases("click here or click here", CATEGORIES)[0]
    assert len(match.spans) == 2


def test_highlighting_marks_phrases_and_escapes_html():
    text = "<b>Hi</b> click here & verify your account"
    found = find_suspicious_phrases(text, CATEGORIES)
    highlighted = highlight_phrases(text, found)
    assert "<mark>click here</mark>" in highlighted
    assert "<mark>verify your account</mark>" in highlighted
    assert "&lt;b&gt;Hi&lt;/b&gt;" in highlighted  # message HTML is not executed
    assert "&amp;" in highlighted


def test_highlighting_without_matches_returns_escaped_text():
    assert highlight_phrases("a < b", []) == "a &lt; b"


def test_config_file_loads():
    categories = load_phrase_categories()  # config/suspicious_phrases.json
    assert len(categories) > 0
    assert all(c["phrases"] for c in categories)


def test_invalid_config_is_rejected(tmp_path):
    path = tmp_path / "phrases.json"
    path.write_text(json.dumps({"categories": [{"name": "x"}]}))
    with pytest.raises(ValueError):
        load_phrase_categories(path)


def test_split_by_phrases_rebuilds_the_text_and_flags_matches():
    from src.suspicious_phrases import split_by_phrases
    text = "Hi, click here or Click Here."
    pieces = split_by_phrases(text, find_suspicious_phrases(text, CATEGORIES))
    assert "".join(p["text"] for p in pieces) == text
    assert [p["text"] for p in pieces if p["flagged"]] == ["click here", "Click Here"]
    assert split_by_phrases("", []) == [] and split_by_phrases(None, []) == []
    assert split_by_phrases("no matches", []) == [{"text": "no matches", "flagged": False}]
