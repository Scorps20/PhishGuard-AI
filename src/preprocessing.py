"""Text preprocessing shared by training and inference.

The same clean_text() function is used by train_model.py and by the
Streamlit app, so the model always sees text prepared in the same way.

We deliberately keep URLs, numbers, currency symbols, email addresses and
most punctuation, because they carry useful phishing signals
(e.g. "$500", "http://bit.ly/...", "verify@bank-support.com").
NLTK is not needed here: stop-word removal or stemming would throw away
phrases such as "your account", which are informative for this task.
"""

import html
import re

# <style>...</style> and <script>...</script> blocks found in HTML emails
_STYLE_SCRIPT_RE = re.compile(r"<(style|script)\b[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)
# Any remaining HTML tag, e.g. <div class="x">
_HTML_TAG_RE = re.compile(r"<[^>]+>")
# Loose CSS rules that appear without tags, e.g. "td { margin: 0; padding: 0; }"
_CSS_RULE_RE = re.compile(r"\{[^{}]*:[^{}]*;[^{}]*\}")
_WHITESPACE_RE = re.compile(r"\s+")


def combine_email_text(subject, body) -> str:
    """Join an email subject and body into one message, the same way everywhere."""
    subject = subject.strip() if isinstance(subject, str) else ""
    body = body.strip() if isinstance(body, str) else ""
    if subject and body:
        return f"{subject}\n{body}"
    return subject or body


def clean_text(text) -> str:
    """Normalise a message for the classifier.

    Returns an empty string for None, NaN or non-text input instead of crashing.
    """
    if not isinstance(text, str):
        return ""

    text = _STYLE_SCRIPT_RE.sub(" ", text)
    text = _HTML_TAG_RE.sub(" ", text)
    text = _CSS_RULE_RE.sub(" ", text)
    text = html.unescape(text)  # "&amp;" -> "&", "&nbsp;" -> non-breaking space
    text = text.lower()
    text = _WHITESPACE_RE.sub(" ", text)
    return text.strip()


_URL_RE = re.compile(r"(https?://|www\.)\S+")
_DIGITS_RE = re.compile(r"\d+")
_NON_WORD_RE = re.compile(r"[^\w\s]")


def near_duplicate_key(text) -> str:
    """A rougher version of the text, used only to spot near-duplicates.

    Messages that differ only in numbers, links or punctuation
    (e.g. the same scam template sent with different phone numbers)
    get the same key, so they can be kept out of separate data splits.
    This key is NOT used as model input.
    """
    text = clean_text(text)
    text = _URL_RE.sub(" url ", text)
    text = _DIGITS_RE.sub("0", text)
    text = _NON_WORD_RE.sub(" ", text)
    return _WHITESPACE_RE.sub(" ", text).strip()


def is_valid_message(text) -> bool:
    """True if the message has some real content after cleaning."""
    return len(clean_text(text)) > 0
