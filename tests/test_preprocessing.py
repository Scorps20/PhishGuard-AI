from src.preprocessing import (
    clean_text,
    combine_email_text,
    is_valid_message,
    near_duplicate_key,
)


def test_empty_and_invalid_input_returns_empty_string():
    assert clean_text("") == ""
    assert clean_text("   \n\t ") == ""
    assert clean_text(None) == ""
    assert clean_text(float("nan")) == ""
    assert clean_text(12345) == ""
    assert not is_valid_message("   ")
    assert not is_valid_message(None)


def test_normal_text_is_cleaned_consistently():
    text = "  Hello   THERE,\n\nhow are   you? "
    assert clean_text(text) == "hello there, how are you?"
    assert clean_text(text) == clean_text(text)  # same input, same output
    assert is_valid_message(text)


def test_useful_phishing_signals_are_kept():
    text = "WIN £500 now! Visit http://bit.ly/abc123 or mail support@bank-help.com"
    cleaned = clean_text(text)
    assert "£500" in cleaned
    assert "http://bit.ly/abc123" in cleaned
    assert "support@bank-help.com" in cleaned
    assert "!" in cleaned


def test_html_and_css_noise_is_removed():
    html_email = "<html><style>p {color: red;}</style><p>Verify&nbsp;your <b>account</b></p></html>"
    cleaned = clean_text(html_email)
    assert "<" not in cleaned and "color" not in cleaned
    assert "verify" in cleaned and "your" in cleaned and "account" in cleaned


def test_combine_email_text():
    assert combine_email_text("Subject", "Body") == "Subject\nBody"
    assert combine_email_text("", "Body") == "Body"
    assert combine_email_text(None, "Body") == "Body"
    assert combine_email_text("Subject only", None) == "Subject only"
    assert combine_email_text(None, None) == ""


def test_near_duplicate_key_groups_templates():
    first = "Call 09050090033 now to claim your £5000 prize!"
    second = "CALL 08712402779 now to claim your £800 prize"
    assert near_duplicate_key(first) == near_duplicate_key(second)
    assert near_duplicate_key("see you tomorrow") != near_duplicate_key(first)
