import phonenumbers

from app.phone_checks import check_phone_number

# Guaranteed-valid fixtures via phonenumbers' own example-number metadata,
# rather than a hand-typed number that might coincidentally be a real
# person/business's -- same "verify, don't guess real-world data"
# discipline as the brand domain list in app.features.lexical.
_IN_MOBILE = phonenumbers.format_number(
    phonenumbers.example_number_for_type("IN", phonenumbers.PhoneNumberType.MOBILE),
    phonenumbers.PhoneNumberFormat.E164,
)
_IN_FIXED_LINE = phonenumbers.format_number(
    phonenumbers.example_number_for_type("IN", phonenumbers.PhoneNumberType.FIXED_LINE),
    phonenumbers.PhoneNumberFormat.E164,
)
_IN_PREMIUM_RATE = phonenumbers.format_number(
    phonenumbers.example_number_for_type("IN", phonenumbers.PhoneNumberType.PREMIUM_RATE),
    phonenumbers.PhoneNumberFormat.E164,
)


def test_valid_indian_mobile_number_is_safe():
    result = check_phone_number(_IN_MOBILE, default_region="IN")
    assert result.verdict == "safe"
    assert result.is_valid is True
    assert result.line_type == "MOBILE"
    assert result.override_reason is None


def test_valid_indian_fixed_line_is_safe():
    result = check_phone_number(_IN_FIXED_LINE, default_region="IN")
    assert result.verdict == "safe"
    assert result.is_valid is True
    # India's numbering plan doesn't always let the library disambiguate
    # fixed-line from mobile by range alone -- FIXED_LINE_OR_MOBILE is a
    # genuine, correct classification here, not a bug.
    assert result.line_type in ("FIXED_LINE", "FIXED_LINE_OR_MOBILE")


def test_unparseable_string_is_flagged():
    result = check_phone_number("not a phone number", default_region="IN")
    assert result.verdict == "phishing"
    assert result.low_confidence is True
    assert result.override_reason == "unparseable_number"
    assert result.is_valid is False


def test_too_short_string_is_invalid_format():
    result = check_phone_number("123", default_region="IN")
    assert result.verdict == "phishing"
    assert result.low_confidence is True
    assert result.override_reason == "invalid_format"


def test_premium_rate_number_is_flagged():
    result = check_phone_number(_IN_PREMIUM_RATE, default_region="IN")
    assert result.verdict == "phishing"
    assert result.low_confidence is True
    assert result.override_reason == "premium_rate_number"
    assert result.line_type == "PREMIUM_RATE"


def test_default_region_applied_when_no_country_code_given():
    # No leading "+" -- default_region="IN" must be what makes this parse
    # as a valid Indian mobile number at all.
    bare_national_number = _IN_MOBILE.removeprefix("+91")
    result = check_phone_number(bare_national_number, default_region="IN")
    assert result.is_valid is True
    assert result.region_code == "IN"


def test_full_international_number_ignores_default_region():
    # A "+"-prefixed number carries its own country code, so the default
    # region must not override it.
    result = check_phone_number("+14155552671", default_region="IN")
    assert result.region_code == "US"


def test_e164_and_carrier_fields_are_populated_for_valid_number():
    result = check_phone_number(_IN_MOBILE, default_region="IN")
    assert result.e164 == _IN_MOBILE
    # Carrier coverage is real but inconsistent -- just assert the field is
    # either a non-empty string or None, never an empty string (callers
    # rely on that to distinguish "no coverage" from "known empty carrier").
    assert result.carrier_name is None or result.carrier_name != ""
