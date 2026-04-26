# -*- coding: utf-8 -*-

"""Comprehensive tests for _api_helper.py functions."""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import re
import pytest

from ansible_collections.community.routeros.plugins.module_utils._api_data import (
    PATHS,
    KeyInfo,
    VersionedAPIData,
)
from ansible_collections.community.routeros.plugins.module_utils._api_helper import (
    value_to_str,
    _test_rule_except_invert,
    validate_and_prepare_restrict,
    restrict_entry_accepted,
    apply_value_sanitizer,
    restrict_argument_spec,
)


class FailJsonException(Exception):
    """Exception raised when module.fail_json is called."""
    def __init__(self, msg, **kwargs):
        self.msg = msg
        self.kwargs = kwargs
        super(FailJsonException, self).__init__(msg)


class FakeModule:
    """Fake Ansible module for testing."""
    def __init__(self, restrict_value=None):
        self.params = {'restrict': restrict_value}

    def fail_json(self, msg, **kwargs):
        raise FailJsonException(msg, **kwargs)


# Get test path info
TEST_PATH = PATHS[('ip', 'firewall', 'filter')]
TEST_PATH.provide_version('7.0')
TEST_PATH_DATA = TEST_PATH.get_data()


# -----------------------------------------------------------------------------
# value_to_str tests
# -----------------------------------------------------------------------------

VALUE_TO_STR_TESTS = [
    # (input, kwargs, expected)
    (None, {}, None),
    (None, {'none_to_empty': True}, ''),
    (None, {'none_to_empty': False}, None),
    ('', {}, ''),
    ('foo', {}, 'foo'),
    ('hello world', {}, 'hello world'),
    (True, {}, 'yes'),
    (False, {}, 'no'),
    (True, {'compat_bool': True}, 'true'),
    (False, {'compat_bool': True}, 'false'),
    (True, {'compat_bool': False}, 'yes'),
    (False, {'compat_bool': False}, 'no'),
    ('true', {}, 'true'),
    ('false', {}, 'false'),
    ('yes', {}, 'yes'),
    ('no', {}, 'no'),
    (0, {}, '0'),
    (1, {}, '1'),
    (-42, {}, '-42'),
    (3.14, {}, '3.14'),
    (1.0, {}, '1.0'),
    ([], {}, '[]'),
    ({}, {}, '{}'),
    (['a', 'b'], {}, "['a', 'b']"),
    ({'key': 'value'}, {}, "{'key': 'value'}"),
]


@pytest.mark.parametrize('value, kwargs, expected', VALUE_TO_STR_TESTS)
def test_value_to_str(value, kwargs, expected):
    """Test value_to_str conversion."""
    result = value_to_str(value, **kwargs)
    assert result == expected, "Expected {0!r} for {1!r} with {2}, got {3!r}".format(expected, value, kwargs, result)


# -----------------------------------------------------------------------------
# _test_rule_except_invert tests
# -----------------------------------------------------------------------------

TEST_RULE_TESTS = [
    # (value, rule, compat, expected)
    # None with match_disabled=False returns False (no values match)
    (None, {'field': 'foo', 'match_disabled': False, 'invert': False}, False, False),
    # None with match_disabled=True returns True
    (None, {'field': 'foo', 'match_disabled': True, 'invert': False}, False, True),
    # Integer 1 with values=[1] in compat=False: value_to_str(1)='1', '1' not in [1], returns False
    (1, {'field': 'foo', 'match_disabled': False, 'invert': False, 'values': [1]}, False, False),
    # Integer 1 with values=['1'] in compat=False: value_to_str(1)='1', '1' in ['1'], returns True
    (1, {'field': 'foo', 'match_disabled': False, 'invert': False, 'values': ['1']}, False, True),
    # Integer 1 with values=['1'] in compat=True: value=1, 1 not in ['1'], returns False
    (1, {'field': 'foo', 'match_disabled': False, 'invert': False, 'values': ['1']}, True, False),
    # Integer 1 with regex ^1$: value_to_str(1)='1', matches, returns True
    (1, {'field': 'foo', 'match_disabled': False, 'invert': False, 'regex': re.compile('^1$')}, False, True),
    # Float 1.10 with regex ^1\.1$: value_to_str(1.10)='1.1', matches, returns True
    (1.10, {'field': 'foo', 'match_disabled': False, 'invert': False, 'regex': re.compile('^1\\.1$')}, False, True),
    # Integer 10 with regex ^1$: value_to_str(10)='10', no match, returns False
    (10, {'field': 'foo', 'match_disabled': False, 'invert': False, 'regex': re.compile('^1$')}, False, False),
    # String 'test' with values=['test']: matches, returns True. invert is
    # NOT handled by _test_rule_except_invert (caller applies it), so this
    # rule omits it.
    ('test', {'field': 'foo', 'match_disabled': False, 'invert': False, 'values': ['test']}, False, True),
    # regex against value=None must short-circuit and return False (no match)
    # regardless of regex content.
    (None, {'field': 'foo', 'match_disabled': False, 'invert': False, 'regex': re.compile('.*')}, False, False),
]


@pytest.mark.parametrize('value, rule, compat, expected', TEST_RULE_TESTS)
def test_test_rule_except_invert(value, rule, compat, expected):
    """Test _test_rule_except_invert function."""
    result = _test_rule_except_invert(value, rule, compat=compat)
    assert result == expected, f"Expected {expected} for {value!r}, got {result}"


def test_test_rule_except_invert_none_match_disabled():
    """Test _test_rule_except_invert with None value and match_disabled."""
    rule = {'field': 'comment', 'match_disabled': True, 'invert': False}
    assert _test_rule_except_invert(None, rule, compat=False) is True

    rule = {'field': 'comment', 'match_disabled': False, 'invert': False}
    assert _test_rule_except_invert(None, rule, compat=False) is False


def test_test_rule_except_invert_values_match():
    """Test _test_rule_except_invert with values matching."""
    rule = {'field': 'chain', 'match_disabled': False, 'invert': False, 'values': ['input', 'forward']}

    assert _test_rule_except_invert('input', rule, compat=False) is True
    assert _test_rule_except_invert('forward', rule, compat=False) is True
    assert _test_rule_except_invert('output', rule, compat=False) is False


def test_test_rule_except_invert_regex_match():
    """Test _test_rule_except_invert with regex matching."""
    rule = {'field': 'comment', 'match_disabled': False, 'invert': False, 'regex': re.compile(r'^foo-\d+$')}

    assert _test_rule_except_invert('foo-123', rule, compat=False) is True
    assert _test_rule_except_invert('foo-456', rule, compat=False) is True
    assert _test_rule_except_invert('bar-123', rule, compat=False) is False


# -----------------------------------------------------------------------------
# validate_and_prepare_restrict tests
# -----------------------------------------------------------------------------

VALIDATE_RESTRICT_VALID = [
    # Valid restrict rules that should pass
    ([{
        'field': 'chain',
        'match_disabled': False,
        'values': None,
        'regex': None,
        'invert': False,
    }], [{
        'field': 'chain',
        'match_disabled': False,
        'invert': False,
    }]),
    ([{
        'field': 'comment',
        'match_disabled': True,
        'values': None,
        'regex': None,
        'invert': False,
    }], [{
        'field': 'comment',
        'match_disabled': True,
        'invert': False,
    }]),
    ([{
        'field': 'comment',
        'match_disabled': False,
        'values': None,
        'regex': None,
        'invert': True,
    }], [{
        'field': 'comment',
        'match_disabled': False,
        'invert': True,
    }]),
    ([{
        'field': 'chain',
        'match_disabled': False,
        'values': ['input', 'forward'],
        'regex': None,
        'invert': False,
    }], [{
        'field': 'chain',
        'match_disabled': False,
        'invert': False,
        'values': ['input', 'forward'],
    }]),
]


@pytest.mark.parametrize('restrict_value, expected', VALIDATE_RESTRICT_VALID)
def test_validate_and_prepare_restrict_valid(restrict_value, expected):
    """Test validate_and_prepare_restrict with valid input."""
    fake_module = FakeModule(restrict_value)
    result = validate_and_prepare_restrict(fake_module, TEST_PATH_DATA)
    assert result == expected


def test_validate_and_prepare_restrict_none():
    """Test validate_and_prepare_restrict with None restrict."""
    fake_module = FakeModule(None)
    result = validate_and_prepare_restrict(fake_module, TEST_PATH_DATA)
    assert result is None


def test_validate_and_prepare_restrict_empty_list():
    """Test validate_and_prepare_restrict with empty list."""
    fake_module = FakeModule([])
    result = validate_and_prepare_restrict(fake_module, TEST_PATH_DATA)
    assert result == []


def test_validate_and_prepare_restrict_invalid_field_name():
    """Test validate_and_prepare_restrict with field starting with !."""
    fake_module = FakeModule([{
        'field': '!foo',
        'match_disabled': False,
        'values': None,
        'regex': None,
        'invert': False,
    }])
    with pytest.raises(FailJsonException) as exc:
        validate_and_prepare_restrict(fake_module, TEST_PATH_DATA)
    assert 'must not start with "!"' in exc.value.msg


def test_validate_and_prepare_restrict_nonexistent_field():
    """Test validate_and_prepare_restrict with non-existent field."""
    fake_module = FakeModule([{
        'field': 'nonexistent_field_xyz',
        'match_disabled': False,
        'values': None,
        'regex': None,
        'invert': False,
    }])
    with pytest.raises(FailJsonException) as exc:
        validate_and_prepare_restrict(fake_module, TEST_PATH_DATA)
    assert 'does not exist for this path' in exc.value.msg


def test_validate_and_prepare_restrict_invalid_regex():
    """Test validate_and_prepare_restrict with invalid regex."""
    fake_module = FakeModule([{
        'field': 'chain',
        'match_disabled': False,
        'values': None,
        'regex': '(',  # Invalid regex
        'invert': False,
    }])
    with pytest.raises(FailJsonException) as exc:
        validate_and_prepare_restrict(fake_module, TEST_PATH_DATA)
    assert 'invalid regular expression' in exc.value.msg


def test_validate_and_prepare_restrict_compat_false():
    """Test validate_and_prepare_restrict with compat=False converts values."""
    restrict_value = [{
        'field': 'chain',
        'match_disabled': False,
        'values': [True, False, 1, 'test'],
        'regex': None,
        'invert': False,
    }]
    fake_module = FakeModule(restrict_value)
    result = validate_and_prepare_restrict(fake_module, TEST_PATH_DATA, compat=False)
    # Values should be converted to strings (None is not in the list since it returns None from value_to_str)
    assert 'values' in result[0]
    assert result[0]['values'] == ['yes', 'no', '1', 'test']


def test_validate_and_prepare_restrict_with_regex():
    """Test validate_and_prepare_restrict with valid regex."""
    restrict_value = [{
        'field': 'comment',
        'match_disabled': False,
        'values': None,
        'regex': r'^foo-\d+$',
        'invert': False,
    }]
    fake_module = FakeModule(restrict_value)
    result = validate_and_prepare_restrict(fake_module, TEST_PATH_DATA)
    assert result is not None
    assert len(result) == 1
    assert 'regex' in result[0]
    assert isinstance(result[0]['regex'], re.Pattern)
    assert result[0]['regex_source'] == r'^foo-\d+$'


# -----------------------------------------------------------------------------
# restrict_entry_accepted tests
# -----------------------------------------------------------------------------

RESTRICT_ENTRY_TESTS = [
    # (entry, restrict_data, expected)
    (
        {'chain': 'input'},
        [{'field': 'chain', 'match_disabled': False, 'invert': False}],
        False,  # No values specified, so no match
    ),
    (
        {'chain': 'input'},
        [{'field': 'chain', 'match_disabled': False, 'invert': True}],
        True,  # Invert: no values means match everything
    ),
    (
        {'chain': 'input'},
        [{'field': 'chain', 'match_disabled': False, 'invert': False, 'values': ['input']}],
        True,  # Matches value
    ),
    (
        {'chain': 'forward'},
        [{'field': 'chain', 'match_disabled': False, 'invert': False, 'values': ['input']}],
        False,  # Does not match value
    ),
    (
        {'chain': 'forward'},
        [{'field': 'chain', 'match_disabled': False, 'invert': True, 'values': ['input']}],
        True,  # Inverted: doesn't match 'input', so passes
    ),
    (
        {'comment': 'foo'},
        [{'field': 'comment', 'match_disabled': True, 'invert': False}],
        False,  # comment is 'foo' not None, match_disabled only matches None
    ),
    (
        {},  # comment field missing
        [{'field': 'comment', 'match_disabled': True, 'invert': False}],
        True,  # Missing field with match_disabled matches
    ),
    (
        {'comment': None},
        [{'field': 'comment', 'match_disabled': True, 'invert': False}],
        True,  # None with match_disabled matches
    ),
    (
        {'comment': None},
        [{'field': 'comment', 'match_disabled': False, 'invert': False}],
        False,  # None without match_disabled does not match
    ),
    (
        {'chain': 'input'},
        [
            {'field': 'chain', 'match_disabled': False, 'invert': False, 'values': ['input']},
            {'field': 'action', 'match_disabled': False, 'invert': False, 'values': ['drop']},
        ],
        False,  # Must match ALL rules, action doesn't match
    ),
    (
        {'chain': 'input', 'action': 'drop'},
        [
            {'field': 'chain', 'match_disabled': False, 'invert': False, 'values': ['input']},
            {'field': 'action', 'match_disabled': False, 'invert': False, 'values': ['drop']},
        ],
        True,  # Matches all rules
    ),
]


@pytest.mark.parametrize('entry, restrict_data, expected', RESTRICT_ENTRY_TESTS)
def test_restrict_entry_accepted(entry, restrict_data, expected):
    """Test restrict_entry_accepted function."""
    result = restrict_entry_accepted(entry, TEST_PATH_DATA, restrict_data)
    assert result == expected, f"Expected {expected} for {entry}, got {result}"


def test_restrict_entry_accepted_regex():
    """Test restrict_entry_accepted with regex matching."""
    entry = {'comment': 'foo-123'}
    restrict_data = [{
        'field': 'comment',
        'match_disabled': False,
        'invert': False,
        'regex': re.compile(r'^foo-\d+$'),
    }]
    result = restrict_entry_accepted(entry, TEST_PATH_DATA, restrict_data)
    assert result is True

    entry = {'comment': 'bar-123'}
    result = restrict_entry_accepted(entry, TEST_PATH_DATA, restrict_data)
    assert result is False


def test_restrict_entry_accepted_multiple_rules_all_must_pass():
    """Test that all restrict rules must pass."""
    entry = {'chain': 'input', 'action': 'accept'}
    restrict_data = [
        {'field': 'chain', 'match_disabled': False, 'invert': False, 'values': ['input']},
        {'field': 'action', 'match_disabled': False, 'invert': False, 'values': ['drop']},
    ]
    result = restrict_entry_accepted(entry, TEST_PATH_DATA, restrict_data)
    assert result is False  # action doesn't match

    entry = {'chain': 'input', 'action': 'drop'}
    result = restrict_entry_accepted(entry, TEST_PATH_DATA, restrict_data)
    assert result is True  # Both match


def test_restrict_entry_accepted_empty_restrict():
    """Test restrict_entry_accepted with empty restrict data."""
    entry = {'chain': 'input', 'action': 'drop'}
    restrict_data = []
    result = restrict_entry_accepted(entry, TEST_PATH_DATA, restrict_data)
    # Empty restrict should accept everything
    assert result is True


def test_restrict_entry_accepted_with_invert_and_regex():
    """Test restrict_entry_accepted with inverted regex."""
    entry = {'comment': 'bar-123'}
    restrict_data = [{
        'field': 'comment',
        'match_disabled': False,
        'invert': True,
        'regex': re.compile(r'^foo-\d+$'),
    }]
    result = restrict_entry_accepted(entry, TEST_PATH_DATA, restrict_data)
    assert result is True  # Doesn't match regex, but inverted means accept

    entry = {'comment': 'foo-123'}
    result = restrict_entry_accepted(entry, TEST_PATH_DATA, restrict_data)
    assert result is False  # Matches regex, but inverted means reject


def test_restrict_entry_accepted_none_returns_true():
    """restrict_data=None means no filtering, accept everything."""
    assert restrict_entry_accepted({'chain': 'input'}, TEST_PATH_DATA, None) is True


def test_restrict_entry_accepted_falls_back_to_default():
    """When the entry omits the field and the field has a default, the
    default is matched against the rule values."""
    path = VersionedAPIData(
        fields={'mode': KeyInfo(default='auto')},
    )
    restrict_data = [{
        'field': 'mode',
        'match_disabled': False,
        'invert': False,
        'values': ['auto'],
    }]
    assert restrict_entry_accepted({}, path, restrict_data, compat=True) is True

    restrict_data[0]['values'] = ['manual']
    assert restrict_entry_accepted({}, path, restrict_data, compat=True) is False


def test_restrict_entry_accepted_falls_back_to_absent_value():
    """When the field is missing from the entry and absent_value is set,
    absent_value is matched."""
    path = VersionedAPIData(
        fields={'note': KeyInfo(absent_value='ABSENT')},
    )
    restrict_data = [{
        'field': 'note',
        'match_disabled': False,
        'invert': False,
        'values': ['ABSENT'],
    }]
    assert restrict_entry_accepted({}, path, restrict_data, compat=True) is True
    # Field present overrides absent_value
    assert restrict_entry_accepted({'note': 'other'}, path, restrict_data, compat=True) is False


def test_restrict_entry_accepted_compat_false_string_compare():
    """With compat=False, integer entry values are stringified before
    matching against string values."""
    path = VersionedAPIData(
        fields={'count': KeyInfo()},
    )
    restrict_data = [{
        'field': 'count',
        'match_disabled': False,
        'invert': False,
        'values': ['5'],
    }]
    assert restrict_entry_accepted({'count': 5}, path, restrict_data, compat=False) is True
    # In compat=True, raw int 5 is checked against ['5'] -> no match
    assert restrict_entry_accepted({'count': 5}, path, restrict_data, compat=True) is False


# -----------------------------------------------------------------------------
# apply_value_sanitizer tests
# -----------------------------------------------------------------------------

def test_apply_value_sanitizer_no_sanitizer_returns_value_unchanged():
    ki = KeyInfo()
    assert apply_value_sanitizer(ki, 'foo', 'name') == 'foo'
    assert apply_value_sanitizer(ki, None, 'name') is None


def test_apply_value_sanitizer_applies_sanitizer():
    ki = KeyInfo(value_sanitizer=lambda v: '/' + v if isinstance(v, str) and not v.startswith('/') else v)
    assert apply_value_sanitizer(ki, 'foo', 'src') == '/foo'
    assert apply_value_sanitizer(ki, '/already', 'src') == '/already'


def test_apply_value_sanitizer_warns_on_change():
    warnings = []
    ki = KeyInfo(value_sanitizer=lambda v: v.upper() if isinstance(v, str) else v)
    result = apply_value_sanitizer(ki, 'foo', 'name', warn=warnings.append)
    assert result == 'FOO'
    assert len(warnings) == 1
    assert 'name' in warnings[0]
    assert "'foo'" in warnings[0]
    assert "'FOO'" in warnings[0]


def test_apply_value_sanitizer_no_warn_when_unchanged():
    warnings = []
    ki = KeyInfo(value_sanitizer=lambda v: v)
    result = apply_value_sanitizer(ki, 'foo', 'name', warn=warnings.append)
    assert result == 'foo'
    assert warnings == []


def test_apply_value_sanitizer_warn_none_is_silent():
    """warn=None must not raise even when the value changes."""
    ki = KeyInfo(value_sanitizer=lambda v: v.upper() if isinstance(v, str) else v)
    assert apply_value_sanitizer(ki, 'foo', 'name', warn=None) == 'FOO'


# -----------------------------------------------------------------------------
# restrict_argument_spec tests
# -----------------------------------------------------------------------------

def test_restrict_argument_spec_shape():
    spec = restrict_argument_spec()
    assert 'restrict' in spec
    restrict = spec['restrict']
    assert restrict['type'] == 'list'
    assert restrict['elements'] == 'dict'
    options = restrict['options']
    assert set(options.keys()) == {'field', 'match_disabled', 'values', 'regex', 'invert'}
    assert options['field']['required'] is True
    assert options['match_disabled']['default'] is False
    assert options['invert']['default'] is False
    assert options['values']['type'] == 'list'
