# -*- coding: utf-8 -*-

"""Comprehensive tests for _api_helper.py functions."""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import re
import pytest

from ansible_collections.community.routeros.plugins.module_utils._api_data import PATHS
from ansible_collections.community.routeros.plugins.module_utils._api_helper import (
    value_to_str,
    _test_rule_except_invert,
    validate_and_prepare_restrict,
    restrict_entry_accepted,
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
    # Handle both positional and keyword argument styles
    if isinstance(kwargs, dict) and len(kwargs) <= 2:
        result = value_to_str(value, **kwargs)
    else:
        # Last element is expected, rest are kwargs
        expected = kwargs
        kwargs = {}
        result = value_to_str(value)
    assert result == expected, f"Expected {expected!r} for {value!r} with {kwargs}, got {result!r}"


def test_value_to_str_simple_cases():
    """Test simple value_to_str cases."""
    assert value_to_str(None) is None
    assert value_to_str(None, none_to_empty=True) == ''
    assert value_to_str('') == ''
    assert value_to_str('foo') == 'foo'


def test_value_to_str_booleans():
    """Test value_to_str boolean handling."""
    assert value_to_str(True) == 'yes'
    assert value_to_str(False) == 'no'
    assert value_to_str(True, compat_bool=True) == 'true'
    assert value_to_str(False, compat_bool=True) == 'false'
    assert value_to_str(True, compat_bool=False) == 'yes'
    assert value_to_str(False, compat_bool=False) == 'no'


def test_value_to_str_numbers():
    """Test value_to_str number handling."""
    assert value_to_str(0) == '0'
    assert value_to_str(1) == '1'
    assert value_to_str(-42) == '-42'
    assert value_to_str(3.14) == '3.14'
    assert value_to_str(1.0) == '1.0'


def test_value_to_str_collections():
    """Test value_to_str collection handling."""
    assert value_to_str([]) == '[]'
    assert value_to_str({}) == '{}'
    assert value_to_str(['a', 'b']) == "['a', 'b']"
    assert value_to_str({'key': 'value'}) == "{'key': 'value'}"


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
    # 'test' with invert=True, values=['test']: matches values, returns True (invert not handled here)
    ('test', {'field': 'foo', 'match_disabled': False, 'invert': True, 'values': ['test']}, False, True),
    # 'test' with invert=False, values=['test']: matches values, returns True
    ('test', {'field': 'foo', 'match_disabled': False, 'invert': False, 'values': ['test']}, False, True),
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
