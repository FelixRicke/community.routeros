# -*- coding: utf-8 -*-

"""Comprehensive tests for _api_data.py with version simulation."""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import pytest

from ansible_collections.community.routeros.plugins.module_utils._api_data import (
    APIData,
    VersionedAPIData,
    KeyInfo,
    Depr,
    _compare,
    _sanitize_ensure_leading_slash,
    split_path,
    join_path,
    PATHS,
)
from ansible_collections.community.routeros.plugins.module_utils.version import LooseVersion

# Test versions for versioned testing
TEST_VERSIONS = ['7.0', '7.5', '7.15', '7.20', '7.22', '8.0']


# -----------------------------------------------------------------------------
# _compare function tests
# -----------------------------------------------------------------------------

COMPARE_TESTS = [
    (5, 3, '==', False),
    (5, 3, '!=', True),
    (5, 3, '<', False),
    (5, 3, '<=', False),
    (5, 3, '>', True),
    (5, 3, '>=', True),
    (3, 5, '==', False),
    (3, 5, '!=', True),
    (3, 5, '<', True),
    (3, 5, '<=', True),
    (3, 5, '>', False),
    (3, 5, '>=', False),
    (5, 5, '==', True),
    (5, 5, '!=', False),
    (5, 5, '<', False),
    (5, 5, '<=', True),
    (5, 5, '>', False),
    (5, 5, '>=', True),
]


@pytest.mark.parametrize('a, b, op, expected', COMPARE_TESTS)
def test_compare_operators(a, b, op, expected):
    """Test all comparison operators."""
    result = _compare(a, b, op)
    assert result == expected


def test_compare_invalid_operator():
    """Test that invalid operator raises ValueError."""
    with pytest.raises(ValueError) as exc:
        _compare(5, 3, 'invalid')
    assert 'Unknown comparator' in str(exc.value.args[0])


# -----------------------------------------------------------------------------
# split_path and join_path tests
# -----------------------------------------------------------------------------

SPLIT_JOIN_TESTS = [
    ('', [], ''),
    ('  ip  ', ['ip'], 'ip'),
    ('ip', ['ip'], 'ip'),
    ('  ip \t\n\raddress  ', ['ip', 'address'], 'ip address'),
    ('interface bridge port', ['interface', 'bridge', 'port'], 'interface bridge port'),
    ('ip firewall filter', ['ip', 'firewall', 'filter'], 'ip firewall filter'),
]


@pytest.mark.parametrize('joined, split_expected, rejoin_expected', SPLIT_JOIN_TESTS)
def test_split_path(joined, split_expected, rejoin_expected):
    """Test path splitting."""
    result = split_path(joined)
    assert result == split_expected


@pytest.mark.parametrize('joined, split_expected, rejoin_expected', SPLIT_JOIN_TESTS)
def test_join_path(joined, split_expected, rejoin_expected):
    """Test path joining."""
    result = join_path(split_expected)
    assert result == rejoin_expected


def test_split_join_roundtrip():
    """Test that split_path(join_path(x)) == x."""
    paths = [
        ('ip', 'address'),
        ('interface', 'bridge', 'port'),
        ('caps-man', 'access-list'),
    ]
    for path_tuple in paths:
        joined = join_path(path_tuple)
        split = split_path(joined)
        assert split == list(path_tuple)


# -----------------------------------------------------------------------------
# KeyInfo comprehensive tests
# -----------------------------------------------------------------------------

def test_keyinfo_basic():
    """Test basic KeyInfo creation."""
    ki = KeyInfo()
    assert ki.can_disable is False
    assert ki.remove_value is None
    assert ki.absent_value is None
    assert ki.default is None
    assert ki.required is False
    assert ki.automatically_computed_from is None
    assert ki.read_only is False
    assert ki.write_only is False


def test_keyinfo_with_values():
    """Test KeyInfo with various values."""
    ki = KeyInfo(
        can_disable=True,
        remove_value='',
        default='auto',
    )
    assert ki.can_disable is True
    assert ki.remove_value == ''
    assert ki.default == 'auto'


def test_keyinfo_positional_args_error():
    """Test that positional arguments raise error."""
    with pytest.raises(ValueError) as exc:
        KeyInfo('foo')
    assert 'does not have positional arguments' in str(exc.value.args[0])


def test_keyinfo_remove_value_requires_can_disable():
    """Test remove_value requires can_disable=True."""
    with pytest.raises(ValueError) as exc:
        KeyInfo(remove_value='')
    assert 'remove_value can only be specified if can_disable=True' in str(exc.value.args[0])


def test_keyinfo_read_write_exclusive():
    """Test read_only and write_only are exclusive."""
    with pytest.raises(ValueError) as exc:
        KeyInfo(read_only=True, write_only=True)
    assert 'read_only and write_only cannot be used at the same time' in str(exc.value.args[0])


def test_keyinfo_read_only_mutually_exclusive():
    """Test read_only cannot be combined with user-modifiable params."""
    with pytest.raises(ValueError) as exc:
        KeyInfo(read_only=True, required=True)
    assert 'read_only can not be combined with' in str(exc.value.args[0])

    with pytest.raises(ValueError) as exc:
        KeyInfo(read_only=True, default='foo')
    assert 'read_only can not be combined with' in str(exc.value.args[0])

    with pytest.raises(ValueError) as exc:
        KeyInfo(read_only=True, can_disable=True)
    assert 'read_only can not be combined with' in str(exc.value.args[0])


def test_keyinfo_mutually_exclusive_params():
    """Test required, default, automatically_computed_from are exclusive."""
    # required + default
    with pytest.raises(ValueError) as exc:
        KeyInfo(required=True, default='foo')
    assert 'mutually exclusive' in str(exc.value.args[0])

    # required + automatically_computed_from
    with pytest.raises(ValueError) as exc:
        KeyInfo(required=True, automatically_computed_from='other')
    assert 'mutually exclusive' in str(exc.value.args[0])

    # default + automatically_computed_from
    with pytest.raises(ValueError) as exc:
        KeyInfo(default='foo', automatically_computed_from='other')
    assert 'mutually exclusive' in str(exc.value.args[0])


def test_keyinfo_default_and_can_disable_together():
    """Test that default and can_disable can be combined."""
    # This should NOT raise
    ki = KeyInfo(default='auto', can_disable=True)
    assert ki.default == 'auto'
    assert ki.can_disable is True


def test_keyinfo_absent_value_exclusive():
    """Test absent_value cannot be combined with default, etc."""
    with pytest.raises(ValueError) as exc:
        KeyInfo(absent_value='', default='foo')
    assert 'absent_value can not be combined' in str(exc.value.args[0])

    with pytest.raises(ValueError) as exc:
        KeyInfo(absent_value='', can_disable=True)
    assert 'absent_value can not be combined' in str(exc.value.args[0])

    with pytest.raises(ValueError) as exc:
        KeyInfo(absent_value='', automatically_computed_from='other')
    assert 'absent_value can not be combined' in str(exc.value.args[0])


def test_keyinfo_value_sanitizer_callable():
    """Test value_sanitizer must be callable."""
    with pytest.raises(ValueError) as exc:
        KeyInfo(value_sanitizer='not callable')
    assert 'value_sanitizer must be a callable' in str(exc.value.args[0])


def test_keyinfo_value_sanitizer_not_with_read_only():
    """Test value_sanitizer cannot be used with read_only."""
    with pytest.raises(ValueError) as exc:
        KeyInfo(value_sanitizer=lambda x: x, read_only=True)
    assert 'value_sanitizer cannot be combined with read_only' in str(exc.value.args[0])


def test_keyinfo_value_sanitizer_not_with_write_only():
    """Test value_sanitizer cannot be used with write_only."""
    with pytest.raises(ValueError) as exc:
        KeyInfo(value_sanitizer=lambda x: x, write_only=True)
    assert 'value_sanitizer cannot be combined with write_only' in str(exc.value.args[0])


def test_keyinfo_value_sanitizer_attribute():
    """Test value_sanitizer is stored as attribute."""
    sanitizer = lambda x: x.upper() if isinstance(x, str) else x
    ki = KeyInfo(value_sanitizer=sanitizer)
    assert ki.value_sanitizer is sanitizer


# -----------------------------------------------------------------------------
# VersionedAPIData tests
# -----------------------------------------------------------------------------

def test_versioned_apidata_requires_fields():
    """Test that VersionedAPIData requires fields."""
    with pytest.raises(ValueError) as exc:
        VersionedAPIData()
    assert 'fields must be provided' in str(exc.value.args[0])


def test_versioned_apidata_primary_keys_mutually_exclusive():
    """Test primary_keys, stratify_keys, has_identifier, etc are exclusive."""
    base_fields = {'name': KeyInfo(), 'disabled': KeyInfo()}

    combinations = [
        {'primary_keys': ['name'], 'stratify_keys': ['disabled']},
        {'primary_keys': ['name'], 'has_identifier': True},
        {'primary_keys': ['name'], 'single_value': True},
        {'primary_keys': ['name'], 'unknown_mechanism': True},
        {'stratify_keys': ['name'], 'has_identifier': True},
        {'stratify_keys': ['name'], 'single_value': True},
        {'stratify_keys': ['name'], 'unknown_mechanism': True},
        {'has_identifier': True, 'single_value': True},
        {'has_identifier': True, 'unknown_mechanism': True},
        {'single_value': True, 'unknown_mechanism': True},
    ]

    for combo in combinations:
        with pytest.raises(ValueError) as exc:
            VersionedAPIData(fields=base_fields, **combo)
        assert 'mutually exclusive' in str(exc.value.args[0])


def test_versioned_apidata_unknown_understood_exclusive():
    """Test unknown_mechanism and fully_understood are exclusive."""
    with pytest.raises(ValueError) as exc:
        VersionedAPIData(
            fields={'name': KeyInfo()},
            unknown_mechanism=True,
            fully_understood=True,
        )
    assert 'unknown_mechanism and fully_understood cannot be combined' in str(exc.value.args[0])


def test_versioned_apidata_fixed_entries_requires_primary_keys():
    """Test fixed_entries requires primary_keys."""
    with pytest.raises(ValueError) as exc:
        VersionedAPIData(
            fields={'name': KeyInfo()},
            fixed_entries=True,
        )
    assert 'fixed_entries can only be used with primary_keys' in str(exc.value.args[0])


def test_versioned_apidata_primary_key_in_fields():
    """Test primary key must be in fields."""
    with pytest.raises(ValueError) as exc:
        VersionedAPIData(
            fields={'name': KeyInfo()},
            primary_keys=['nonexistent'],
        )
    assert 'Primary key nonexistent must be in fields' in str(exc.value.args[0])


def test_versioned_apidata_stratify_key_in_fields():
    """Test stratify key must be in fields."""
    with pytest.raises(ValueError) as exc:
        VersionedAPIData(
            fields={'name': KeyInfo()},
            stratify_keys=['nonexistent'],
        )
    assert 'Stratify key nonexistent must be in fields' in str(exc.value.args[0])


def test_versioned_apidata_required_one_of_format():
    """Test required_one_of element format."""
    with pytest.raises(ValueError) as exc:
        VersionedAPIData(
            fields={'name': KeyInfo()},
            required_one_of=['not_a_list'],  # Should be [['name']]
        )
    assert 'must be a list' in str(exc.value.args[0])


def test_versioned_apidata_required_one_of_in_fields():
    """Test required_one_of key must be in fields."""
    with pytest.raises(ValueError) as exc:
        VersionedAPIData(
            fields={'name': KeyInfo()},
            required_one_of=[['nonexistent']],
        )
    assert 'Require one of key nonexistent must be in fields' in str(exc.value.args[0])


def test_versioned_apidata_mutually_exclusive_format():
    """Test mutually_exclusive element format."""
    with pytest.raises(ValueError) as exc:
        VersionedAPIData(
            fields={'name': KeyInfo()},
            mutually_exclusive=['not_a_list'],
        )
    assert 'must be a list' in str(exc.value.args[0])


def test_versioned_apidata_mutually_exclusive_in_fields():
    """Test mutually_exclusive key must be in fields."""
    with pytest.raises(ValueError) as exc:
        VersionedAPIData(
            fields={'name': KeyInfo()},
            mutually_exclusive=[['nonexistent']],
        )
    assert 'Mutually exclusive key nonexistent must be in fields' in str(exc.value.args[0])


def test_versioned_apidata_versioned_fields_format():
    """Test versioned_fields must be a list."""
    with pytest.raises(ValueError) as exc:
        VersionedAPIData(
            fields={'name': KeyInfo()},
            versioned_fields=('not', 'a', 'list'),  # Should be a list
        )
    assert 'unversioned_fields must be a list' in str(exc.value.args[0])


def test_versioned_apidata_versioned_fields_conditions_format():
    """Test versioned_fields conditions must be list/tuple."""
    with pytest.raises(ValueError) as exc:
        VersionedAPIData(
            fields={'name': KeyInfo()},
            versioned_fields=[
                ('not_a_list', 'new_field', KeyInfo()),
            ],
        )
    assert 'conditions must be a list or tuple' in str(exc.value.args[0])


def test_versioned_apidata_versioned_fields_field_not_keyinfo():
    """versioned_fields entries must contain a KeyInfo as field."""
    with pytest.raises(ValueError) as exc:
        VersionedAPIData(
            fields={'name': KeyInfo()},
            versioned_fields=[
                ([('7.0', '>=')], 'new_field', 'not_a_keyinfo'),
            ],
        )
    assert 'field must be a KeyInfo object' in str(exc.value.args[0])


def test_versioned_apidata_versioned_fields_name_collision():
    """A field name appearing both in fields and versioned_fields raises."""
    with pytest.raises(ValueError) as exc:
        VersionedAPIData(
            fields={'name': KeyInfo()},
            versioned_fields=[
                ([('7.0', '>=')], 'name', KeyInfo()),
            ],
        )
    assert 'appears both in fields and versioned_fields' in str(exc.value.args[0])


def test_versioned_apidata_needs_version_flag():
    """needs_version is True when versioned_fields is non-empty."""
    plain = VersionedAPIData(fields={'name': KeyInfo()})
    assert plain.needs_version is False

    with_versioned = VersionedAPIData(
        fields={'name': KeyInfo()},
        versioned_fields=[([('7.0', '>=')], 'extra', KeyInfo())],
    )
    assert with_versioned.needs_version is True


def test_versioned_apidata_happy_paths():
    """Smoke-test that valid combinations construct without error."""
    # single_value
    sv = VersionedAPIData(single_value=True, fields={'name': KeyInfo()})
    assert sv.single_value is True
    # unknown_mechanism
    um = VersionedAPIData(unknown_mechanism=True, fields={'name': KeyInfo()})
    assert um.unknown_mechanism is True
    # stratify_keys
    sk = VersionedAPIData(stratify_keys=['name'], fields={'name': KeyInfo()})
    assert sk.stratify_keys == ['name']
    # fixed_entries with primary_keys
    fe = VersionedAPIData(
        primary_keys=['name'], fixed_entries=True,
        fields={'name': KeyInfo()},
    )
    assert fe.fixed_entries is True
    # required_one_of + mutually_exclusive
    cm = VersionedAPIData(
        fields={'a': KeyInfo(), 'b': KeyInfo()},
        required_one_of=[['a', 'b']],
        mutually_exclusive=[['a', 'b']],
    )
    assert cm.required_one_of == [['a', 'b']]
    assert cm.mutually_exclusive == [['a', 'b']]


# -----------------------------------------------------------------------------
# APIData tests
# -----------------------------------------------------------------------------

def test_apidata_unversioned_basic():
    """Test basic unversioned APIData."""
    apidata = APIData(
        unversioned=VersionedAPIData(
            fully_understood=True,
            fields={'name': KeyInfo(), 'disabled': KeyInfo()},
        )
    )
    assert apidata.fully_understood is True
    assert apidata.needs_version is False
    assert apidata.has_identifier is False

    fully_understood, error = apidata.provide_version('7.0')
    assert fully_understood is True
    assert error is None
    assert apidata.get_data() is not None


def test_apidata_versioned_basic():
    """Test basic versioned APIData."""
    apidata = APIData(
        versioned=[
            ('7.0', '>=', VersionedAPIData(
                fully_understood=True,
                fields={'name': KeyInfo()},
            )),
        ]
    )
    assert apidata.fully_understood is True
    assert apidata.needs_version is True

    fully_understood, error = apidata.provide_version('7.5')
    assert fully_understood is True
    data = apidata.get_data()
    assert data is not None


def test_apidata_versioned_no_match():
    """Test versioned APIData with no matching version."""
    apidata = APIData(
        versioned=[
            ('7.0', '>=', VersionedAPIData(
                fully_understood=True,
                fields={'name': KeyInfo()},
            )),
        ]
    )
    # Version 6.0 should not match 7.0 >=
    fully_understood, error = apidata.provide_version('6.0')
    assert fully_understood is False
    assert error is None


def test_apidata_versioned_with_fallback():
    """Test versioned APIData with fallback version."""
    apidata = APIData(
        versioned=[
            ('7.22', '>=', VersionedAPIData(
                fully_understood=True,
                fields={'new_field': KeyInfo()},
            )),
            ('7.0', '>=', VersionedAPIData(
                fully_understood=True,
                fields={'old_field': KeyInfo()},
            )),
            ('*', '*', VersionedAPIData(
                fully_understood=False,
                fields={'fallback_field': KeyInfo()},
            )),
        ]
    )

    # 7.22+ should use first
    fully_understood, _ = apidata.provide_version('7.22')
    assert fully_understood is True
    data = apidata.get_data()
    assert 'new_field' in data.fields

    # 7.5 should use second
    fully_understood, _ = apidata.provide_version('7.5')
    assert fully_understood is True
    data = apidata.get_data()
    assert 'old_field' in data.fields

    # 6.0 should use fallback
    fully_understood, _ = apidata.provide_version('6.0')
    assert fully_understood is False
    data = apidata.get_data()
    assert 'fallback_field' in data.fields


def test_apidata_versioned_fields():
    """Test VersionedAPIData with versioned_fields."""
    versioned = VersionedAPIData(
        fully_understood=True,
        fields={'name': KeyInfo()},
        versioned_fields=[
            ([('7.15', '>=')], 'new_field', KeyInfo(default='auto')),
            ([('7.0', '>='), ('7.22', '<')], 'mid_field', KeyInfo()),
        ]
    )

    # 7.10: only mid_field
    result = versioned.specialize_for_version(LooseVersion('7.10'))
    assert 'name' in result.fields
    assert 'mid_field' in result.fields
    assert 'new_field' not in result.fields

    # 7.15: both versioned fields
    result = versioned.specialize_for_version(LooseVersion('7.15'))
    assert 'name' in result.fields
    assert 'mid_field' in result.fields
    assert 'new_field' in result.fields

    # 7.22: only new_field
    result = versioned.specialize_for_version(LooseVersion('7.22'))
    assert 'name' in result.fields
    assert 'new_field' in result.fields
    assert 'mid_field' not in result.fields

    # 6.0: no versioned fields
    result = versioned.specialize_for_version(LooseVersion('6.0'))
    assert 'name' in result.fields
    assert 'mid_field' not in result.fields
    assert 'new_field' not in result.fields


def test_apidata_unversioned_and_versioned_mutually_exclusive():
    """Test that unversioned and versioned are mutually exclusive."""
    with pytest.raises(ValueError) as exc:
        APIData(
            unversioned=VersionedAPIData(fields={'name': KeyInfo()}),
            versioned=[('7.0', '>=', VersionedAPIData(fields={'name': KeyInfo()}))],
        )
    assert 'either unversioned or versioned must be provided' in str(exc.value.args[0])


def test_apidata_hardware_variants_requires_hardware_detect():
    """Test that hardware_variants requires hardware_detect."""
    with pytest.raises(ValueError) as exc:
        APIData(
            hardware_variants={
                'chip1': APIData(unversioned=VersionedAPIData(fields={'name': KeyInfo()})),
            }
        )
    assert 'hardware_detect required when hardware_variants is set' in str(exc.value.args[0])


def test_apidata_hardware_detect_without_variants():
    """Test that hardware_detect requires hardware_variants."""
    with pytest.raises(ValueError) as exc:
        APIData(
            hardware_detect='switch_chip_type',
        )
    assert 'hardware_detect requires hardware_variants' in str(exc.value.args[0])


def test_apidata_hardware_variants_must_be_apidata():
    """Test that hardware variant values must be APIData instances."""
    with pytest.raises(ValueError) as exc:
        APIData(
            hardware_detect='switch_chip_type',
            hardware_variants={
                'chip1': 'not_an_apidata',
            }
        )
    assert "hardware_variants['chip1'] must be an APIData instance" in str(exc.value.args[0])


def test_apidata_hardware_variants_no_nesting():
    """Test that hardware variants cannot be nested."""
    with pytest.raises(ValueError) as exc:
        APIData(
            hardware_detect='switch_chip_type',
            hardware_variants={
                'chip1': APIData(
                    hardware_detect='other',
                    hardware_variants={
                        'chip2': APIData(unversioned=VersionedAPIData(fields={'name': KeyInfo()})),
                    }
                ),
            }
        )
    assert "hardware_variants['chip1'] must not itself have hardware_variants" in str(exc.value.args[0])


def test_apidata_hardware_variants_basic():
    """Test basic hardware_variants functionality."""
    apidata = APIData(
        hardware_detect='chip_type',
        hardware_variants={
            'chip_a': APIData(unversioned=VersionedAPIData(
                fully_understood=True,
                fields={'name': KeyInfo(), 'chip_field': KeyInfo(default='A')},
            )),
            'chip_b': APIData(unversioned=VersionedAPIData(
                fully_understood=True,
                fields={'name': KeyInfo(), 'chip_field': KeyInfo(default='B')},
            )),
        }
    )
    assert apidata.hardware_detect == 'chip_type'
    assert 'chip_a' in apidata.hardware_variants
    assert 'chip_b' in apidata.hardware_variants
    assert apidata.fully_understood is True


def test_apidata_neither_unversioned_nor_versioned():
    """Test error when neither unversioned nor versioned is provided."""
    with pytest.raises(ValueError) as exc:
        APIData()
    assert 'either unversioned or versioned must be provided' in str(exc.value.args[0])


@pytest.mark.parametrize('version', TEST_VERSIONS)
def test_apidata_provide_version_all_versions(version):
    """Test provide_version works for all test versions."""
    apidata = APIData(
        unversioned=VersionedAPIData(
            fully_understood=True,
            fields={'name': KeyInfo()},
        )
    )
    fully_understood, error = apidata.provide_version(version)
    assert fully_understood is True
    assert error is None
    assert apidata.get_data() is not None


# -----------------------------------------------------------------------------
# Integration tests with PATHS
# -----------------------------------------------------------------------------

def test_paths_structure():
    """PATHS is a dict mapping tuple keys to APIData instances."""
    assert isinstance(PATHS, dict)
    assert len(PATHS) > 0
    for key, value in PATHS.items():
        assert isinstance(key, tuple), 'PATHS key {key!r} is not a tuple'.format(key=key)
        assert isinstance(value, APIData), 'PATHS[{key!r}] is not APIData'.format(key=key)


def test_provide_version_on_real_paths():
    """provide_version returns usable data for known PATHS entries."""
    test_paths = [
        ('ip', 'address'),
        ('interface', 'bridge'),
    ]
    seen = 0
    for path in test_paths:
        if path not in PATHS:
            continue
        seen += 1
        apidata = PATHS[path]
        fully_understood, error = apidata.provide_version('7.5')
        # error is the deprecated/removed-in-version message string when the
        # path resolves to a string fallback; in that case fully_understood
        # is False. Otherwise, get_data() must yield a usable VersionedAPIData.
        if error is None and fully_understood:
            data = apidata.get_data()
            assert isinstance(data, VersionedAPIData)
            assert isinstance(data.fields, dict)
    assert seen > 0, 'expected at least one of the test paths to exist in PATHS'


# -----------------------------------------------------------------------------
# Depr tests
# -----------------------------------------------------------------------------

def test_depr_default_context():
    d = Depr(version='3.0.0', msg='use foo instead')
    assert d.context == 'all'
    assert d.applies('read') is True
    assert d.applies('write') is True
    assert d.applies('all') is True


@pytest.mark.parametrize('context', ['read', 'write', 'all'])
def test_depr_valid_context(context):
    d = Depr(version='3.0.0', msg='x', context=context)
    assert d.context == context
    assert d.applies(context) is True


def test_depr_applies_scoped_context():
    d = Depr(version='3.0.0', msg='x', context='read')
    assert d.applies('read') is True
    assert d.applies('write') is False
    # 'all' check: applies returns True only when stored context matches
    # query, or stored context is 'all'. d.context='read' with query 'all'
    # is False per current implementation.
    assert d.applies('all') is False


def test_depr_invalid_context():
    with pytest.raises(ValueError) as exc:
        Depr(version='3.0.0', msg='x', context='somewhere')
    assert 'context must be all, read, or write' in str(exc.value.args[0])


def test_depr_emit_calls_module_deprecate():
    calls = []

    class FakeModule(object):
        def deprecate(self, msg, **kwargs):
            calls.append((msg, kwargs))

    d = Depr(version='3.0.0', msg='gone soon')
    d.emit(FakeModule())
    assert len(calls) == 1
    assert calls[0][0] == 'gone soon'
    assert calls[0][1].get('version') == '3.0.0'
    assert calls[0][1].get('collection_name') == 'community.routeros'


# -----------------------------------------------------------------------------
# KeyInfo with Depr
# -----------------------------------------------------------------------------

def test_keyinfo_depr_must_be_depr_instance():
    with pytest.raises(ValueError) as exc:
        KeyInfo(depr='not a Depr')
    assert 'depr must be a Depr instance' in str(exc.value.args[0])


def test_keyinfo_depr_stored():
    d = Depr(version='3.0.0', msg='x')
    ki = KeyInfo(depr=d)
    assert ki.depr is d


# -----------------------------------------------------------------------------
# _sanitize_ensure_leading_slash
# -----------------------------------------------------------------------------

@pytest.mark.parametrize('value, expected', [
    ('foo', '/foo'),
    ('foo/bar', '/foo/bar'),
    ('/foo', '/foo'),
    ('/', '/'),
    ('', ''),
    (None, None),
    (0, 0),
    (False, False),
    (['x'], ['x']),
])
def test_sanitize_ensure_leading_slash(value, expected):
    assert _sanitize_ensure_leading_slash(value) == expected


def test_sanitize_ensure_leading_slash_idempotent():
    once = _sanitize_ensure_leading_slash('foo')
    twice = _sanitize_ensure_leading_slash(once)
    assert once == twice == '/foo'


# -----------------------------------------------------------------------------
# APIData provide_version with string fallback in versioned tuples
# -----------------------------------------------------------------------------

def test_apidata_versioned_string_fallback():
    """A versioned entry whose data is a plain string is treated as a
    deprecation/error message: provide_version returns (False, msg)."""
    apidata = APIData(versioned=[
        ('7.0', '>=', VersionedAPIData(
            fully_understood=True,
            fields={'name': KeyInfo()},
        )),
        ('*', '*', 'this path was removed'),
    ])
    fully_understood, error = apidata.provide_version('6.0')
    assert fully_understood is False
    assert error == 'this path was removed'


def test_apidata_versioned_no_match_no_fallback():
    """When no versioned entry matches and there is no '*', '*' fallback,
    provide_version returns (False, None) and get_data() raises."""
    apidata = APIData(versioned=[
        ('7.0', '>=', VersionedAPIData(
            fully_understood=True,
            fields={'name': KeyInfo()},
        )),
    ])
    fully_understood, error = apidata.provide_version('6.0')
    assert fully_understood is False
    assert error is None
    with pytest.raises(ValueError):
        apidata.get_data()
