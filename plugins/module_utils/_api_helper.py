# -*- coding: utf-8 -*-
# Copyright (c) 2022, Felix Fontein (@felixfontein) <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# The data inside here is private to this collection. If you use this from outside the collection,
# you are on your own. There can be random changes to its format even in bugfix releases!

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import re

from ansible.module_utils.common.text.converters import to_text

"""
Helper functions for the MikroTik RouterOS collection's API layer.

This module provides utility functions used across plugins to handle:

- Value conversion: ``value_to_str`` converts Python values to their
  string representations as expected by the RouterOS API, with special
  handling for boolean values (true/false vs yes/no).

- Restrict filter handling: ``validate_and_prepare_restrict`` validates
  and prepares restrict filter rules from module parameters.
  ``restrict_entry_accepted`` evaluates whether a RouterOS entry matches
  the configured restrict filters.

- Value sanitization: ``apply_value_sanitizer`` applies registered value
  sanitizers to normalize field values before API operations.
"""


def value_to_str(value, compat_bool=False, none_to_empty=False):
    """Convert a Python value to its string representation for RouterOS API.

    Boolean values are converted to either ``true``/``false`` or ``yes``/``no``
    depending on the ``compat_bool`` flag:

    - ``compat_bool=False`` (default): Returns ``'yes'`` for ``True``,
      ``'no'`` for ``False`` (Ansible-style).
    - ``compat_bool=True``: Returns ``'true'`` for ``True``, ``'false'``
      for ``False`` (RouterOS API style).

    Examples
    --------
    >>> value_to_str(True)
    'yes'
    >>> value_to_str(False)
    'no'
    >>> value_to_str(True, compat_bool=True)
    'true'
    >>> value_to_str(False, compat_bool=True)
    'false'
    >>> value_to_str(None)
    None
    >>> value_to_str(None, none_to_empty=True)
    ''
    >>> value_to_str('hello')
    'hello'

    Parameters
    ----------
    value : any
        The value to convert. ``None``, ``True``, and ``False`` are handled
        specially; all other values are converted using ``to_text``.
    compat_bool : bool, optional
        If ``True``, use RouterOS API boolean format (``true``/``false``).
        If ``False``, use Ansible-style format (``yes``/``no``).
    none_to_empty : bool, optional
        If ``True`` and value is ``None``, return empty string ``''``.
        If ``False`` (default), return ``None`` unchanged.

    Returns
    -------
    str or None
        The string representation, or ``None`` if the input was ``None``
        and ``none_to_empty=False``.
    """
    if value is None:
        return '' if none_to_empty else None
    if value is True:
        return 'true' if compat_bool else 'yes'
    if value is False:
        return 'false' if compat_bool else 'no'
    return to_text(value)


def validate_and_prepare_restrict(module, path_info, compat=True):
    """Validate and compile restrict filter rules from module parameters.

    Module Integration Contract
    ---------------------------
    This function is called by Ansible plugins that support the ``restrict``
    parameter. It expects:

    **Input requirements:**
    - ``module.params['restrict']``: A list of restrict rule dictionaries, or
      ``None`` if the parameter was not specified.
    - Each rule dictionary must contain:
      - ``field``: Field name (string, must exist in ``path_info.fields``)
      - ``match_disabled``: Boolean for handling ``None`` values
      - ``invert``: Boolean to negate the match result
      - ``values``: List of values to match, or ``None``
      - ``regex``: Regular expression string, or ``None``

    **Processing:**
    1. Validates that each field exists in ``path_info.fields``.
    2. Ensures field names do not start with ``!`` (use ``invert`` instead).
    3. Compiles ``regex`` patterns, failing on invalid expressions.
    4. Converts ``values`` to strings if ``compat=False``.

    **Output:**
    Returns a list of compiled rules with:
    - ``field``: Field name (string)
    - ``match_disabled``: Boolean
    - ``invert``: Boolean
    - ``values``: List of string values, or absent if ``None``
    - ``regex``: Compiled regex pattern, or absent if ``None``
    - ``regex_source``: Original regex string (only if regex present)

    Parameters
    ----------
    module : AnsibleModule
        The Ansible module instance. ``module.params['restrict']`` is read,
        and ``module.fail_json`` is called on validation errors.
    path_info : PathInfo
        Metadata object containing field definitions. Used to validate that
        all referenced fields exist for the current API path.
    compat : bool, optional
        If ``True``, keep ``values`` as raw values (legacy behavior).
        If ``False``, convert all values to strings using ``value_to_str``.

    Returns
    -------
    list or None
        List of compiled restrict rules, or ``None`` if ``restrict`` parameter
        was not specified.

    Raises
    ------
    module.fail_json
        Called if a field does not exist, field name starts with ``!``, or
        regex compilation fails.

    See Also
    --------
    restrict_entry_accepted : Evaluate entries against compiled rules
    value_to_str : Convert values to string representation
    restrict_argument_spec : Argument spec definition for restrict parameter
    """
    restrict = module.params['restrict']
    if restrict is None:
        return None
    restrict_data = []
    for rule in restrict:
        field = rule['field']
        if field.startswith('!'):
            module.fail_json(msg='restrict: the field name "{0}" must not start with "!"'.format(field))
        f = path_info.fields.get(field)
        if f is None:
            module.fail_json(msg='restrict: the field "{0}" does not exist for this path'.format(field))

        new_rule = dict(
            field=field,
            match_disabled=rule['match_disabled'],
            invert=rule['invert'],
        )
        if rule['values'] is not None:
            if compat:
                new_rule['values'] = rule['values']
            else:
                new_rule['values'] = [value_to_str(v, none_to_empty=False) for v in rule['values']]
        if rule['regex'] is not None:
            regex = rule['regex']
            try:
                new_rule['regex'] = re.compile(regex)
                new_rule['regex_source'] = regex
            except Exception as exc:
                module.fail_json(msg='restrict: invalid regular expression "{0}": {1}'.format(regex, exc))
        restrict_data.append(new_rule)
    return restrict_data


def _test_rule_except_invert(value, rule, compat=False):
    if value is None and rule['match_disabled']:
        return True
    if 'values' in rule:
        v = value if compat else value_to_str(value, none_to_empty=False)
        if v in rule['values']:
            return True
    if 'regex' in rule and value is not None and rule['regex'].match(value_to_str(value, compat_bool=compat)):
        return True
    return False


def restrict_entry_accepted(entry, path_info, restrict_data, compat=True):
    """Evaluate whether a RouterOS entry passes all restrict filter rules.

    This function implements the filter evaluation flow for the ``restrict``
    parameter used across collection plugins to limit which RouterOS entries
    are returned or processed.

    Filter Evaluation Flow
    ----------------------
    1. **No filters**: If ``restrict_data`` is ``None``, the entry is accepted.

    2. **Per-rule evaluation**: For each rule in ``restrict_data``:
       a. Resolve the field value from the entry, falling back to the
          field's default or absent value if not present.
       b. Test the value against the rule using ``_test_rule_except_invert``:
          - Match against ``values`` list if specified
          - Match against ``regex`` pattern if specified
          - Handle ``match_disabled`` for ``None`` values
       c. Apply ``invert`` flag if set (negate the match result).
       d. If the (possibly inverted) result is ``False``, the entry is rejected.

    3. **Result**: If all rules pass (or there are no rules), the entry is accepted.

    A field must satisfy ALL restrict rules to be accepted (logical AND across
    rules). Within a single rule, matching any ``values`` entry or the ``regex``
    pattern constitutes a match (logical OR).

    Parameters
    ----------
    entry : dict
        The RouterOS API entry (dictionary of field name to value).
    path_info : PathInfo
        Metadata object containing field definitions with default and absent
        values for value resolution.
    restrict_data : list or None
        List of compiled restrict rules from ``validate_and_prepare_restrict``,
        or ``None`` if no filters were specified (accepts all entries).
    compat : bool, optional
        If ``True``, use compatibility mode for value comparison (raw values).
        If ``False``, convert values to strings before comparison.

    Returns
    -------
    bool
        ``True`` if the entry passes all restrict filters (or no filters),
        ``False`` if any rule rejects the entry.

    See Also
    --------
    validate_and_prepare_restrict : Validate and compile restrict rules
    _test_rule_except_invert : Test a single value against a rule
    """
    if restrict_data is None:
        return True
    for rule in restrict_data:
        # Obtain field and value
        field = rule['field']
        field_info = path_info.fields[field]
        value = entry.get(field)
        if value is None:
            value = field_info.default
        if field not in entry and field_info.absent_value:
            value = field_info.absent_value

        # Check
        matches_rule = _test_rule_except_invert(value, rule, compat=compat)
        if rule['invert']:
            matches_rule = not matches_rule
        if not matches_rule:
            return False
    return True


def restrict_argument_spec():
    return dict(
        restrict=dict(
            type='list',
            elements='dict',
            options=dict(
                field=dict(type='str', required=True),
                match_disabled=dict(type='bool', default=False),
                values=dict(type='list', elements='raw'),
                regex=dict(type='str'),
                invert=dict(type='bool', default=False),
            ),
        ),
    )


def apply_value_sanitizer(key_info, value, key_name, warn=None):
    """Apply ``key_info.value_sanitizer`` to *value* and warn on change.

    This is the central call-site for value sanitisation. It is intentionally
    kept separate from ``KeyInfo`` itself so that no specific plugin framework
    (e.g. ``AnsibleModule``) is ever imported by ``api_data.py``.

    Parameters
    ----------
    key_info : KeyInfo
        Metadata for the field being sanitised.
    value : any
        The value to sanitise. Non-string and ``None`` handling is delegated
        to the sanitizer itself. If no sanitizer is registered, *value* is
        returned unchanged.
    key_name : str
        Human-readable field name used in the warning message.
    warn : callable or None
        Optional warning function (e.g. ``module.warn``). Called with a
        single string message when the sanitizer modifies *value*. Pass
        ``None`` to suppress warnings entirely.

    Returns
    -------
    any
        The sanitised value, or *value* unchanged if no sanitizer is
        registered.
    """
    if key_info.value_sanitizer is None:
        return value

    sanitized = key_info.value_sanitizer(value)

    if warn is not None and sanitized != value:
        warn(
            'Value of field "{key}" was automatically normalised from {original!r} to '
            '{sanitized!r}. Consider updating your playbook to use the normalised '
            'value directly to avoid this warning.'.format(
                key=key_name,
                original=value,
                sanitized=sanitized,
            )
        )

    return sanitized
