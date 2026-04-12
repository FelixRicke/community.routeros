# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from unittest.mock import MagicMock, patch

import ansible_collections.community.routeros.plugins.module_utils._tagging as tagging_mod


def test_deprecate_value_without_support_returns_value_unchanged():
    with patch.object(tagging_mod, 'HAS_DEPRECATE_VALUE', False):
        result = tagging_mod.deprecate_value('foo', 'this is deprecated', '4.0.0')
    assert result == 'foo'


def test_deprecate_value_with_support_calls_underlying():
    mock_deprecate = MagicMock(return_value='tagged_bar')
    with patch.object(tagging_mod, 'HAS_DEPRECATE_VALUE', True), \
         patch.object(tagging_mod, '_deprecate_value', mock_deprecate, create=True):
        result = tagging_mod.deprecate_value('bar', 'deprecated msg', '5.0.0', help_text='see docs')
    assert result == 'tagged_bar'
    mock_deprecate.assert_called_once_with(
        'bar',
        'deprecated msg',
        collection_name='community.routeros',
        version='5.0.0',
        help_text='see docs',
    )


def test_deprecate_value_with_support_no_help_text():
    mock_deprecate = MagicMock(return_value='tagged_baz')
    with patch.object(tagging_mod, 'HAS_DEPRECATE_VALUE', True), \
         patch.object(tagging_mod, '_deprecate_value', mock_deprecate, create=True):
        result = tagging_mod.deprecate_value('baz', 'old field', '3.0.0')
    assert result == 'tagged_baz'
    mock_deprecate.assert_called_once_with(
        'baz',
        'old field',
        collection_name='community.routeros',
        version='3.0.0',
        help_text=None,
    )
