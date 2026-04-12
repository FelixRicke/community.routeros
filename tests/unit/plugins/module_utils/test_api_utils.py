# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import ssl

import pytest
from unittest.mock import MagicMock, patch, call

import ansible_collections.community.routeros.plugins.module_utils.api as api_mod


def test_check_has_library_fails_when_missing():
    module = MagicMock()
    with patch.object(api_mod, 'HAS_LIB', False), \
         patch.object(api_mod, 'LIB_IMP_ERR', 'traceback text'):
        api_mod.check_has_library(module)
    module.fail_json.assert_called_once()
    args = module.fail_json.call_args
    assert 'librouteros' in args[1]['msg']
    assert args[1]['exception'] == 'traceback text'


def test_check_has_library_passes_when_present():
    module = MagicMock()
    with patch.object(api_mod, 'HAS_LIB', True):
        api_mod.check_has_library(module)
    module.fail_json.assert_not_called()


def test_ros_api_connect_force_no_cert():
    mock_connect = MagicMock(return_value=MagicMock())
    mock_ctx = MagicMock()
    module = MagicMock()

    with patch.object(api_mod, 'connect', mock_connect, create=True), \
         patch('ssl.create_default_context', return_value=mock_ctx):
        api_mod._ros_api_connect(
            module, 'admin', 'pass', '192.168.1.1', None,
            use_tls=True, force_no_cert=True, validate_certs=True,
            validate_cert_hostname=True, ca_path=None, encoding='ASCII', timeout=10,
        )

    assert mock_ctx.check_hostname is False
    mock_ctx.set_ciphers.assert_called_once_with("ADH:@SECLEVEL=0")
    mock_connect.assert_called_once()
    assert mock_connect.call_args[1]['ssl_wrapper'] == mock_ctx.wrap_socket


def test_ros_api_connect_no_validate_certs():
    mock_connect = MagicMock(return_value=MagicMock())
    mock_ctx = MagicMock()
    module = MagicMock()

    with patch.object(api_mod, 'connect', mock_connect, create=True), \
         patch('ssl.create_default_context', return_value=mock_ctx):
        api_mod._ros_api_connect(
            module, 'admin', 'pass', '192.168.1.1', None,
            use_tls=True, force_no_cert=False, validate_certs=False,
            validate_cert_hostname=True, ca_path=None, encoding='ASCII', timeout=10,
        )

    assert mock_ctx.check_hostname is False
    assert mock_ctx.verify_mode == ssl.CERT_NONE


def test_ros_api_connect_no_validate_cert_hostname():
    mock_connect = MagicMock(return_value=MagicMock())
    mock_ctx = MagicMock()
    module = MagicMock()

    with patch.object(api_mod, 'connect', mock_connect, create=True), \
         patch('ssl.create_default_context', return_value=mock_ctx):
        api_mod._ros_api_connect(
            module, 'admin', 'pass', '192.168.1.1', None,
            use_tls=True, force_no_cert=False, validate_certs=True,
            validate_cert_hostname=False, ca_path=None, encoding='ASCII', timeout=10,
        )

    assert mock_ctx.check_hostname is False
    # verify_mode should NOT be set to CERT_NONE
    mock_ctx.set_ciphers.assert_not_called()


def test_ros_api_connect_default_tls_hostname_wrap():
    mock_connect = MagicMock(return_value=MagicMock())
    mock_ctx = MagicMock()
    module = MagicMock()

    with patch.object(api_mod, 'connect', mock_connect, create=True), \
         patch('ssl.create_default_context', return_value=mock_ctx):
        api_mod._ros_api_connect(
            module, 'admin', 'pass', 'router.example.com', None,
            use_tls=True, force_no_cert=False, validate_certs=True,
            validate_cert_hostname=True, ca_path=None, encoding='ASCII', timeout=10,
        )

    # The custom wrap_context should have been passed as ssl_wrapper
    passed_wrapper = mock_connect.call_args[1]['ssl_wrapper']
    assert passed_wrapper is not mock_ctx.wrap_socket  # it's a custom closure

    # Call the wrapper and verify it passes server_hostname=host
    mock_socket = MagicMock()
    passed_wrapper(mock_socket, server_hostname='should_be_replaced')
    mock_ctx.wrap_socket.assert_called_once_with(mock_socket, server_hostname='router.example.com')


class FailJsonException(Exception):
    pass


def test_ros_api_connect_connection_error():
    mock_connect = MagicMock(side_effect=Exception('connection refused'))
    module = MagicMock()
    module.fail_json.side_effect = FailJsonException()

    with patch.object(api_mod, 'connect', mock_connect, create=True):
        with pytest.raises(FailJsonException):
            api_mod._ros_api_connect(
                module, 'admin', 'pass', '192.168.1.1', None,
                use_tls=False, force_no_cert=False, validate_certs=True,
                validate_cert_hostname=True, ca_path=None, encoding='ASCII', timeout=10,
            )
    module.fail_json.assert_called_once()
    args = module.fail_json.call_args
    assert 'Error while connecting' in args[1]['msg']
    assert 'connection' in args[1]


def test_get_api_version():
    mock_resource = [{'version': '7.15.2 (stable)'}]

    # api.path() returns an object whose .join('system', 'resource') returns an iterable
    mock_joined = MagicMock()
    mock_joined.__iter__ = MagicMock(return_value=iter(mock_resource))

    mock_path_obj = MagicMock()
    mock_path_obj.join.return_value = mock_joined

    mock_api = MagicMock()
    mock_api.path.return_value = mock_path_obj

    result = api_mod.get_api_version(mock_api)
    assert result == '7.15.2'
    mock_api.path.assert_called_once_with()
    mock_path_obj.join.assert_called_once_with('system', 'resource')
