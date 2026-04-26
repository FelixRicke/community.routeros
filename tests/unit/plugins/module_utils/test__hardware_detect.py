# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import pytest

import ansible_collections.community.routeros.plugins.module_utils._hardware_detect as hw_mod
from ansible_collections.community.routeros.plugins.module_utils._hardware_detect import (
    clear_cache,
    detect_switch_chip_type,
    get_cached_or_detect,
)


class MockApiPath(object):
    """Mock for the result of api.path(route) -- an iterable of dicts."""
    def __init__(self, entries):
        self._entries = entries

    def __iter__(self):
        return iter(self._entries)


class MockApi(object):
    """Minimal mock of a librouteros API connection.

    Parameters
    ----------
    switch_entries : list[dict]
        Entries returned for ``/interface/ethernet/switch``.
    pi_entries : list[dict] or None
        Entries returned for ``/interface/ethernet/switch/port-isolation``.
        If None and ``pi_raises`` is False, returns an empty list.
    pi_raises : bool
        If True, querying port-isolation raises an Exception.
    raises_on_switch : bool
        If True, querying the switch path raises an Exception.
    """
    def __init__(self, switch_entries=None, pi_entries=None, pi_raises=False, raises_on_switch=False):
        self._switch = switch_entries or []
        self._pi = pi_entries if pi_entries is not None else []
        self._pi_raises = pi_raises
        self._raises_on_switch = raises_on_switch

    def path(self, route):
        if self._raises_on_switch and route == '/interface/ethernet/switch':
            raise Exception('connection lost')
        if route == '/interface/ethernet/switch':
            return MockApiPath(self._switch)
        if route == '/interface/ethernet/switch/port-isolation':
            if self._pi_raises:
                raise Exception('port-isolation error')
            return MockApiPath(self._pi)
        return MockApiPath([])


@pytest.fixture(autouse=True)
def _clear_detection_cache():
    """Ensure the module-level cache is empty before and after each test."""
    clear_cache()
    yield
    clear_cache()


@pytest.fixture
def counting_detector():
    """Replace the registered switch_chip_type detector with a counter that
    delegates to the real implementation. Yields a list whose only element
    is the call count."""
    call_count = [0]
    original = hw_mod.HARDWARE_DETECTORS['switch_chip_type']

    def counting(api):
        call_count[0] += 1
        return detect_switch_chip_type(api)

    hw_mod.HARDWARE_DETECTORS['switch_chip_type'] = counting
    try:
        yield call_count
    finally:
        hw_mod.HARDWARE_DETECTORS['switch_chip_type'] = original


# -----------------------------------------------------------------------------
# detect_switch_chip_type
# -----------------------------------------------------------------------------

def test_detect_single_entry_no_name_field():
    """One switch entry + port-isolation entries without 'name' -> single_entry_switch."""
    api = MockApi(
        switch_entries=[{'.id': '*1', 'name': 'switch1'}],
        pi_entries=[{'forwarding': 'enabled'}, {'forwarding': 'disabled'}],
    )
    assert detect_switch_chip_type(api) == 'single_entry_switch'


def test_detect_single_entry_empty_port_isolation():
    """One switch entry + empty port-isolation -> single_entry_switch
    (no entry exposes a 'name' field, so multi-entry is not implied)."""
    api = MockApi(switch_entries=[{'.id': '*1', 'name': 'sw1'}], pi_entries=[])
    assert detect_switch_chip_type(api) == 'single_entry_switch'


def test_detect_single_entry_with_name_field():
    """One switch entry + port-isolation entries WITH 'name' -> multi_entry_switch."""
    api = MockApi(
        switch_entries=[{'.id': '*1', 'name': 'switch1'}],
        pi_entries=[{'name': 'ether1', 'forwarding': 'enabled'}],
    )
    assert detect_switch_chip_type(api) == 'multi_entry_switch'


def test_detect_multiple_entries():
    """More than one switch entry -> multi_entry_switch (no port-isolation check)."""
    api = MockApi(
        switch_entries=[{'.id': '*1', 'name': 'sw1'}, {'.id': '*2', 'name': 'sw2'}],
    )
    assert detect_switch_chip_type(api) == 'multi_entry_switch'


def test_detect_zero_entries():
    """Empty switch list -> multi_entry_switch (safe modern default)."""
    api = MockApi(switch_entries=[])
    assert detect_switch_chip_type(api) == 'multi_entry_switch'


def test_detect_port_isolation_raises_falls_back_to_multi():
    """One switch entry but port-isolation query raises -> multi_entry_switch."""
    api = MockApi(
        switch_entries=[{'.id': '*1', 'name': 'sw1'}],
        pi_raises=True,
    )
    assert detect_switch_chip_type(api) == 'multi_entry_switch'


def test_detect_switch_query_raises_falls_back_to_multi():
    """API error on switch query -> safe default multi_entry_switch."""
    api = MockApi(raises_on_switch=True)
    assert detect_switch_chip_type(api) == 'multi_entry_switch'


# -----------------------------------------------------------------------------
# get_cached_or_detect / clear_cache
# -----------------------------------------------------------------------------

def test_get_cached_or_detect_returns_detector_value():
    api = MockApi(switch_entries=[{'name': 'sw1'}, {'name': 'sw2'}])
    assert get_cached_or_detect('switch_chip_type', api) == 'multi_entry_switch'


def test_get_cached_or_detect_caches_per_api(counting_detector):
    api = MockApi(switch_entries=[{'name': 'sw1'}])
    first = get_cached_or_detect('switch_chip_type', api)
    second = get_cached_or_detect('switch_chip_type', api)
    assert counting_detector[0] == 1
    assert first == second


def test_get_cached_or_detect_distinct_apis_get_separate_entries(counting_detector):
    """Cache keys include the api connection identity, so separate api
    instances trigger separate detector calls."""
    api1 = MockApi(switch_entries=[{'name': 'sw1'}])
    api2 = MockApi(switch_entries=[{'name': 'sw1'}])
    get_cached_or_detect('switch_chip_type', api1)
    get_cached_or_detect('switch_chip_type', api2)
    assert counting_detector[0] == 2


def test_clear_cache_forces_redetection(counting_detector):
    api = MockApi(switch_entries=[{'name': 'sw1'}])
    get_cached_or_detect('switch_chip_type', api)
    assert counting_detector[0] == 1
    clear_cache()
    get_cached_or_detect('switch_chip_type', api)
    assert counting_detector[0] == 2


def test_get_cached_or_detect_unknown_detector_raises():
    api = MockApi()
    with pytest.raises(KeyError):
        get_cached_or_detect('does_not_exist', api)
