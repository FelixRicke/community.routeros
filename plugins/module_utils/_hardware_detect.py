# -*- coding: utf-8 -*-
# Copyright (c) 2026, Felix Ricke (@FelixRicke)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# The data inside here is private to this collection. If you use this from outside the collection,
# you are on your own. There can be random changes to its format even in bugfix releases!

from __future__ import absolute_import, division, print_function
__metaclass__ = type

"""Hardware detection functions for community.routeros.

This module provides hardware detection utilities for RouterOS devices.
Detection functions query the device via the API and return a string
variant key that is used to select the appropriate schema variant
from the ``PATHS`` registry in ``_api_data.py``.

Detection Flow
--------------
1. Module determines that a path requires hardware detection (via
   ``hardware_detect`` parameter in ``APIData``).
2. Module calls ``get_cached_or_detect()`` with the detector name.
3. If not cached, the detector function is called with the API connection.
4. Detector queries the device and returns a variant key string.
5. Result is cached and used to select the correct hardware variant
   from ``hardware_variants`` dictionary.

Cache
-----
Results are cached per (detector_name, connection) to avoid redundant
API calls when the same detector is used multiple times in a single
module run. The cache is keyed by detector name and API connection ID.

Detector Registry
-----------------
Detectors are registered in the ``HARDWARE_DETECTORS`` dictionary.
Each detector is a callable that takes an API connection object and
returns a string variant key.

See Also
--------
- ``_api_data.py``: ``APIData`` class with ``hardware_detect`` and
  ``hardware_variants`` parameters
- ``HARDWARE_DETECTOR_KEYS`` in ``_api_data.py``: Registry of valid
  detector names
"""

# Cache: keyed by (detector_name, connection_id) to support
# multiple connections in the same process (unlikely but safe).
_detection_cache = {}


def _cache_key(detector_name, api):
    """Build a cache key from the detector name and connection identity.

    The cache key combines the detector name with the API connection's
    object ID to support multiple connections in the same process.

    Parameters
    ----------
    detector_name : str
        Name of the detector (e.g., 'switch_chip_type').
    api : LibRouterosAPI
        The API connection object.

    Returns
    -------
    tuple
        A tuple of (detector_name, id(api)) used as cache key.
    """
    return (detector_name, id(api))


def get_cached_or_detect(detector_name, api):
    """Return cached detection result or run detection and cache it.

    This is the main entry point for hardware detection. It first checks
    the cache for a previous result, and if not found, runs the detector
    function and stores the result.

    Parameters
    ----------
    detector_name : str
        Name of the detector to use (must exist in HARDWARE_DETECTORS).
    api : LibRouterosAPI
        The API connection object used to query the device.

    Returns
    -------
    str
        The detected hardware variant key (e.g., 'single_entry_switch',
        'multi_entry_switch').

    Raises
    ------
    KeyError
        If detector_name is not registered in HARDWARE_DETECTORS.

    See Also
    --------
    HARDWARE_DETECTORS : Registry of available detectors
    clear_cache : Clear the detection cache
    """
    key = _cache_key(detector_name, api)
    if key not in _detection_cache:
        detector = HARDWARE_DETECTORS[detector_name]
        _detection_cache[key] = detector(api)
    return _detection_cache[key]


def clear_cache():
    """Clear the hardware detection cache.

    This function is primarily useful for testing, allowing you to
    reset the cache between test cases to ensure isolated detection
    runs.

    In normal module operation, the cache persists for the duration
    of the module run and is automatically discarded when the module
    exits.

    See Also
    --------
    get_cached_or_detect : Main detection entry point with caching
    """
    _detection_cache.clear()


# --- Individual detector implementations ---


def detect_switch_chip_type(api):
    """Detect whether the switch chip uses single-entry or multi-entry semantics.

    This detector distinguishes between two families of MikroTik CRS switches:

    **CRS1xx/2xx series** (e.g., QCA8519 chip):
        - ``/interface/ethernet/switch`` returns exactly one entry
        - Entry has no meaningful ``.id`` field
        - ``/interface/ethernet/switch/port-isolation`` has no per-port
          sub-entries with ``name`` field
        - Returns: ``'single_entry_switch'``

    **CRS3xx/5xx and others** (e.g., MT7621, 88E6393X chips):
        - ``/interface/ethernet/switch`` returns entries with ``.id`` and ``name``
        - ``/interface/ethernet/switch/port-isolation`` has per-port entries
          keyed by ``name`` field
        - Returns: ``'multi_entry_switch'``

    Detection Heuristic
    -------------------
    1. Query ``/interface/ethernet/switch``
    2. If exactly one entry:
       - Query ``/interface/ethernet/switch/port-isolation``
       - Check if any entry has a ``name`` field
       - Has ``name`` -> multi_entry_switch, otherwise -> single_entry_switch
    3. If not exactly one entry -> multi_entry_switch
    4. On any error -> multi_entry_switch (safe default for modern hardware)

    Parameters
    ----------
    api : LibRouterosAPI
        The API connection object used to query the device.

    Returns
    -------
    str
        Either ``'single_entry_switch'`` or ``'multi_entry_switch'``.
        Defaults to ``'multi_entry_switch'`` on detection failure.

    See Also
    --------
    HARDWARE_DETECTORS : Registry containing this detector
    """
    try:
        result = list(api.path('/interface/ethernet/switch'))

        # Heuristic: CRS1xx/2xx have exactly one switch entry
        # and port-isolation entries do NOT have a 'name' field
        # CRS3xx/5xx: port-isolation entries HAVE a 'name' field
        if len(result) == 1:
            entry = result[0]
            try:
                pi_result = list(api.path('/interface/ethernet/switch/port-isolation'))
                # Check if port-isolation entries have 'name' field
                has_name_field = any('name' in e for e in pi_result)
                if has_name_field:
                    return 'multi_entry_switch'
                else:
                    return 'single_entry_switch'
            except Exception:
                pass

        return 'multi_entry_switch'

    except Exception:
        # If detection fails, default to multi-entry (modern/common hardware)
        return 'multi_entry_switch'


# --- Detector registry ---

HARDWARE_DETECTORS = {
    """Registry of hardware detector functions.

    This dictionary maps detector names to their implementation functions.
    Each detector is a callable that:

    1. Takes an API connection object as input
    2. Queries the device for hardware-specific information
    3. Returns a string variant key identifying the hardware type

    Available Detectors
    -------------------
    - ``switch_chip_type``: Detects switch chip semantics (single vs multi-entry)
      Used for paths that behave differently on CRS1xx/2xx vs CRS3xx/5xx devices.

    Registration
    ------------
    To add a new detector:
    1. Implement the detector function following the pattern above
    2. Add an entry to this dictionary with a unique name
    3. Add the name to ``HARDWARE_DETECTOR_KEYS`` in ``_api_data.py``
    4. Use the detector name in ``APIData(hardware_detect='...')``

    See Also
    --------
    _api_data.py: HARDWARE_DETECTOR_KEYS, APIData class
    """
    'switch_chip_type': detect_switch_chip_type,
}
