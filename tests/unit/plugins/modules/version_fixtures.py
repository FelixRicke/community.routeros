# -*- coding: utf-8 -*-

"""Version fixtures for RouterOS version simulation in tests."""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

# RouterOS versions to test against
ROS_VERSIONS = [
    '7.0',   # Early ROSv7
    '7.5',   # Mid ROSv7
    '7.15',  # Later ROSv7
    '7.20',  # Recent ROSv7
    '7.22',  # Latest ROSv7
    '8.0',   # Future ROSv8 (for forward compatibility)
]

# Version comparison operators
VERSION_OPERATORS = ['==', '!=', '<', '<=', '>', '>=']


def version_parametrize(func):
    """Decorator to parametrize test with all ROS versions."""
    import pytest
    return pytest.mark.parametrize('ros_version', ROS_VERSIONS)(func)


def version_range_parametrize(start, end):
    """Create parametrization for a version range."""
    import pytest
    from ansible_collections.community.routeros.plugins.module_utils.version import LooseVersion
    versions = [v for v in ROS_VERSIONS
                if LooseVersion(start) <= LooseVersion(v) <= LooseVersion(end)]
    return pytest.mark.parametrize('ros_version', versions)
