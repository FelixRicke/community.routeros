# API Data System Architecture

## Overview

The API data system is the foundation of the `community.routeros` collection's API modules. 
It provides a centralized, declarative schema for RouterOS API paths, enabling modules like `api_info` and `api_modify` to work consistently across hundreds of different API endpoints.

### Purpose

The system serves three main purposes:

1. **Schema Definition**: Declares what fields exist for each API path, their defaults, and which are read-only or write-only
2. **Version Handling**: Manages fields that differ across RouterOS versions (7.x series)
3. **Hardware Detection**: Adapts path schemas based on detected hardware (e.g., different switch chip behaviors)

### Component Relationships

```
┌──────────────────────────────────────────────────────────────────┐
│                     Module Layer                                 │
│  ┌──────────────────┐               ┌──────────────────┐         │
│  │   api_info.py    │               │  api_modify.py   │         │
│  │  (read data)     │               │  (write data)    │         │
│  └────────┬─────────┘               └────────┬─────────┘         │
│           │                                  │                   │
│           └──────────┬───────────────────────┘                   │
│                      ▼                                           │
│               ┌───────────────┐                                  │
│               │ _api_helper.py│                                  │
│               │ (utilities)   │                                  │
│               └───────┬───────┘                                  │
└───────────────────────┼──────────────────────────────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────────────────────────┐
│                    Data Layer                                    │
│  ┌─────────────────────────────────────────────────────────┐     │
│  │           PATHS[('ip', 'address')]                      │     │
│  │                    │                                    │     │
│  │                    ▼                                    │     │
│  │               ┌─────────┐                               │     │
│  │               │APIData  │──── hardware_variants ──────▶│     │
│  │               └────┬────┘                               │     │
│  │                    │                                    │     │
│  │                    ▼                                    │     │
│  │            ┌────────────────┐                           │     │
│  │            │VersionedAPIData│── versioned_fields ─────▶│     │
│  │            └───────┬────────┘                           │     │
│  │                    │                                    │     │
│  │                    ▼                                    │     │
│  │              field → KeyInfo                            │     │
│  └─────────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│               Hardware Detection                                │
│  ┌───────────────────────────────────────────────────────┐      │
│  │  _hardware_detect.py                                  │      │
│  │  - detect_switch_chip_type()                          │      │
│  │  - HARDWARE_DETECTORS registry                        │      │
│  └───────────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────────┘
```

**Key Files:**
- `community.routeros/plugins/module_utils/_api_data.py` - Core data model and PATHS dictionary
- `community.routeros/plugins/module_utils/_api_helper.py` - Helper functions and value sanitization
- `community.routeros/plugins/module_utils/_hardware_detect.py` - Hardware detection logic
- `community.routeros/plugins/modules/api_info.py` - Information retrieval module
- `community.routeros/plugins/modules/api_modify.py` - Data modification module

---

## Core Data Model

The data model consists of three primary classes that work together to define API path schemas.

### APIData

The `APIData` class is the top-level container that handles version resolution and hardware variants.

**Constructor Parameters:**
- `unversioned` - A `VersionedAPIData` instance for paths that don't need version selection
- `versioned` - A list of `(version, comparator, VersionedAPIData)` tuples for version-specific paths
- `hardware_detect` - Name of hardware detector function (e.g., `'switch_chip_type'`)
- `hardware_variants` - Dictionary mapping hardware keys to `APIData` instances

**Key Properties:**
- `fully_understood` - True if at least one variant/version is fully documented
- `needs_version` - True if version selection is required
- `has_identifier` - True if entries have a `.id` field
- `modify_not_supported` - True if the path cannot be modified via API

**Usage Example:**
```python
APIData(
    unversioned=VersionedAPIData(
        fully_understood=True,
        fields={'disabled': KeyInfo(default=False)}
    )
)
```

### VersionedAPIData

`VersionedAPIData` defines the schema for a specific RouterOS version or version range.

**Constructor Parameters:**
- `primary_keys` - Fields used to identify entries (e.g., `('address',)`)
- `stratify_keys` - Alternative to primary_keys for single-value entries
- `has_identifier` - Entries have `.id` field for identification
- `single_value` - Path contains exactly one entry (e.g., system settings)
- `fixed_entries` - Number of entries is fixed (cannot add/remove)
- `fully_understood` - All fields are documented
- `fields` - Dictionary of `field_name → KeyInfo`
- `versioned_fields` - List of `(conditions, name, KeyInfo)` for version-specific fields

**Key Methods:**
- `specialize_for_version(api_version)` - Returns a new instance with version-specific fields merged in

**Usage Example:**
```python
VersionedAPIData(
    primary_keys=('name',),
    fully_understood=True,
    fields={
        'name': KeyInfo(required=True),
        'disabled': KeyInfo(default=False)
    },
    versioned_fields=[
        ([('7.22', '>=')], 'new-field', KeyInfo()),
    ]
)
```

### KeyInfo

`KeyInfo` contains metadata for individual fields within a path schema.

**Constructor Parameters:**
- `can_disable` - Field can be disabled (prefixed with `!` in API)
- `remove_value` - Value used when disabling a field
- `absent_value` - Value when field is absent from API response
- `default` - Default value when field is not specified
- `required` - Field must be provided
- `read_only` - Field cannot be modified (API returns it only)
- `write_only` - Field can be set but not read back
- `value_sanitizer` - Callable to normalize user-provided values
- `automatically_computed_from` - Field value computed from another field

**Validation Rules:**
- `required`, `default`, and `automatically_computed_from` are mutually exclusive
- `read_only` cannot be combined with `can_disable`, `default`, or `required`
- `value_sanitizer` cannot be used with `read_only` or `write_only` fields

**Usage Example:**
```python
KeyInfo(
    can_disable=True,
    remove_value='',
    default='bridge',
    value_sanitizer=_sanitize_ensure_leading_slash
)
```

---

## The PATHS Dictionary

The `PATHS` dictionary is the central registry of all supported API paths in the collection.

### Structure

```python
PATHS = {
    ('ip', 'address'): APIData(...),
    ('interface', 'bridge'): APIData(...),
    # ... many more paths
}
```

### How Paths Are Keyed

- **Key**: A tuple of path segments, split by spaces
  - `'ip address'` → `('ip', 'address')`
  - `'interface bridge port'` → `('interface', 'bridge', 'port')`
- **Value**: An `APIData` instance defining the schema for that path

### Path Conversion Utilities

```python
from ansible_collections.community.routeros.plugins.module_utils._api_data import (
    join_path,
    split_path,
)

split_path('ip address')      # Returns: ('ip', 'path')
join_path(('ip', 'address'))  # Returns: 'ip address'
```

### How Definitions Are Organized

Each path definition follows this pattern:

1. **Simple paths** (no versioning): Use `unversioned` parameter
2. **Versioned paths**: Use `versioned` with `(version, comparator, data)` tuples
3. **Hardware-dependent paths**: Use `hardware_detect` and `hardware_variants`

**Example: Simple unversioned path:**
```python
('caps-man', 'aaa'): APIData(
    unversioned=VersionedAPIData(
        fixed_entries=True,
        fully_understood=True,
        single_value=True,
        fields={
            'called-format': KeyInfo(default='mac:ssid'),
        }
    )
)
```

**Example: Versioned path:**
```python
('app',): APIData(
    versioned=[
        ('7.22', '>=', VersionedAPIData(fields={'auto-update': KeyInfo()})),
        ('7.21', '>=', VersionedAPIData(fields={'numbers': KeyInfo()})),
    ]
)
```

---

## Version Handling

RouterOS 7.x introduces new fields and changes behavior across versions. The system handles this through versioned data definitions.

### Versioned vs Unversioned Data

**Unversioned:**
- Path has the same schema across all RouterOS versions
- Defined via `unversioned=VersionedAPIData(...)`
- `needs_version = False`

**Versioned:**
- Path schema changes based on RouterOS version
- Defined via `versioned=[(version, op, data), ...]`
- `needs_version = True`

### Version Selection Logic

The `APIData.provide_version()` method selects the appropriate schema:

```python
def provide_version(self, version):
    # For unversioned paths: return immediately
    if not self.needs_version:
        return self.unversioned.fully_understood, None
    
    # For versioned paths: find matching version range
    api_version = LooseVersion(version)
    for other_version, comparator, data in self.versioned:
        if _compare(api_version, other_version, comparator):
            return self._select(data, api_version)
    
    # No match found
    return False, None
```

**Supported Comparators:**
- `>=` - Version greater than or equal
- `<=` - Version less than or equal
- `>` - Version greater than
- `<` - Version less than
- `==` - Exact version match
- `!=` - Version not equal

**Wildcard Syntax:**
```python
('*', '*')  # Matches all versions (fallback)
```

### Version-Specific Fields

Fields that only exist in certain versions are defined in `versioned_fields`:

```python
VersionedAPIData(
    fields={
        'common-field': KeyInfo(),
    },
    versioned_fields=[
        # Add 'new-field' for RouterOS 7.22 and later
        ([('7.22', '>=')], 'new-field', KeyInfo()),
    ]
)
```

When `specialize_for_version()` is called, matching fields are merged into the result.

---

## Hardware Detection

Some API paths behave differently depending on the RouterOS device hardware. The system supports detecting hardware and selecting appropriate schemas.

### How Hardware Variants Work

**Hardware-dependent path definition:**
```python
('interface', 'ethernet', 'switch'): APIData(
    hardware_detect='switch_chip_type',
    hardware_variants={
        'single_entry_switch': APIData(unversioned=VersionedAPIData(...)),
        'multi_entry_switch': APIData(unversioned=VersionedAPIData(...)),
    }
)
```

**Flow:**
1. Module detects hardware via registered detector
2. Looks up variant in `hardware_variants` dictionary
3. Uses variant-specific schema for all operations

### Detector Registration

Detectors are registered in `_hardware_detect.py`:

```python
HARDWARE_DETECTORS = {
    'switch_chip_type': detect_switch_chip_type,
}
```

**Detector Function Signature:**
```python
def detect_switch_chip_type(api):
    # Query the API to detect hardware
    result = list(api.path('/interface/ethernet/switch'))
    # Return string key matching hardware_variants
    return 'single_entry_switch'  # or 'multi_entry_switch'
```

### Caching

Detection results are cached per detector/API connection pair:

```python
def get_cached_or_detect(detector_name, api):
    key = (detector_name, id(api))
    if key not in _detection_cache:
        _detection_cache[key] = HARDWARE_DETECTORS[detector_name](api)
    return _detection_cache[key]
```

### Example: Switch Chip Detection

The `detect_switch_chip_type()` function distinguishes between:

- **CRS1xx/2xx (single_entry_switch)**: QCA8519 chip, single switch entry, no per-port sub-entries
- **CRS3xx/5xx (multi_entry_switch)**: MT7621, 88E6393X chips, entries with `.id` and `name`

```python
def detect_switch_chip_type(api):
    result = list(api.path('/interface/ethernet/switch'))
    
    if len(result) == 1:
        # Check port-isolation for 'name' field
        pi_result = list(api.path('/interface/ethernet/switch/port-isolation'))
        has_name_field = any('name' in e for e in pi_result)
        return 'multi_entry_switch' if has_name_field else 'single_entry_switch'
    
    return 'multi_entry_switch'
```

---

## Value Sanitization

Value sanitizers normalize user-provided values to match how RouterOS stores and returns data.

### Contract

A value sanitizer is a callable with these guarantees:

1. **Idempotent**: Applying twice yields the same result as applying once
2. **Type preservation**: Non-matching types are returned unchanged

**Signature:** `Callable[[Any], Any]`

**Example contract enforcement:**
```python
def _sanitize_ensure_leading_slash(value):
    # Non-string values passed through unchanged
    if value and isinstance(value, str) and not value.startswith('/'):
        return '/' + value
    return value  # Already has slash, or empty, or not a string
```

### Registration

Sanitizers are registered on `KeyInfo` instances:

```python
'path-field': KeyInfo(
    value_sanitizer=_sanitize_ensure_leading_slash
)
```

### Example: `_sanitize_ensure_leading_slash`

Used in paths like `container mounts` where RouterOS prepends `/` to path values.

**Behavior:**
- Input: `'usb1/data'` → Output: `'/usb1/data'`
- Input: `'/usb1/data'` → Output: `'/usb1/data'` (unchanged)
- Input: `''` → Output: `''` (unchanged, empty string is valid)
- Input: `None` → Output: `None` (unchanged, type not handled)

**Use Case:**
Without this sanitizer, Ansible would always detect a diff between user input `'usb1/data'` and RouterOS-stored `'/usb1/data'`, breaking idempotency.

### Application

Sanitizers are applied through `apply_value_sanitizer()` in `_api_helper.py`:

```python
def apply_value_sanitizer(key_info, value, key_name, warn=None):
    if key_info.value_sanitizer is None:
        return value
    
    sanitized = key_info.value_sanitizer(value)
    
    if warn is not None and sanitized != value:
        warn(f'Value of field "{key_name}" was automatically normalised '
             f'from {value!r} to {sanitized!r}')
    
    return sanitized
```

**Warning Behavior:**
When a sanitizer modifies a value, users receive a warning suggesting they update their playbooks to use the normalized value directly.

---

## Helper Functions

The `_api_helper.py` module provides utility functions used by both `api_info` and `api_modify`.

### `_api_helper.py` Restrict Mechanism

The `restrict` parameter filters output to entries matching specific criteria.

**Restrict Rule Structure:**
```python
restrict_argument_spec() → dict(
    restrict=dict(
        type='list',
        elements='dict',
        options=dict(
            field=dict(type='str', required=True),      # Field to check
            match_disabled=dict(type='bool', default=False),  # Match None values
            values=dict(type='list', elements='raw'),   # Exact values to match
            regex=dict(type='str'),                      # Regex pattern
            invert=dict(type='bool', default=False),     # Invert match
        ),
    )
)
```

**Matching Logic:**
1. Get field value from entry (use default if missing)
2. Check if value matches `values` list or `regex` pattern
3. Apply `invert` if specified
4. Entry is accepted if any rule matches (OR logic)

**Example Restrict Usage:**
```yaml
- name: Get only input chain firewall rules
  api_info:
    path: ip firewall filter
    restrict:
      - field: chain
        values:
          - input
```

### `value_to_str`

Converts Python values to strings for comparison and API communication.

```python
def value_to_str(value, compat_bool=False, none_to_empty=False):
    if value is None:
        return '' if none_to_empty else None
    if value is True:
        return 'true' if compat_bool else 'yes'
    if value is False:
        return 'false' if compat_bool else 'no'
    return to_text(value)
```

**Boolean Handling:**
- `compat_bool=False` (default): `'yes'` / `'no'` (RouterOS convention)
- `compat_bool=True`: `'true'` / `'false'` (API internal format)

### `apply_value_sanitizer`

See the "Value Sanitization" section above for detailed usage.

**Parameters:**
- `key_info` - The `KeyInfo` instance for the field
- `value` - Value to sanitize
- `key_name` - Human-readable field name for warnings
- `warn` - Optional warning function (e.g., `module.warn`)

---

## Module Integration

Both `api_info` and `api_modify` use the data layer for schema lookups and validation.

### `api_info.py` Flow

```python
# 1. Parse path
path = split_path(module.params['path'])

# 2. Look up schema
versioned_path_info = PATHS.get(tuple(path))

# 3. Hardware detection (if needed)
if versioned_path_info.hardware_detect:
    hardware_variant_key = get_cached_or_detect(...)
    versioned_path_info = versioned_path_info.hardware_variants[hardware_variant_key]

# 4. Version selection (if needed)
if versioned_path_info.needs_version:
    api_version = get_api_version(api)
    supported, _ = versioned_path_info.provide_version(api_version)

# 5. Get concrete schema
path_info = versioned_path_info.get_data()

# 6. Fetch data and filter based on path_info.fields
for entry in api_path:
    # Remove fields not in schema (unless unfiltered)
    # Apply handle_disabled, hide_defaults, etc.
```

**Key Integration Points:**
- `handle_disabled`: How `None` values are represented (`!field`, `field: null`, or omitted)
- `hide_defaults`: Omit fields matching their default value
- `include_read_only`: Include/exclude read-only fields
- `restrict`: Filter entries by field values

### `api_modify.py` Flow

```python
# 1. Same setup as api_info (hardware detection, version selection)
path_info = versioned_path_info.get_data()

# 2. Fetch current state
old_data = fetch_entries(api_path, path_info)

# 3. Polish new data (apply sanitizers)
for entry in new_data:
    for field, value in entry.items():
        entry[field] = apply_value_sanitizer(path_info.fields[field], value, ...)

# 4. Find differences
modifications = find_modifications(old_entry, new_entry, path_info, module)

# 5. Apply changes via API
for key, value in modifications.items():
    api_path.update({key: value})
```

**Key Integration Points:**
- `find_modifications()`: Compares old/new entries using schema metadata
- Sanitizers ensure idempotent comparisons
- Schema validates required fields, mutual exclusivity, etc.

---

## Common Patterns

This section provides guidance for contributors adding support for new paths.

### How to Add New Paths

**Step 1: Gather Schema Information**

Run `/export verbose` in the RouterOS CLI. Note:
- All attributes = fields
- Attributes that can have `!` = `can_disable=True`
- Bold attributes = likely primary keys

**Step 2: Define the Path**

Add entry to `PATHS` dictionary:

```python
('new', 'path'): APIData(
    unversioned=VersionedAPIData(
        primary_keys=('name',),  # Or has_identifier=True, or single_value
        fully_understood=True,
        fields={
            'name': KeyInfo(required=True),
            'disabled': KeyInfo(default=False),
            'comment': KeyInfo(can_disable=True, remove_value=''),
        }
    )
)
```

**Step 3: Handle Versions (if needed)**

```python
('versioned', 'path'): APIData(
    versioned=[
        ('7.22', '>=', VersionedAPIData(
            fields={'new-field-in-7-22': KeyInfo()}
        )),
        ('7.17', '>=', VersionedAPIData(
            fields={'field-from-7-17': KeyInfo()}
        )),
    ]
)
```

Or use `versioned_fields` for conditional additions:

```python
VersionedAPIData(
    fields={'common-field': KeyInfo()},
    versioned_fields=[
        ([('7.22', '>=')], 'new-field', KeyInfo()),
    ]
)
```

### Adding Version-Specific Fields

**Pattern 1: Multiple versioned definitions**
```python
versioned=[
    ('7.22', '>=', VersionedAPIData(fields={'field-for-7-22': KeyInfo()})),
    ('7.17', '>=', VersionedAPIData(fields={'field-for-7-17': KeyInfo()})),
]
```

**Pattern 2: Conditional fields**
```python
VersionedAPIData(
    fields={'base-field': KeyInfo()},
    versioned_fields=[
        ([('7.22', '>=')], 'field-only-7-22', KeyInfo()),
        ([('7.17', '>='), ('7.22', '<')], 'field-7-17-to-7-21', KeyInfo()),
    ]
)
```

**Chaining Conditions:**
Multiple `(version, comparator)` tuples mean AND logic.

### Adding Hardware Detection

**Step 1: Implement Detector**

Add to `_hardware_detect.py`:

```python
def detect_my_hardware(api):
    result = list(api.path('/some/path'))
    if some_condition(result):
        return 'hardware_variant_a'
    return 'hardware_variant_b'

HARDWARE_DETECTORS = {
    'my_hardware': detect_my_hardware,
}
```

**Step 2: Define Hardware Variants**

```python
('hardware', 'path'): APIData(
    hardware_detect='my_hardware',
    hardware_variants={
        'hardware_variant_a': APIData(unversioned=VersionedAPIData(fields={
            'field-for-a': KeyInfo(),
        })),
        'hardware_variant_b': APIData(unversioned=VersionedAPIData(fields={
            'field-for-b': KeyInfo(),
        })),
    }
)
```

### Adding Value Sanitizers

**Step 1: Define Sanitizer**

Add to top of `_api_data.py`:

```python
def _sanitize_my_field(value):
    """Normalize my_field values.
    
    CONTRACT: Must be idempotent and pass through non-matching types.
    """
    if value and isinstance(value, str):
        return value.strip().lower()
    return value
```

**Step 2: Register on Field**

```python
'my-field': KeyInfo(value_sanitizer=_sanitize_my_field)
```

### Field Flags Quick Reference

| Flag | Purpose | Example |
|------|---------|---------|
| `can_disable=True` | Field can be disabled with `!` prefix | `comment: KeyInfo(can_disable=True)` |
| `remove_value=''` | Value used when disabling | `comment: KeyInfo(remove_value='')` |
| `default=X` | Default value when unset | `disabled: KeyInfo(default=False)` |
| `required=True` | Must be provided | `name: KeyInfo(required=True)` |
| `read_only=True` | Cannot be modified | `progress: KeyInfo(read_only=True)` |
| `write_only=True` | Cannot be read back | `password: KeyInfo(write_only=True)` |
| `value_sanitizer=X` | Normalize user input | `path: KeyInfo(value_sanitizer=_sanitize)` |
| `absent_value=X` | Value when field absent | `field: KeyInfo(absent_value=None)` |

---

## Contributing Checklist

When adding support for a new path:

- [ ] Add entry to `PATHS` dictionary
- [ ] Define all fields with appropriate `KeyInfo` flags
- [ ] Handle version differences if applicable
- [ ] Add hardware detection if required
- [ ] Register value sanitizers where needed
- [ ] Set `fully_understood=True` when complete
- [ ] Test with `api_info` and `api_modify`
- [ ] Update module documentation path list

---

## Summary

The API data system provides a robust, declarative framework for interacting with RouterOS API paths. Key takeaways for contributors:

1. **PATHS is the source of truth** - All schema information flows from this dictionary
2. **Version handling is automatic** - Define versioned fields; the system selects the right schema
3. **Hardware detection is extensible** - Add detectors for hardware-specific behavior
4. **Value sanitization ensures idempotency** - Register sanitizers for values RouterOS normalizes
5. **Modules share the same data layer** - `api_info` and `api_modify` use identical schema lookups

This architecture enables the collection to support hundreds of API paths with consistent behavior, proper idempotency, and clear separation between schema definition and module logic.
