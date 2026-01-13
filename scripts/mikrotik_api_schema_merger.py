#!/usr/bin/env python3
"""
MikroTik API Schema Merger

Merges base + update MikroTik RouterOS API schemas into a comprehensive,
version-aware schema.

Copyright (c) 2025, (@Ricke)
GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later

PROCESSING PHASES & RULES (in execution order):

PHASE 1: Shared Path Field Merging (R1-R6)
├── R1: KeyInfo metadata inheritance (update overrides base non-defaults)
├── R2: Primary/stratify/required_one_of keys stay in fields permanently (never versioned)
├── R3: Protect base versioned_fields(>=) newer than update_version from R4
├── R4: Move base.fields missing in update → versioned_fields < update_version
├── R5: Add new fields from update
│      • if base is unversioned → versioned_fields >= field-introduced version
│      • if base is already versioned:
│          - same (version, comparator) bucket → add to fields
│          - otherwise → add to versioned_fields in all version covered buckets
└── R6: Normalize versioned_fields (deduplicate, canonicalize constraints)

PHASE 2: Base-only Path Handling (R7-R9)
├── R7: PROTECTED_PATHS copied verbatim from base (no deprecation)
├── R8: Use base < version if single < entry exists for deprecation boundary
└── R9: Deprecation handling for base-only paths
       • R9a: Skip deprecation if any >= update_version data exists
               (either in unversioned.versioned_fields or versioned list)
       • R9b: Skip if any >= string already present (idempotent)
       • otherwise, wrap unversioned as < boundary and add
         "Not supported anymore" >= boundary

PHASE 3: Global Cleanup (invoked via R6)
├── R10: Earliest < constraint wins across all versioned_fields entries
└── R11: Exact >=/< version pairs are equivalent for coverage checks

USAGE: ./mikrotik_api_schema_merger.py [--comments] <base_schema.py> <update_schema.py> <output_file.py>

OPTIONAL extra-vars:
--comments adds fixed_entries=True as comments to a set-only path if no single_value=True or primary_keys=[...] is defined
(should only be used for the last merge as comments are currently ignored on import).

"""

import sys
import copy
import importlib.util
from dataclasses import dataclass, field
from typing import Dict, Tuple, List, Any, Optional

# ------------------------------
# PROTECTED PATHS (R7: exempt from deprecation - copied verbatim from base)
# ------------------------------
PROTECTED_PATHS = {
    # ### No wireless package installed/active ###
    # ('caps-man', 'aaa'),
    # ('caps-man', 'access-list'),
    # ('caps-man', 'channel'),
    # ('caps-man', 'configuration'),
    # ('caps-man', 'datapath'),
    # ('caps-man', 'manager'),
    # ('caps-man', 'manager', 'interface'),
    # ('caps-man', 'provisioning'),
    # ('caps-man', 'security'),
    # ('interface', 'wireless'),
    # ('interface', 'wireless', 'access-list'),
    # ('interface', 'wireless', 'align'),
    # ('interface', 'wireless', 'cap'),
    # ('interface', 'wireless', 'connect-list'),
    # ('interface', 'wireless', 'security-profiles'),
    # ('interface', 'wireless', 'sniffer'),
    # ('interface', 'wireless', 'snooper'),
    ### device specific ###
    ('interface', 'bridge', 'mlag'),    # All CRS3xx, CRS5xx series switches, and CCR2116, CCR2216 (https://help.mikrotik.com/docs/spaces/ROS/pages/67633179/Multi-chassis+Link+Aggregation+Group)
    # ('interface', 'ethernet', 'poe'),   # on all MikroTik devices with PoE interfaces
    ('interface', 'ethernet', 'switch', 'l3hw-settings'),   # has been introduced in RouterOS version 7.6 on specific devices (https://help.mikrotik.com/docs/spaces/ROS/pages/62390319/L3+Hardware+Offloading)
    ('interface', 'ethernet', 'switch', 'l3hw-settings', 'advanced'),
    ('interface', 'ethernet', 'switch', 'qos'), # available on Marvell Prestera DX switch chips (CRS3xx, CRS5xx series switches, and CCR2116, CCR2216 routers) (https://help.mikrotik.com/docs/spaces/ROS/pages/189497483/Quality+of+Service)
    ### ipv6?
    ('routing', 'ripng'),
    #('routing', 'ospf-v3', 'instance'), # OSPFv3 and OSPFv2 are now merged into one single menu /routing ospf (https://help.mikrotik.com/docs/spaces/ROS/pages/30474256/Moving+from+ROSv6+to+v7+with+examples#MovingfromROSv6tov7withexamples-OSPFConfiguration)
    #('routing', 'ospf-v3', 'area'),     # OSPFv3 and OSPFv2 are now merged into one single menu /routing ospf (https://help.mikrotik.com/docs/spaces/ROS/pages/30474256/Moving+from+ROSv6+to+v7+with+examples#MovingfromROSv6tov7withexamples-OSPFConfiguration)
    
    
    # Add more protected paths here as needed - these keep base schema exactly

    # missing packages:
    #   switch-marvell  -  available on CCR3xx, CRS5xx series switches and CCR2116, CCR2216 routers
    #   wifi-mediatek  -  arm
    #   wifi-qcom-ac  -  arm
}

# ------------------------------
# Data Classes (must match input/output schema files exactly)
# ------------------------------
@dataclass
class KeyInfo:
    """Individual API field metadata."""
    default: Any = None         # Default value when field omitted (e.g. 'no', '', 0); used for idempotency matching
    can_disable: bool = False   # Field supports 'disabling' via !<field name> (Type '/path/to/check/add !' (or 'set !') over SSH and press Tab; if nothing completes, there are no values to disable at that path.)
    remove_value: Any = None    # Value that removes field entirely (e.g. '' for some string fields)
    required: bool = False      # Field MUST be provided for 'add' operations (enforced by module) | same field should not be set in required_one_of
    read_only: bool = False     # Field visible in 'print' but cannot be set/modified
    write_only: bool = False    # Field settable but not returned in 'print' responses
    automatically_computed_from: Tuple[str, ...] = ()  # Field auto-populated from these other fields (read-only after)
    absent_value: Any = None    # Value treated as "field absent" for idempotency (differs from default)

    # USAGE RULES:
    # - default ≠ absent_value → distinguishes "explicitly unset" vs "default state"
    # - can_disable=True → module supports value='disable' for toggle fields
    # - read_only + write_only = False → normal read/write field
    # - automatically_computed_from → module skips setting if source fields match

    # INCOMPATIBLE COMBINATIONS:
    # - required=True + read_only=True → cannot require read-only field
    # - can_disable=True + write_only=True → cannot disable invisible field
    # - remove_value + default → avoid overlap (use absent_value for distinction)

@dataclass
class VersionedAPIData:
    """Version-aware API data structure."""
    primary_keys: Tuple[str, ...] = ()          # REQUIRED for fixed_entries (non-singleton): .id/.name/... for matching existing entries (find/set)
    stratify_keys: Tuple[str, ...] = ()         # Group entries by this key for parallel idempotent updates (e.g. 'interface') (in parallel on multiple hosts)
    required_one_of: Tuple[str, ...] = ()       # At least one of these fields MUST be provided for add operations
    mutually_exclusive: Tuple[str, ...] = ()    # Cannot provide more than one of these fields together in same operation
    fixed_entries: bool = False                 # New entries CAN'T be added (set-only paths); REQUIRES primary_keys unless single_value
    single_value: bool = False                  # Singleton table (always exactly 1 entry); bypasses primary_keys, direct /path set
    fully_understood: bool = False              # All fields/behavior known → full idempotency guarantees
    unknown_mechanism: bool = False             # Unfinished/unsupported path → module skips entirely (not an error)
    has_identifier: bool = False                # Path uses .id-style numeric identifiers (affects find/set syntax)
    fields: Dict[str, KeyInfo] = field(default_factory=dict)
    versioned_fields: List[Tuple[List[Tuple[str, str]], str, KeyInfo]] = field(default_factory=list)

    # INCOMPATIBLE COMBINATIONS:
    # - fixed_entries=True + single_value=False → REQUIRES primary_keys
    # - fixed_entries=True + single_value=True + primary_keys=[...] → not allowed
    # - required_one_of + mutually_exclusive → fields overlap prohibited
    # - unknown_mechanism=True → all other flags ignored (path skipped)

@dataclass
class APIData:
    """API path container - unversioned OR versioned entries."""
    unversioned: Optional[VersionedAPIData] = None
    versioned: Optional[List[Tuple[str, str, Any]]] = None

# ------------------------------
# Version Constraint Utilities (R10, R11)
# ------------------------------
def compare_versions(v1: str, v2: str) -> int:
    """Compare RouterOS versions: 1 if v1>v2, -1 if v1<v2, 0 if equal."""
    t1, t2 = tuple(map(int, v1.split('.'))), tuple(map(int, v2.split('.')))
    return (t1 > t2) - (t1 < t2)

def is_version_covered(constraints: List[Tuple[str, str]], candidate_version: str, candidate_comp: str) -> bool:
    """
    R10+R11: True if candidate < is covered by:
    - Earlier < constraint (R10: earliest < wins)
    - Exact >= match for same version (R11: >=v == <v+next coverage)
    """
    if candidate_comp != '<':
        return False
    for ver, comp in constraints:
        if comp == '<' and compare_versions(ver, candidate_version) <= 0:
            return True  # R10
        if comp == '>=' and compare_versions(ver, candidate_version) == 0:
            return True  # R11
    return False

# ------------------------------
# Core Processing Functions (R1-R6)
# ------------------------------
KEYINFO_DEFAULT = KeyInfo()

def merge_keyinfo(base_ki: KeyInfo, update_ki: KeyInfo) -> KeyInfo:
    """R1: Update KeyInfo overrides base non-default values."""
    merged = KeyInfo()
    for attr in KeyInfo.__dataclass_fields__:
        base_val = getattr(base_ki, attr)
        upd_val = getattr(update_ki, attr)
        def_val = getattr(KEYINFO_DEFAULT, attr)
        setattr(merged, attr, upd_val if upd_val != def_val else base_val)
    return merged

def normalize_versioned_fields(vfields: List[Tuple[List[Tuple[str, str]], str, KeyInfo]]) -> List[Tuple[List[Tuple[str, str]], str, KeyInfo]]:
    """
    R6+R10+R11: Normalize versioned_fields for each field:
    - R6: Deduplicate identical (constraints, field_name) entries
    - R10: Keep only earliest < constraint per field
    - R11: Keep only earliest >= constraint per field
    - R1: Merge KeyInfo metadata for duplicates
    """
    result = []
    seen = {}

    for ver_list, name, ki in vfields:
        # Canonical form: [earliest_<, earliest_>=]
        less = sorted([vc for vc in ver_list if vc[1] == '<'], key=lambda x: x[0])
        ge = sorted([vc for vc in ver_list if vc[1] == '>='], key=lambda x: x[0])
        combined = []

        if less:  # R10
            combined.append(less[0])
        if ge:    # R11
            combined.append(ge[0])

        key = (tuple(combined), name)
        if key in seen:
            existing_ki = seen[key][2]
            seen[key] = (combined, name, merge_keyinfo(existing_ki, ki))  # R1
        else:
            seen[key] = (combined, name, ki)

    # Preserve original insertion order
    for _, (ver_list, name, ki) in seen.items():
        result.append((ver_list, name, ki))
    return result

def merge_api_data(base: APIData, update: APIData, update_version: str) -> APIData:
    """
    PHASE 1: Merge shared path fields (R1-R6).

    CASE 1 (R5, versioned base):
        - Base already has versioned entries.
        - For each new field in update:
          • If there is a version bucket with the same (version, comparator),
            add the field directly into that bucket's fields (introduced there).
          • Otherwise, add the field as a versioned_fields entry attached to
            all version covered buckets.

    CASE 2 (R2-R5, unversioned base):
        - Base is unversioned.
        - Apply full field lifecycle:
          R2: keep primary/stratify keys permanent in fields
          R3: protect base versioned_fields(>=) newer than update_version
          R4: move removed fields into versioned_fields < update_version
          R5: add new fields into versioned_fields >= their first seen version
          R6: normalize/deduplicate versioned_fields
    """
    if base is None:
        return copy.deepcopy(update)

    # CASE 1: Base already versioned → merge new fields into matching buckets (R5)
    if getattr(base, 'versioned', None):
        merged_versioned = copy.deepcopy(base.versioned)

        # fixed_entries handling for versioned base
        for _, _, vd in merged_versioned:
            if hasattr(vd, 'fixed_entries'):
                # Update overrides base fixed_entries
                if getattr(update, 'versioned', None):
                    for _, _, u_vd in update.versioned:
                        if hasattr(u_vd, 'fixed_entries'):
                            vd.fixed_entries = u_vd.fixed_entries
                            break

        base_field_names = set()
        for _, _, vd in merged_versioned:
            if hasattr(vd, 'fields') and isinstance(vd.fields, dict):
                base_field_names.update(vd.fields.keys())
                base_field_names.update(f[1] for f in getattr(vd, 'versioned_fields', []))

        for u_ver, u_comp, u_vd in getattr(update, 'versioned', []) or []:
            if hasattr(u_vd, 'fields') and isinstance(u_vd.fields, dict):
                for field_name, field_ki in u_vd.fields.items():
                    if field_name not in base_field_names:
                        placed = False

                        # R5a: Exact match → add to fields dict
                        for i, (ver, comp, vd) in enumerate(merged_versioned):
                            # Exact same version bucket: treat as base fields for that version
                            if ver == u_ver and comp == u_comp and hasattr(vd, 'fields'):
                                vd.fields[field_name] = copy.deepcopy(field_ki)
                                base_field_names.add(field_name)
                                placed = True
                                break

                        if not placed:
                            # R5b: Fallback - add to ALL buckets covering u_ver
                            for ver, comp, vd in merged_versioned:
                                if (hasattr(vd, 'versioned_fields') and
                                    ((comp == '>=' and compare_versions(u_ver, ver) >= 0) or     # u_ver >= bucket_start
                                    (comp == '<'  and compare_versions(u_ver, ver) < 0))):      # u_ver < bucket_end
                                    vd.versioned_fields.append(([(u_ver, u_comp)], field_name, copy.deepcopy(field_ki)))
                                    base_field_names.add(field_name)

        return APIData(versioned=merged_versioned, unversioned=base.unversioned)

    # CASE 2: Base unversioned → full field lifecycle processing
    if getattr(base, 'unversioned', None):
        merged_unv = copy.deepcopy(base.unversioned)

        # fixed_entries handling for unversioned base
        # Update sets it → keep it
        # Base has it but update doesn't → remove it
        update_has_fixed_entries = False
        if getattr(update, 'unversioned', None) and update.unversioned.fixed_entries:
            merged_unv.fixed_entries = True
            update_has_fixed_entries = True
        elif getattr(update, 'versioned', None):
            for _, _, u_vd in update.versioned:
                if hasattr(u_vd, 'fixed_entries') and u_vd.fixed_entries:
                    merged_unv.fixed_entries = True
                    update_has_fixed_entries = True
                    break

        # Remove if base had it but update doesn't
        if not update_has_fixed_entries:
            merged_unv.fixed_entries = False

        # Collect all update field presence across all version buckets
        update_field_names = set()
        update_versioned_fields = {}
        for u_ver, u_comp, u_vd in getattr(update, 'versioned', []) or []:
            if hasattr(u_vd, 'fields') and isinstance(u_vd.fields, dict):
                update_field_names.update(u_vd.fields.keys())  # R4 checks these
            if hasattr(u_vd, 'versioned_fields'):
                for ver_list, field_name, field_ki in u_vd.versioned_fields:
                    update_versioned_fields[(tuple(ver_list), field_name)] = field_ki

        if getattr(update, 'unversioned', None) and hasattr(update.unversioned, 'fields'):
            update_field_names.update(update.unversioned.fields.keys())

        # R2: Primary/stratify/required_one_of keys are permanent (never versioned out)
        pk_sk_and_req = set(merged_unv.primary_keys) | set(merged_unv.stratify_keys)
        for group in merged_unv.required_one_of:
            pk_sk_and_req.update(group)  # Flatten nested lists like ['dns-servers', 'doh-servers']

        # R3: Protect base versioned_fields(>=) newer than update_version from R4
        protected_fields = set()
        for ver_list, field_name, _ in merged_unv.versioned_fields:
            ge_versions = [(v, c) for v, c in ver_list if c == '>=']
            if ge_versions and compare_versions(min(ge_versions, key=lambda x: x[0])[0], update_version) >= 0:
                protected_fields.add(field_name)  # Skip R4 for these

        # R4: Move base.fields missing in update → versioned_fields < update_version
        fields_to_remove = set(merged_unv.fields.keys()) - update_field_names
        fields_to_remove -= pk_sk_and_req                     # R2
        fields_to_remove -= protected_fields                  # R3
        for field_name in fields_to_remove:
            field_ki = merged_unv.fields.pop(field_name)
            existing_constraints = [
                (v, c) for ver_list, n, _ in merged_unv.versioned_fields
                if n == field_name for v, c in ver_list
            ]
            if not is_version_covered(existing_constraints, update_version, '<'):  # R10+R11
                merged_unv.versioned_fields.append(([(update_version, '<')], field_name, field_ki))

        # R5: Add NEW fields from update → versioned_fields >= their version
        base_field_names = set(merged_unv.fields.keys()).union(f[1] for f in merged_unv.versioned_fields)
        for u_ver, u_comp, u_vd in getattr(update, 'versioned', []) or []:
            if hasattr(u_vd, 'fields') and isinstance(u_vd.fields, dict):
                for field_name, field_ki in u_vd.fields.items():
                    if field_name not in base_field_names:
                        merged_unv.versioned_fields.append(([ (u_ver, u_comp) ], field_name, copy.deepcopy(field_ki)))
                        base_field_names.add(field_name)

        # R6: Normalize/deduplicate all versioned_fields
        merged_unv.versioned_fields = normalize_versioned_fields(merged_unv.versioned_fields)
        return APIData(unversioned=merged_unv)

    return copy.deepcopy(update)

def merge_api_dicts(base_dict: Dict[Tuple, APIData], update_dict: Dict[Tuple, APIData]) -> Dict[Tuple, APIData]:
    """
    Full 3-phase merge pipeline:
    1. PHASE 1: Process shared paths (R1-R6 field lifecycle)
    2. PHASE 2: Handle base-only paths (R7-R9 deprecation/protection)
    3. PHASE 3: Cleanup via R6 normalization (already called in PHASE 1)
    """
    # Extract update_version from first versioned entry
    update_version = next(
        (upd_api.versioned[0][0] for upd_api in update_dict.values()
         if getattr(upd_api, 'versioned', None) and upd_api.versioned),
        "unknown"
    )

    merged_dict = copy.deepcopy(base_dict)

    # PHASE 1: Process shared paths through full field lifecycle (R1-R6)
    for path, update_api in update_dict.items():
        if path not in merged_dict:
            merged_dict[path] = copy.deepcopy(update_api)
        else:
            merged_dict[path] = merge_api_data(merged_dict[path], update_api, update_version)

    # PHASE 2: Handle base-only paths (R7-R9)
    for path in base_dict:
        if path not in update_dict:
            # R7: PROTECTED_PATHS - copy verbatim from base, skip deprecation entirely
            if path in PROTECTED_PATHS:
                # Keep base version exactly as-is
                continue

            merged_entry = merged_dict.setdefault(path, APIData())

            # R9a: Skip deprecation if base has >= update_version data
            has_future_versioned_fields = False
            if getattr(merged_entry, 'unversioned', None):
                for ver_list, _, _ in getattr(merged_entry.unversioned, 'versioned_fields', []):
                    for ver, comp in ver_list:
                        if comp == '>=' and compare_versions(ver, update_version) >= 0:
                            has_future_versioned_fields = True
                            break
                    if has_future_versioned_fields:
                        break

            # R9a (continued): Skip deprecation if base has >= update_version data
            has_future_versioned_entry = False
            if getattr(merged_entry, 'versioned', None):
                for ver, comp, vd in merged_entry.versioned:
                    if comp == '>=' and compare_versions(ver, update_version) >= 0:
                        has_future_versioned_entry = True
                        break

            if has_future_versioned_fields or has_future_versioned_entry:
                continue  # Path is still supported in or after update_version, no deprecation


            # R9b: Skip if ANY >= string already exists (idempotent)
            has_existing_ge_string = False
            if getattr(merged_entry, 'versioned', None):
                for ver, comp, vd in merged_entry.versioned:
                    if isinstance(vd, str) and comp == '>=':
                        has_existing_ge_string = True
                        break

            if has_existing_ge_string:
                continue

            # R8: Prefer base < version if a single < entry exists as boundary
            not_supported_version = update_version
            if getattr(merged_entry, 'versioned', None):
                lt_versions = [(ver, comp) for ver, comp, _ in merged_entry.versioned if comp == '<']
                if len(lt_versions) == 1:
                    not_supported_version = lt_versions[0][0]

            # R9: Wrap unversioned data as < boundary (if needed)
            #     and append a ">=" deprecation notice at that same version.
            if getattr(merged_entry, 'unversioned', None):
                vd = merged_entry.unversioned
                merged_entry.versioned = [(not_supported_version, '<', vd)]
                merged_entry.unversioned = None
            elif not getattr(merged_entry, 'versioned', None):
                merged_entry.versioned = []

            merged_entry.versioned.append((
                not_supported_version, '>=',
                f"Not supported anymore in version {not_supported_version}"
            ))

    # PHASE 3 cleanup handled by R6 normalize_versioned_fields() calls
    return merged_dict

# ------------------------------
# Schema I/O
# ------------------------------
def load_api_schema(file_path: str) -> Dict[Tuple, APIData]:
    """Dynamically load API_SCHEMA from Python file."""
    spec = importlib.util.spec_from_file_location("api_schema_module", file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return getattr(module, "API_SCHEMA")

# ------------------------------
# Output Formatting
# ------------------------------
def format_keyinfo(ki: KeyInfo) -> str:
    """Format KeyInfo showing only non-default attributes."""
    attrs = [
        f"{attr}={repr(getattr(ki, attr))}"
        for attr in KeyInfo.__dataclass_fields__
        if getattr(ki, attr) != getattr(KeyInfo(), attr)
    ]
    return f"KeyInfo({', '.join(attrs)})" if attrs else "KeyInfo()"

def format_versioned_api_data(vd: Any, indent: str, comments_mode: bool = True) -> str:
    """Format VersionedAPIData or string literal with exact indentation and with CLI-controlled #fixed_entries."""
    if isinstance(vd, str):
        return repr(vd)

    lines = ["VersionedAPIData("]
    base_attrs = [
        'primary_keys', 'stratify_keys', 'required_one_of', 'mutually_exclusive',
        'fixed_entries', 'single_value', 'fully_understood', 'unknown_mechanism', 'has_identifier'
    ]

    # Pre-check the condition for commented fixed_entries
    fixed_as_comment = (
        getattr(vd, "fixed_entries", False)
        and not getattr(vd, "single_value", True)
        and not getattr(vd, "primary_keys", ())
    )

    # Non-default base attributes
    for attr in base_attrs:
        if attr == "fixed_entries" and fixed_as_comment:
            continue  # Skip adding normal fixed_entries line
        val = getattr(vd, attr)
        if val not in (None, (), False):
            lines.append(f"{indent}    {attr}={repr(val)},")

    # Add fixed_entries as a comment if conditions are met
    if fixed_as_comment:
        # CLI override: --no-comments → always uncommented
        if not comments_mode:
            lines.append(f"{indent}    fixed_entries=True,")
        else:
            # Original fixed_as_comment logic
            if fixed_as_comment:
                lines.append(f"{indent}    #fixed_entries=True,")
            else:
                lines.append(f"{indent}    fixed_entries=True,")

    # Versioned fields (R3-R6 results, sorted by field name)
    if getattr(vd, 'versioned_fields', []):
        lines.append(f"{indent}    versioned_fields=[")
        for ver_list, name, ki in sorted(vd.versioned_fields, key=lambda x: x[1]):
            lines.append(f"{indent}        ({ver_list}, '{name}', {format_keyinfo(ki)}),")
        lines.append(f"{indent}    ],")

    # Current fields dict (alphabetical, post-R4 removals)
    if vd.fields:
        lines.append(f"{indent}    fields={{")
        for k, v in sorted(vd.fields.items()):
            lines.append(f"{indent}        '{k}': {format_keyinfo(v)},")
        lines.append(f"{indent}    }},")

    lines.append(f"{indent})")
    return "\n".join(lines)

def format_apidata(path_tuple: Tuple, api_data: APIData, comments_mode: bool) -> str:
    """Format complete APIData entry (relative indent for main() prefix)."""
    lines = [f"{repr(path_tuple)}: APIData("]
    content_indent = "        "

    if getattr(api_data, 'versioned', None):
        lines.append(f"{content_indent}versioned=[")
        for ver, comp, vd in api_data.versioned:
            vd_formatted = format_versioned_api_data(vd, content_indent + "    ", comments_mode)
            lines.append(f"{content_indent}    ('{ver}', '{comp}', {vd_formatted}),")
        lines.append(f"{content_indent}],")
    elif getattr(api_data, 'unversioned', None):
        unv_formatted = format_versioned_api_data(api_data.unversioned, content_indent)
        lines.append(f"{content_indent}unversioned={unv_formatted},")

    lines.append("    ),")
    return "\n".join(lines)

# ------------------------------
# Output Template (exact dataclass definitions for output file)
# ------------------------------
DATACLASS_HEADER = """from dataclasses import dataclass, field
from typing import Dict, Tuple, List, Any, Optional

@dataclass
class KeyInfo:
    default: Any = None
    can_disable: bool = False
    remove_value: Any = None
    required: bool = False
    read_only: bool = False
    write_only: bool = False
    automatically_computed_from: Tuple[str, ...] = ()
    absent_value: Any = None

@dataclass
class VersionedAPIData:
    primary_keys: Tuple[str, ...] = ()
    stratify_keys: Tuple[str, ...] = ()
    required_one_of: Tuple[str, ...] = ()
    mutually_exclusive: Tuple[str, ...] = ()
    fixed_entries: bool = False
    single_value: bool = False
    fully_understood: bool = False
    unknown_mechanism: bool = False
    has_identifier: bool = False
    fields: Dict[str, KeyInfo] = field(default_factory=dict)
    versioned_fields: List[Tuple[List[Tuple[str,str]], str, KeyInfo]] = field(default_factory=list)

@dataclass
class APIData:
    unversioned: Optional[VersionedAPIData] = None
    versioned: Optional[List[Tuple[str, str, Any]]] = None

API_SCHEMA = {
"""

# ------------------------------
# CLI Entry Point
# ------------------------------
def main():
    """Merge base → update → comprehensive version-aware output."""
    if len(sys.argv) not in (4, 5):
        print(f"Usage: {sys.argv[0]} [--comments] <base_schema.py> <update_schema.py> <output_file.py>")
        sys.exit(1)

    # Parse --comments flag
    comments_mode = '--comments' in sys.argv
    arg_start = 1 if comments_mode else 0
    base_file, update_file, output_file = sys.argv[arg_start+1:arg_start+4]
    # base_file, update_file, output_file = sys.argv[1:4]

    print(f"Loading schemas (comments_mode={'ON' if comments_mode else 'OFF'})...")
    base_dict = load_api_schema(base_file)
    update_dict = load_api_schema(update_file)

    print(f"  Base: {len(base_dict)} paths | Update: {len(update_dict)} paths")
    print(f"  Protected paths (R7): {len(PROTECTED_PATHS)}")

    print("PHASE 1: Merging shared paths (R1-R6)...")
    print("PHASE 2: Handling base-only paths (R7-R9)...")
    merged = merge_api_dicts(base_dict, update_dict)

    print(f"Writing {len(merged)} merged paths with {'#' if comments_mode else ''}fixed_entries → {output_file}")
    with open(output_file, "w") as f:
        f.write(DATACLASS_HEADER)
        for path_tuple, api_data in sorted(merged.items()):
            formatted = format_apidata(path_tuple, api_data, comments_mode)
            f.write("    " + formatted + "\n\n")
        f.write("}\n")

    print(f"✓ Complete! Output: {output_file}")

if __name__ == "__main__":
    main()
