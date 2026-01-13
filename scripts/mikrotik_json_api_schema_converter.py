#!/usr/bin/env python3
"""
MikroTik JSON Schema → APIData Converter

Converts MikroTik RouterOS JSON API schemas to merger-compatible Python APIData format.

RULES:
1. Prioritizes "add" command, falls back to "set" (excludes command from path)
2. Extracts _type="arg" fields as KeyInfo entries
3. Recurses through _type="dir"/"path" nodes building path tuples
4. Strips trailing command names when path remains meaningful (>1 segment)
5. Outputs versioned APIData matching merger script format

USAGE EXAMPLES:
  ./mikrotik_json_api_schema_converter.py --input schema.json --output update.py --version 7.20.5
  ./mikrotik_json_api_schema_converter.py schema.json update.py                          # default 7.20.5
  ./mikrotik_json_api_schema_converter.py -i schema-7-25.json -o update.py -v 7.25.0
"""

import argparse
import sys
import json
from dataclasses import dataclass, field
from typing import Dict, Tuple, List, Any, Optional
from pathlib import Path


# ------------------------------
# Data Classes
# ------------------------------
@dataclass
class KeyInfo:
    """Minimal field metadata - merger adds can_disable, defaults, etc."""
    default: Any = None


@dataclass
class VersionedAPIData:
    """Version-specific API structure."""
    primary_keys: Tuple[str, ...] = ()
    stratify_keys: Tuple[str, ...] = ()
    required_one_of: Tuple[str, ...] = ()
    mutually_exclusive: Tuple[str, ...] = ()
    fixed_entries: bool = False
    single_value: bool = False
    fully_understood: bool = True
    unknown_mechanism: bool = False
    has_identifier: bool = False
    fields: Dict[str, KeyInfo] = field(default_factory=dict)
    versioned_fields: List[Tuple[List[Tuple[str, str]], str, KeyInfo]] = field(default_factory=list)


@dataclass
class APIData:
    """API path container."""
    unversioned: Optional[VersionedAPIData] = None
    versioned: Optional[List[Tuple[str, str, Any]]] = None


# ------------------------------
# Parsing Constants
# ------------------------------
PRIMARY_KEY_CANDIDATES = ('name', 'address', 'mac-address', 'number')
COMMAND_NAMES = {
    'add', 'set', 'remove', 'delete', 'enable', 'disable',
    'print', 'find', 'get', 'move', 'edit', 'export', 'comment'
}
DEFAULT_VERSION = "7.20.5"


# ------------------------------
# JSON Parsing Pipeline
# ------------------------------
def extract_fields(cmd_dict: Dict[str, Any]) -> Dict[str, KeyInfo]:
    """Extract API arguments (_type='arg') from command dictionary."""
    return {
        key: KeyInfo()
        for key, value in cmd_dict.items()
        if isinstance(value, dict) and value.get('_type') == 'arg'
    }


def process_node(node: Dict[str, Any], path: Tuple[str, ...] = (),
                version: str = DEFAULT_VERSION) -> List[Tuple[Tuple[str, ...], APIData]]:
    """
    Recursively traverse JSON schema extracting API paths.
    
    PATH CONSTRUCTION:
    * "add"/"set" → current path (command excluded)
    * _type="dir"/"path" → path + key, recurse
    """
    if not isinstance(node, dict):
        return []

    results = []

    # RULE 1: Extract primary command ("add" > "set")
    has_add = 'add' in node
    cmd_node = None
    cmd_name = None

    if has_add:
        cmd_name = 'add'
        cmd_node = node['add']
    elif 'set' in node:
        cmd_name = 'set'
        cmd_node = node['set']

    if cmd_node and isinstance(cmd_node, dict) and cmd_node.get('_type') == 'cmd':
        fields = extract_fields(cmd_node)
        if fields:
            # fixed_entries=True when we only have "set" (no "add")
            fixed_entries = (not has_add and cmd_name == 'set')

            vd = VersionedAPIData(
                fields=fields,
                fixed_entries=fixed_entries,
                fully_understood=True,  # keep your original default
            )

            api_data = APIData(
                versioned=[(version, '>=', vd)]
            )
            results.append((path, api_data))

    # RULE 2: Recurse directories/paths
    for key, value in node.items():
        if isinstance(value, dict) and value.get('_type') in ('dir', 'path'):
            results.extend(process_node(value, path + (key,), version))

    return results


def clean_path_tuple(path: Tuple[str, ...]) -> Tuple[str, ...]:
    """Remove trailing command name if path has ≥2 segments."""
    return path[:-1] if len(path) > 1 and path[-1] in COMMAND_NAMES else path


# ------------------------------
# Python Code Generation
# ------------------------------
def format_versioned_apidata(vd: VersionedAPIData, indent_level: int) -> str:
    """Format VersionedAPIData with correct indentation."""
    indent = "    " * indent_level
    lines = ["VersionedAPIData("]
    
    if vd.fixed_entries:
        lines.append(f"{indent}    fixed_entries=True,")
    if vd.fully_understood:
        lines.append(f"{indent}    fully_understood=True,")
    
    lines.append(f"{indent}    fields={{")
    for field_name in sorted(vd.fields.keys()):
        lines.append(f"{indent}        '{field_name}': KeyInfo(),")
    lines.append(f"{indent}    }},")
    
    lines.append(f"{indent})")
    return "\n".join(lines)


def format_apidata(path: Tuple[str, ...], api_data: APIData,
                  indent_level: int = 1) -> str:
    """Format complete APIData entry."""
    base_indent = "    " * indent_level
    content_indent = "    " * (indent_level + 1)
    
    lines = [f"{repr(path)}: APIData("]
    
    if api_data.versioned:
        lines.append(f"{content_indent}versioned=[")
        for version, comp, vd in api_data.versioned:
            vd_fmt = format_versioned_apidata(vd, indent_level + 2)
            lines.append(f"{content_indent}    ('{version}', '{comp}', {vd_fmt}),")
        lines.append(f"{content_indent}],")
    
    lines.append(f"{base_indent}),")
    return "\n".join(lines)


# ------------------------------
# Output Template
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
# CLI Parser
# ------------------------------
def parse_args() -> argparse.Namespace:
    """Parse CLI with flexible positional/named arguments."""
    parser = argparse.ArgumentParser(
        description="Convert MikroTik JSON → merger Python schema",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Positional arguments (optional)
    parser.add_argument('input_json', nargs='?', type=Path)
    parser.add_argument('output_py', nargs='?', type=Path)
    parser.add_argument('version', nargs='?', default=DEFAULT_VERSION)
    
    # Named arguments (override positionals)
    parser.add_argument('--input', '-i', type=Path, dest='input_file')
    parser.add_argument('--output', '-o', type=Path, dest='output_file')
    parser.add_argument('--version', '-v', dest='named_version', default=None)
    
    args = parser.parse_args()
    
    # Named args override positionals
    input_file = args.input_file or args.input_json
    output_file = args.output_file or args.output_py
    version = args.named_version if args.named_version is not None else args.version  # Named or 3rd positional
    
    if input_file is None:
        parser.error("input required: --input FILE, input.json, or positional")
    if output_file is None:
        parser.error("output required: --output FILE or 2nd positional")
    
    return argparse.Namespace(
        input_file=Path(input_file),
        output_file=Path(output_file),
        version=version
    )

# ------------------------------
# Main Workflow
# ------------------------------
def main() -> None:
    """JSON schema → Python schema conversion pipeline."""
    args = parse_args()
    
    # Validate input
    print(f"Loading: {args.input_file}")
    if not args.input_file.exists():
        sys.exit(f"ERROR: {args.input_file} does not exist")
    
    # Parse JSON → APIData
    with open(args.input_file, 'r') as f:
        schema_data = json.load(f)
    
    print("Extracting API paths...")
    entries = process_node(schema_data, version=args.version)
    
    # Filter valid paths only
    valid_entries = [
        (clean_path_tuple(path), api_data)
        for path, api_data in entries
        if clean_path_tuple(path)
    ]
    
    print(f"✓ {len(valid_entries)} paths (RouterOS {args.version})")
    
    # Generate Python output
    print(f"Writing: {args.output_file}")
    with open(args.output_file, 'w') as f:
        f.write(DATACLASS_HEADER)
        for path, api_data in sorted(valid_entries):
            f.write("    " + format_apidata(path, api_data) + "\n\n")
        f.write("}\n")
    
    print(f"✓ Converted {len(valid_entries)} paths → {args.output_file}")


if __name__ == "__main__":
    main()
