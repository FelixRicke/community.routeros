#!/usr/bin/env python3
"""
mikrotik_ast_dump.py

Traverse the RouterOS console command tree using
`/console/inspect request=child` and produce a JSON representation.

USAGE: ./mikrotik_ast_dump.py --host <ip address> -user <username> --password <password> --output <output_file.py> [--only-add-set]

JSON shape (no synthetic root key):

{
  "beep": {
    "_type": "cmd",
    "as-value": {
      "_type": "arg"
    }
  },
  "ip": {
    "_type": "dir",
    "address": {
      "_type": "dir"
    }
  }
}

- Top-level keys are top-level console commands (e.g. "ip", "interface", "beep").
- Each node has:
  - "_type": "dir"  for directory/menu-like nodes
  - "_type": "path" for path-like nodes (if RouterOS uses that)
  - "_type": "cmd"  for commands
  - "_type": "arg"  for special argument-like nodes (currently "as-value")
- Children are nested as further keys under each node.

Traversal:
- Uses a breadth-first search (BFS) over console "paths".
- A path is represented as comma-separated segments, e.g.: "ip,address,dhcp".
- The empty string "" is used internally as the starting point (root marker),
  but is never written as a key into the JSON.


ARM and ARM64 with all extra packages installed will cover all packages on other architectures (based on what's currently available December 2025).
Only on arm64:
extra-nic
switch-marvell

Only on arm:
wifi-mediatek
wifi-qcom-ac
"""

import argparse
import json
import subprocess
import shlex
from typing import Dict, List, Any, Tuple


# ---------------------------------------------------------------------------
# Low-level RouterOS /console/inspect interaction
# ---------------------------------------------------------------------------

def run_console_inspect(host: str, user: str, password: str, path: str) -> List[str]:
    """
    Execute `/console/inspect request=child` on a RouterOS device over SSH.

    Args:
        host: RouterOS IP or hostname.
        user: RouterOS username.
        password: RouterOS password.
        path: Comma-separated console path, e.g. "ip,address".
              Empty string means top-level.

    Returns:
        List of non-empty lines from stdout.

    Behavior:
        - Uses sshpass + ssh with StrictHostKeyChecking disabled, matching your
          Ansible call:
              sshpass -p PASSWORD ssh -o StrictHostKeyChecking=no -l USER HOST CMD
        - Does NOT impose a Python-side timeout; the call may block if the router
          itself responds slowly.
        - On non-zero exit code, prints a warning and returns an empty list, so
          traversal can continue without aborting.
    """
    # Build the RouterOS console command exactly like in Ansible
    if path:
        cmd = f'/console/inspect request=child path={path}'
    else:
        cmd = '/console/inspect request=child'

    ssh_cmd = (
        f"sshpass -p {shlex.quote(password)} "
        f"ssh -o StrictHostKeyChecking=no "
        f"-l {shlex.quote(user)} {shlex.quote(host)} "
        f"{shlex.quote(cmd)}"
    )

    print(f"[INFO] Inspecting path={path!r} on {host} ...")
    proc = subprocess.run(
        ssh_cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )

    if proc.returncode != 0:
        # Do not abort the entire traversal; just log and continue.
        print(
            f"[WARN] console/inspect failed for path={path!r}: "
            f"rc={proc.returncode}, stderr={proc.stderr.strip()}"
        )
        return []

    # Return non-empty lines only
    return [l for l in proc.stdout.splitlines() if l.strip()]


def parse_children(lines: List[str]) -> List[Dict[str, Any]]:
    """
    Parse the output lines from `/console/inspect request=child` into
    a structured list of children.

    Expected input looks like a table, typically including:
      - Header lines such as 'Columns: ...' or 'TYPE NAME ...'
      - Data lines like: 'cmd beep arg', etc.

    Returns:
        A list of dicts with:
        {
          "type": <str>,      # TYPE column (e.g. "cmd")
          "name": <str>,      # NAME column (e.g. "beep")
          "node_type": <str>, # column representing kind (child/dir/path/cmd/...)
          "raw": <str>,       # original line
        }
    """
    children: List[Dict[str, Any]] = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        # Skip header / meta lines
        if stripped.startswith("Columns:"):
            continue
        if stripped.startswith("TYPE") and "NAME" in stripped:
            continue
        if stripped.startswith("self "):
            continue

        parts = stripped.split()
        if len(parts) < 3:
            # Not enough columns to be a valid row
            continue

        t, name, node_type = parts[0], parts[1], parts[2]
        children.append(
            {
                "type": t,
                "name": name,
                "node_type": node_type,
                "raw": stripped,
            }
        )

    return children


# ---------------------------------------------------------------------------
# AST building helpers
# ---------------------------------------------------------------------------

def get_node_type_for_json(node_type: str, name: str) -> str:
    """
    Map RouterOS node_type + name to the JSON `_type` field.

    Rules:
      - If the name is 'as-value', treat it as an argument node (`arg`).
      - Otherwise keep the RouterOS node_type as-is (dir/path/cmd/...).
      - If node_type is empty/unknown, default to 'cmd'.

    This ensures dir/path elements are not flattened into 'cmd' in JSON.
    """
    if name == "as-value":
        return "arg"
    return node_type or "cmd"


def ensure_node(ast_root: Dict[str, Any], path: str) -> Dict[str, Any]:
    """
    Ensure that a node for a given path exists in the nested JSON tree.

    Args:
        ast_root: The root JSON dict being built.
        path: Comma-separated path, e.g. "ip,address,dhcp".
              Empty string means "top-level" (no single root node).

    Returns:
        The dict corresponding to the node at `path`.

    Example final JSON shape (no explicit root key):

    {
      "beep": {
        "_type": "cmd",
        "as-value": {
          "_type": "arg"
        }
      },
      "ip": {
        "_type": "dir",
        "address": {
          "_type": "dir"
        }
      }
    }
    """
    if not path:
        # Top-level: callers will attach children directly to ast_root.
        return ast_root

    segments = path.split(",")
    node = ast_root

    for segment in segments:
        if segment not in node:
            # Create a new node with a default `_type` of "cmd".
            # This will often be overwritten to 'dir'/'path' when we see children.
            node[segment] = {"_type": "cmd"}
        node = node[segment]

    return node


# ---------------------------------------------------------------------------
# BFS traversal over console paths
# ---------------------------------------------------------------------------

def should_descend(current_path: str, child: Dict[str, Any], only_add_set: bool) -> bool:
    """
    Decide whether to enqueue a child path for further traversal.

    Rules when only_add_set is False:
      - descend into dir/path/child/cmd.

    Rules when only_add_set is True:
      - always descend into dir/path/child (submenus).
      - only descend into cmd nodes whose *name* is 'add' or 'set'.
    """
    node_type = child.get("node_type")
    name = child.get("name")

    # Always descend into submenus
    if node_type in ("child", "dir", "path"):
        return True

    if not only_add_set:
        # also descend into all cmd to see their args
        return node_type == "cmd"

    # Restricted behavior: only add/set commands
    if node_type == "cmd" and name in ("add", "set"):
        return True

    return False

def traverse(host: str, user: str, password: str,
             only_add_set: bool = False) -> Tuple[Dict[str, Any], int, int]:
    """
    Perform a breadth-first traversal (BFS) of the RouterOS console tree.

    Returns:
        (ast_root, dir_path_count, cmd_count)

        ast_root: nested JSON structure as described above.
        dir_path_count: number of nodes that had at least one "dir/path-like"
                        child (child/dir/path node_type).
        cmd_count: number of nodes that only exposed cmd/arg children.

    Traversal rules:
        - The queue holds comma-separated paths ("" for starting at top-level).
        - For each path, we:
          - run /console/inspect request=child
          - parse children
          - attach their names as nested JSON nodes
          - enqueue further paths for any child with node_type in:
              ("child", "dir", "path", "cmd")
          - This means we also traverse into cmd nodes to discover argument
            children (e.g. "as-value").
    """
    ast_root: Dict[str, Any] = {}

    queue: List[str] = [""]   # "" is the starting pseudo-root marker
    visited: List[str] = []

    dir_path_count = 0  # nodes with at least one dir/path child
    cmd_count = 0       # nodes that only expose cmd/arg children

    while queue:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.append(current)

        print(f"[INFO] Visiting node: {current!r} (remaining in queue: {len(queue)})")

        # Fetch and parse children of the current path
        lines = run_console_inspect(host, user, password, current)
        children = parse_children(lines)

        # Identify the current JSON node that children should attach to
        if current:
            current_node = ensure_node(ast_root, current)
        else:
            # At the top level, children attach directly to ast_root
            current_node = ast_root

        # Determine how to classify this path for summary counting
        has_dir_like_child = any(
            c.get("node_type") in ("child", "dir", "path") for c in children
        )
        if has_dir_like_child:
            dir_path_count += 1
        else:
            # If it has children but none are dir-like, treat this as "cmd-only"
            # (there may still be cmd/arg children).
            if children:
                cmd_count += 1

        # Add children under current node in JSON with correct _type
        for c in children:
            name = c["name"]
            node_type = c.get("node_type", "cmd")
            json_type = get_node_type_for_json(node_type, name)

            if name not in current_node:
                current_node[name] = {}
            # Only set _type if not already present
            current_node[name].setdefault("_type", json_type)

        # Enqueue nodes to traverse further:
        # - "child"/"dir"/"path" are navigation nodes (submenus).
        # - "cmd" may have argument children, so we also traverse into them.
        for c in children:
            if should_descend(current, c, only_add_set):
                name = c["name"]
                if current:
                    next_path = current + "," + name
                else:
                    next_path = name

                if next_path not in visited and next_path not in queue:
                    queue.append(next_path)
                    print(f"[DEBUG] Enqueued: {next_path!r}")

    print(f"[INFO] Traversal finished. Visited {len(visited)} paths.")
    print(f"[INFO] Summary: dir/path-like nodes={dir_path_count}, cmd-only nodes={cmd_count}")
    return ast_root, dir_path_count, cmd_count


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Parse CLI arguments, run the traversal, and write the JSON output.
    """
    parser = argparse.ArgumentParser(
        description="Dump MikroTik RouterOS console AST using /console/inspect request=child"
    )
    parser.add_argument("--host", required=True, help="RouterOS host/IP")
    parser.add_argument("--user", required=True, help="RouterOS username")
    parser.add_argument("--password", required=True, help="RouterOS password")
    parser.add_argument(
        "--output",
        "-o",
        default="routeros-ast.json",
        help="Output JSON file (default: routeros-ast.json)",
    )
    parser.add_argument(
        "--only-add-set",
        action="store_true",
        help="Only traverse deeper into 'add'/'set' commands (and all submenus).",
    )
    args = parser.parse_args()

    ast, dir_path_count, cmd_count = traverse(args.host, args.user, args.password, only_add_set=args.only_add_set)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(ast, f, indent=2, sort_keys=True)

    print(f"[INFO] Wrote AST to {args.output}")
    print(f"[INFO] Total dir/path-like nodes: {dir_path_count}")
    print(f"[INFO] Total cmd-only nodes: {cmd_count}")


if __name__ == "__main__":
    main()
