"""Static defense-in-depth for G2 offline-only Python modules.

Only checks source syntax. Passing this does NOT prove network non-reachability.
CI also runs tests with Docker --network none.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

FORBIDDEN_ROOTS = frozenset({
    "boto3", "botocore", "awscrt", "socket", "socketserver", "ssl",
    "requests", "urllib", "http", "httpx", "aiohttp", "aiofiles",
    "urllib3", "websockets", "websocket", "grpc", "ftplib", "smtplib",
    "poplib", "imaplib", "telnetlib", "xmlrpc", "subprocess",
    "importlib", "ctypes", "cffi", "multiprocessing",
})
FORBIDDEN_CALLS = frozenset({"__import__", "eval", "exec", "compile"})
FORBIDDEN_OS_ATTRS = frozenset({
    "system", "popen", "fork", "forkpty", "spawnl", "spawnle",
    "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp",
    "spawnvpe", "execv", "execve", "execl", "execle", "execlp",
    "execlpe", "execvp", "execvpe", "posix_spawn", "posix_spawnp",
    "startfile",
})


def check_ast(source: str) -> list[str]:
    """Report statically recognizable SDK, network and dynamic-import paths."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ["Invalid Python syntax"]
    violations: list[str] = []
    nodes = list(ast.walk(tree))
    os_module_aliases = {"os"}
    os_function_aliases: dict[str, str] = {}
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "os":
                    os_module_aliases.add(alias.asname or "os")
        elif isinstance(node, ast.ImportFrom) and node.module == "os":
            for alias in node.names:
                if alias.name in FORBIDDEN_OS_ATTRS:
                    os_function_aliases[alias.asname or alias.name] = alias.name

    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".", 1)[0] in FORBIDDEN_ROOTS:
                    violations.append(f"L{node.lineno}: forbidden import")
        elif isinstance(node, ast.ImportFrom):
            if node.level or (node.module and node.module.split(".", 1)[0] in FORBIDDEN_ROOTS):
                violations.append(f"L{node.lineno}: forbidden import-from")
        elif isinstance(node, ast.Call):
            call = node.func
            if isinstance(call, ast.Name) and call.id in FORBIDDEN_CALLS:
                violations.append(f"L{node.lineno}: dynamic code/import forbidden")
            elif (isinstance(call, ast.Attribute)
                  and isinstance(call.value, ast.Name)
                  and call.value.id in os_module_aliases
                  and call.attr in FORBIDDEN_OS_ATTRS):
                violations.append(f"L{node.lineno}: process creation forbidden")
            elif (isinstance(call, ast.Name)
                  and call.id in os_function_aliases):
                violations.append(f"L{node.lineno}: process creation forbidden")
    return violations


def main(argv: list[str] | None = None) -> int:
    # CLI flags may select/order the known modules, but can never choose paths.
    supplied = argv if argv is not None else sys.argv[1:]
    expected = ("g2_evidence.py", "g2_collector_contract.py")
    if len(supplied) != len(expected) or set(supplied) != set(expected):
        print("Only the two fixed G2 offline modules may be scanned", file=sys.stderr)
        return 1
    source_dir = Path(__file__).resolve().parent
    # These are constant, source-controlled filenames, never built from CLI input.
    fixed_paths = (
        source_dir / "g2_evidence.py",
        source_dir / "g2_collector_contract.py",
    )
    errors = []
    for path in fixed_paths:
        if path.is_symlink() or not path.is_file():
            errors.append("Missing or symlinked fixed source")
            continue
        errors.extend(check_ast(path.read_text(encoding="utf-8")))
    if errors:
        for msg in errors:
            print(msg, file=sys.stderr)
        return 1
    print("G2 static import/code guard PASS (2 fixed modules)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
