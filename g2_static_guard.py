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
    "execlpe", "execvp", "execvpe",
})


def check_ast(source: str) -> list[str]:
    """Report statically recognizable SDK, network and dynamic-import paths."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ["Invalid Python syntax"]
    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".", 1)[0] in FORBIDDEN_ROOTS:
                    violations.append(f"L{node.lineno}: forbidden import")
        elif isinstance(node, ast.ImportFrom) and node.module:
            if node.level or node.module.split(".", 1)[0] in FORBIDDEN_ROOTS:
                violations.append(f"L{node.lineno}: forbidden import-from")
        elif isinstance(node, ast.Call):
            call = node.func
            if isinstance(call, ast.Name) and call.id in FORBIDDEN_CALLS:
                violations.append(f"L{node.lineno}: dynamic code/import forbidden")
            elif (isinstance(call, ast.Attribute)
                  and isinstance(call.value, ast.Name)
                  and call.value.id == "os"
                  and call.attr in FORBIDDEN_OS_ATTRS):
                violations.append(f"L{node.lineno}: process creation forbidden")
    return violations


def main(argv: list[str] | None = None) -> int:
    paths = argv if argv is not None else sys.argv[1:]
    if not paths:
        print("Must specify the G2 offline modules", file=sys.stderr)
        return 2
    errors = []
    for name in paths:
        path = Path(name)
        if path.name not in ("g2_evidence.py", "g2_collector_contract.py") or not path.is_file():
            errors.append("Unexpected scan target")
            continue
        errors.extend(check_ast(path.read_text(encoding="utf-8")))
    if errors:
        for msg in errors:
            print(msg, file=sys.stderr)
        return 1
    print(f"G2 static import/code guard PASS ({len(paths)} modules)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
