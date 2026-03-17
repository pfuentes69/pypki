"""
PyPKI test runner.

Usage:
    python -m tests          # interactive menu
    python tests/__main__.py # same
"""

import ast
import glob
import os
import runpy
import sys


TESTS_DIR = os.path.dirname(os.path.abspath(__file__))


def _read_description(filepath: str) -> str:
    """Extract the DESCRIPTION variable from a test file using AST (no execution)."""
    try:
        with open(filepath, "r") as f:
            tree = ast.parse(f.read(), filename=filepath)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "DESCRIPTION":
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            return node.value.value
    except Exception:
        pass
    # Fallback: pretty-print the filename
    name = os.path.splitext(os.path.basename(filepath))[0]
    return name.replace("_", " ").title()


def discover_tests() -> list:
    """Return a sorted list of (description, filepath) for all test files."""
    pattern = os.path.join(TESTS_DIR, "*.py")
    tests = []
    for path in sorted(glob.glob(pattern)):
        if os.path.basename(path).startswith("_"):
            continue
        tests.append((_read_description(path), path))
    return tests


def print_menu(tests: list) -> None:
    print()
    print("  PyPKI – Tests")
    print("  " + "─" * 40)
    for i, (desc, _) in enumerate(tests, start=1):
        print(f"  {i:2}.  {desc}")
    print()
    print("   0.  Exit")
    print()


def run_test(filepath: str) -> None:
    print()
    print("─" * 60)
    try:
        runpy.run_path(filepath, run_name="__main__")
    except SystemExit:
        pass
    except Exception as exc:
        print(f"\nERROR: {exc}")
    print("─" * 60)


def main() -> None:
    tests = discover_tests()

    if not tests:
        print("No test files found in", TESTS_DIR)
        sys.exit(0)

    while True:
        print_menu(tests)
        try:
            raw = input("  Select: ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            break

        if raw == "0":
            break

        if not raw.isdigit() or not (1 <= int(raw) <= len(tests)):
            print(f"  Invalid selection. Enter a number between 0 and {len(tests)}.")
            continue

        _, filepath = tests[int(raw) - 1]
        run_test(filepath)

        try:
            input("\n  Press Enter to return to the menu...")
        except (KeyboardInterrupt, EOFError):
            print()
            break

    print("\nBye!")


if __name__ == "__main__":
    main()
