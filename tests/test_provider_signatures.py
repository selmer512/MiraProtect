from __future__ import annotations

from mira_protect.providers import classify_ai_process


def test_windows_node_wrapper_path_classifies_claude() -> None:
    match = classify_ai_process(
        "node.exe",
        [
            r"C:\Program Files\nodejs\node.exe",
            r"C:\Users\tester\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\cli.js",
            r"C:\Users\tester\AppData\Roaming\npm\claude.exe",
        ],
    )
    assert match is not None
    assert match.provider == "anthropic"
    assert match.product == "Claude Code"
    assert match.signature.startswith("command-executable:")


def test_unknown_process_is_not_forced_into_ai_inventory() -> None:
    match = classify_ai_process("python", ["python", "build.py"])
    assert match is None
