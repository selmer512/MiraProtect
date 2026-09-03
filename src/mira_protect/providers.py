from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .schemas import DeploymentType


@dataclass(frozen=True)
class AIProductSignature:
    provider: str
    product: str
    deployment_type: DeploymentType
    process_names: tuple[str, ...] = ()
    command_markers: tuple[str, ...] = ()


@dataclass(frozen=True)
class AIProductMatch:
    provider: str
    product: str
    deployment_type: DeploymentType
    signature: str


SIGNATURES: tuple[AIProductSignature, ...] = (
    AIProductSignature(
        provider="anthropic",
        product="Claude Code",
        deployment_type=DeploymentType.VENDOR_UI,
        process_names=("claude", "claude.exe"),
        command_markers=("@anthropic-ai/claude-code", "/claude", "\\claude"),
    ),
    AIProductSignature(
        provider="openai",
        product="Codex CLI",
        deployment_type=DeploymentType.VENDOR_UI,
        process_names=("codex", "codex.exe"),
        command_markers=("@openai/codex", "openai codex", "/codex", "\\codex"),
    ),
    AIProductSignature(
        provider="github",
        product="GitHub Copilot CLI",
        deployment_type=DeploymentType.ENTERPRISE_LICENSED,
        process_names=("copilot", "copilot.exe"),
        command_markers=("gh copilot", "github copilot"),
    ),
    AIProductSignature(
        provider="google",
        product="Gemini CLI",
        deployment_type=DeploymentType.VENDOR_UI,
        process_names=("gemini", "gemini.exe"),
        command_markers=("@google/gemini-cli", "/gemini", "\\gemini"),
    ),
    AIProductSignature(
        provider="local",
        product="Ollama",
        deployment_type=DeploymentType.PRETRAINED_OR_FINETUNED,
        process_names=("ollama", "ollama.exe"),
        command_markers=("ollama run", "ollama serve"),
    ),
    AIProductSignature(
        provider="local",
        product="LM Studio",
        deployment_type=DeploymentType.PRETRAINED_OR_FINETUNED,
        process_names=("lmstudio", "lmstudio.exe", "lm studio"),
        command_markers=("lmstudio", "lm studio"),
    ),
    AIProductSignature(
        provider="cursor",
        product="Cursor",
        deployment_type=DeploymentType.VENDOR_UI,
        process_names=("cursor", "cursor.exe"),
        command_markers=("cursor-agent",),
    ),
    AIProductSignature(
        provider="community",
        product="Aider",
        deployment_type=DeploymentType.VENDOR_UI,
        process_names=("aider", "aider.exe"),
        command_markers=("aider-chat", "/aider", "\\aider"),
    ),
    AIProductSignature(
        provider="community",
        product="OpenCode",
        deployment_type=DeploymentType.VENDOR_UI,
        process_names=("opencode", "opencode.exe"),
        command_markers=("/opencode", "\\opencode"),
    ),
)


def _normalized_process_name(value: str) -> str:
    return Path(value or "").name.lower()


def classify_ai_process(process_name: str, command_line: list[str]) -> AIProductMatch | None:
    """Classify an endpoint process using extensible product signatures.

    Classification is deliberately separate from policy. Finding a product means Mira
    Protect discovered AI software; it does not imply the process should be blocked.
    """

    normalized_name = _normalized_process_name(process_name)
    command = " ".join(str(value) for value in command_line).lower()
    argument_basenames = {_normalized_process_name(str(value)) for value in command_line}

    for signature in SIGNATURES:
        names = {name.lower() for name in signature.process_names}
        if normalized_name in names or names.intersection(argument_basenames):
            return AIProductMatch(
                provider=signature.provider,
                product=signature.product,
                deployment_type=signature.deployment_type,
                signature=f"process:{normalized_name}",
            )
        for marker in signature.command_markers:
            if marker.lower() in command:
                return AIProductMatch(
                    provider=signature.provider,
                    product=signature.product,
                    deployment_type=signature.deployment_type,
                    signature=f"command:{marker}",
                )
    return None


def known_ai_process_names() -> set[str]:
    return {
        name.lower()
        for signature in SIGNATURES
        for name in signature.process_names
        if name
    }


def known_ai_command_markers() -> set[str]:
    return {
        marker.lower()
        for signature in SIGNATURES
        for marker in signature.command_markers
        if marker
    }
