from __future__ import annotations

from .schemas import ThreatCatalogItem, ThreatProfile


THREAT_CATALOG: list[ThreatCatalogItem] = [
    ThreatCatalogItem(
        threat_id="COMPASS-P1-01",
        profile=ThreatProfile.EXTERNAL,
        category="AI Enabled Cyber Threats",
        name="AI-assisted attack acceleration",
        description="Adversaries use AI to accelerate reconnaissance, vulnerability discovery, scripting, exploit development, or adaptation.",
        sample_signals=["abnormal automated reconnaissance", "rapid script/payload iteration", "high-rate vulnerability probing"],
        mitigations=["behavioral detection", "rate limiting", "threat-informed hunting", "attack-surface reduction"],
        framework_refs={"ATT&CK": ["T1592", "T1595", "T1059", "T1587"], "ATLAS": ["TA0031", "TA0032", "TA0002"]},
    ),
    ThreatCatalogItem(
        threat_id="COMPASS-P1-02",
        profile=ThreatProfile.EXTERNAL,
        category="Identity Compromise",
        name="Synthetic identity and social engineering",
        description="Deepfakes, voice cloning, and AI-generated communications are used to impersonate trusted people or organizations.",
        sample_signals=["unusual executive approval request", "synthetic voice/video indicators", "multilingual high-quality spear phishing"],
        mitigations=["out-of-band verification", "phishing-resistant MFA", "transaction approval controls", "deepfake awareness procedures"],
        framework_refs={"ATT&CK": ["T1566"], "ATLAS": ["TA0003"]},
    ),
    ThreatCatalogItem(
        threat_id="COMPASS-P2A-01",
        profile=ThreatProfile.INTERNAL_GENERAL,
        category="Asset Management",
        name="Shadow AI",
        description="AI systems, local models, applications, or integrations operate without central inventory, ownership, or authorization.",
        sample_signals=["unknown AI domain", "unregistered local model", "unapproved AI desktop or browser application"],
        mitigations=["AI asset discovery", "central registry", "owner assignment", "approved-use policy"],
        framework_refs={"OWASP_COMPASS": ["Profile 2A"]},
    ),
    ThreatCatalogItem(
        threat_id="COMPASS-P2A-02",
        profile=ThreatProfile.INTERNAL_GENERAL,
        category="Monitoring and Logging",
        name="AI observability gap",
        description="Security teams lack sufficient prompt, output, authorization, metadata, system, or sensitive-data handling telemetry.",
        sample_signals=["AI use without correlated identity", "missing prompt/output audit trail", "agent actions without tool lineage"],
        mitigations=["normalize AI telemetry", "retain trace identifiers", "correlate identity/device/tool context", "forward security findings to SIEM/SOAR"],
        framework_refs={"OWASP_COMPASS": ["Profile 2A Technical and Security Gaps"]},
    ),
    ThreatCatalogItem(
        threat_id="COMPASS-P2B-01",
        profile=ThreatProfile.ENTERPRISE_ASSISTANT,
        category="Access and Permissions",
        name="Overprivileged enterprise AI data access",
        description="Enterprise assistants expose information users technically can access but do not need, magnifying stale or excessive permissions.",
        sample_signals=["sensitive content surfaced from stale sites", "broad SharePoint/Drive access", "assistant access to oversized shared repositories"],
        mitigations=["least privilege", "permission cleanup", "sensitivity labels", "DLP", "access reviews"],
        framework_refs={"OWASP_COMPASS": ["Profile 2B"]},
    ),
    ThreatCatalogItem(
        threat_id="COMPASS-P2C-01",
        profile=ThreatProfile.AGENTIC,
        category="Tool and Execution Misuse",
        name="Prompt injection causes unauthorized tool behavior",
        description="Adversarial instructions influence a model or agent into invoking tools, code, APIs, or business actions outside intended policy.",
        sample_signals=["instruction-override text", "unexpected tool invocation", "tool use after untrusted retrieval", "privileged action without approval"],
        mitigations=["content trust boundaries", "tool authorization", "human approval", "sandboxing", "execution trace logging"],
        framework_refs={"CWE": ["CWE-77", "CWE-1427", "CWE-94", "CWE-78"], "OWASP_COMPASS": ["Profile 2C"]},
    ),
    ThreatCatalogItem(
        threat_id="COMPASS-P2C-02",
        profile=ThreatProfile.AGENTIC,
        category="Identity and Privilege",
        name="Overprivileged non-human identity",
        description="Agents, bots, service accounts, API keys, or tool credentials have excessive privileges that increase lateral movement and blast radius.",
        sample_signals=["persistent privileged token", "agent account outside IAM governance", "cross-environment credential reuse"],
        mitigations=["short-lived credentials", "least privilege", "workload identity", "separation of duties", "credential rotation"],
        framework_refs={"OWASP_COMPASS": ["Profile 2C Identity, Access, and Privilege Risks"]},
    ),
    ThreatCatalogItem(
        threat_id="COMPASS-P2C-03",
        profile=ThreatProfile.AGENTIC,
        category="Multi-Agent Risk",
        name="Recursive or uncontrolled delegated execution",
        description="Agents recursively delegate or chain actions, increasing resource consumption and allowing one compromised context to propagate through a workflow.",
        sample_signals=["high chain depth", "repeated agent-to-agent calls", "runaway token or API use", "unexpected delegation path"],
        mitigations=["delegation limits", "quotas", "rate limits", "trace lineage", "circuit breakers"],
        framework_refs={"OWASP_COMPASS": ["Profile 2C Multi-Agent", "Profile 2C Infrastructure"]},
    ),
]


def get_catalog() -> list[ThreatCatalogItem]:
    return list(THREAT_CATALOG)
