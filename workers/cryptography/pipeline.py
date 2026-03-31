# workers/cryptography/pipeline.py
from dataclasses import dataclass, field


@dataclass
class Stage:
    name: str
    section_id: str
    tools: list = field(default_factory=list)


# Import all tool classes
from .tools.tls_auditor import TlsAuditor
from .tools.padding_oracle_tester import PaddingOracleTester
from .tools.plaintext_leak_scanner import PlaintextLeakScanner
from .tools.algorithm_auditor import AlgorithmAuditor

STAGES = [
    Stage(name="tls_testing", section_id="4.9.1", tools=[TlsAuditor]),
    Stage(name="padding_oracle", section_id="4.9.2", tools=[PaddingOracleTester]),
    Stage(name="plaintext_transmission", section_id="4.9.3", tools=[PlaintextLeakScanner]),
    Stage(name="weak_crypto", section_id="4.9.4", tools=[AlgorithmAuditor]),
]