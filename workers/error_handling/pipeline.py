# workers/error_handling/pipeline.py
from dataclasses import dataclass, field


@dataclass
class Stage:
    name: str
    section_id: str
    tools: list = field(default_factory=list)


# Import all tool classes
from .tools.error_prober import ErrorProber
from .tools.stack_trace_detector import StackTraceDetector

STAGES = [
    Stage(name="error_codes", section_id="4.8.1", tools=[ErrorProber]),
    Stage(name="stack_traces", section_id="4.8.2", tools=[StackTraceDetector]),
]