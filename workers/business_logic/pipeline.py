# workers/business_logic/pipeline.py
from dataclasses import dataclass, field


@dataclass
class Stage:
    name: str
    section_id: str
    tools: list = field(default_factory=list)


# Import all tool classes
from .tools.business_validation_tester import BusinessValidationTester
from .tools.request_forgery_tester import RequestForgeryTester
from .tools.integrity_tester import IntegrityTester
from .tools.timing_analyzer import TimingAnalyzer
from .tools.rate_limit_tester import RateLimitTester
from .tools.workflow_bypass_tester import WorkflowBypassTester
from .tools.misuse_tester import MisuseTester
from .tools.file_type_tester import FileTypeTester
from .tools.malicious_upload_tester import MaliciousUploadTester

STAGES = [
    Stage(name="data_validation", section_id="4.10.1", tools=[BusinessValidationTester]),
    Stage(name="request_forgery", section_id="4.10.2", tools=[RequestForgeryTester]),
    Stage(name="integrity_checks", section_id="4.10.3", tools=[IntegrityTester]),
    Stage(name="process_timing", section_id="4.10.4", tools=[TimingAnalyzer]),
    Stage(name="rate_limiting", section_id="4.10.5", tools=[RateLimitTester]),
    Stage(name="workflow_bypass", section_id="4.10.6", tools=[WorkflowBypassTester]),
    Stage(name="application_misuse", section_id="4.10.7", tools=[MisuseTester]),
    Stage(name="file_upload_validation", section_id="4.10.8", tools=[FileTypeTester]),
    Stage(name="malicious_file_upload", section_id="4.10.9", tools=[MaliciousUploadTester]),
]