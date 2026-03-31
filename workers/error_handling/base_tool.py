# workers/error_handling/base_tool.py
from abc import ABC, abstractmethod
from typing import Optional
from lib_webbh import get_session, Vulnerability


class ErrorHandlingTool(ABC):
    """Abstract base for all error_handling tools."""

    worker_type = "error_handling"

    @abstractmethod
    async def execute(self, target_id: int, **kwargs):
        """Run this tool against the target. Must be implemented by subclasses."""
        ...

    async def save_vulnerability(self, target_id, **kwargs):
        """Helper: insert a Vulnerability record."""
        async with get_session() as session:
            vuln = Vulnerability(
                target_id=target_id,
                worker_type=self.worker_type,
                **kwargs,
            )
            session.add(vuln)
            await session.commit()
            return vuln.id

    def detect_framework_error_page(self, response_body: str) -> Optional[str]:
        """Match response against known framework error page signatures."""
        # Common framework error patterns
        error_patterns = {
            "ASP.NET": ["Server Error in '/' Application", "Runtime Error"],
            "PHP": ["Fatal error:", "Parse error:", "Warning:"],
            "Java": ["java.lang.", "Exception in thread", "javax.servlet"],
            "Python": ["Traceback (most recent call last)", "Django", "Flask"],
            "Node.js": ["Error:", "throw new Error", "uncaughtException"],
            "Ruby": ["Rails", "NoMethodError", "undefined method"],
        }

        for framework, patterns in error_patterns.items():
            for pattern in patterns:
                if pattern.lower() in response_body.lower():
                    return framework
        return None

    def extract_stack_trace(self, response_body: str) -> list[dict]:
        """Parse stack traces from response bodies."""
        import re

        stack_traces = []

        # Python traceback pattern
        python_pattern = r'File "([^"]+)", line (\d+), in ([^\n]+)\n([^\n]*)\n'
        for match in re.finditer(python_pattern, response_body, re.MULTILINE):
            stack_traces.append({
                "framework": "Python",
                "file": match.group(1),
                "line": int(match.group(2)),
                "function": match.group(3),
                "code": match.group(4).strip(),
            })

        # Java stack trace pattern
        java_pattern = r'at ([^\(]+)\(([^:]+):(\d+)\)'
        for match in re.finditer(java_pattern, response_body):
            stack_traces.append({
                "framework": "Java",
                "method": match.group(1),
                "file": match.group(2),
                "line": int(match.group(3)),
            })

        # .NET stack trace pattern
        dotnet_pattern = r'at ([^\s]+) in ([^:]+):line (\d+)'
        for match in re.finditer(dotnet_pattern, response_body):
            stack_traces.append({
                "framework": ".NET",
                "method": match.group(1),
                "file": match.group(2),
                "line": int(match.group(3)),
            })

        return stack_traces