from workers.api_worker.tools.ffuf_api_tool import FfufApiTool
from workers.api_worker.tools.openapi_parser import OpenapiParserTool
from workers.api_worker.tools.graphql_introspect import GraphqlIntrospectTool
from workers.api_worker.tools.trufflehog_tool import TrufflehogTool

# Stage 2: auth_testing
from workers.api_worker.tools.jwt_tool import JwtTool
from workers.api_worker.tools.oauth_tester import OauthTesterTool
from workers.api_worker.tools.cors_scanner import CorsScannerTool

# Stage 3: injection_testing
from workers.api_worker.tools.idor_tester import IdorTesterTool
from workers.api_worker.tools.mass_assign_tester import MassAssignTesterTool
from workers.api_worker.tools.nosqlmap_tool import NosqlmapTool

__all__ = [
    # Stage 1: api_discovery
    "FfufApiTool",
    "OpenapiParserTool",
    "GraphqlIntrospectTool",
    "TrufflehogTool",
    # Stage 2: auth_testing
    "JwtTool",
    "OauthTesterTool",
    "CorsScannerTool",
    # Stage 3: injection_testing
    "IdorTesterTool",
    "MassAssignTesterTool",
    "NosqlmapTool",
]
