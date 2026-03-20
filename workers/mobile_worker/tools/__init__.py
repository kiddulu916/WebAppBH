# Stage 1: acquire_decompile
from workers.mobile_worker.tools.binary_downloader import BinaryDownloaderTool
from workers.mobile_worker.tools.apktool_decompiler import ApktoolDecompilerTool
from workers.mobile_worker.tools.mobsf_scanner import MobsfScannerTool

# Stage 2: secret_extraction
from workers.mobile_worker.tools.secret_scanner import SecretScannerTool
from workers.mobile_worker.tools.mobsf_secrets import MobsfSecretsTool

# Stage 3: configuration_audit
from workers.mobile_worker.tools.manifest_auditor import ManifestAuditorTool
from workers.mobile_worker.tools.ios_plist_auditor import IosPlistAuditorTool
from workers.mobile_worker.tools.deeplink_analyzer import DeeplinkAnalyzerTool

# Stage 4: dynamic_analysis
from workers.mobile_worker.tools.frida_crypto_hooker import FridaCryptoHookerTool
from workers.mobile_worker.tools.frida_root_detector import FridaRootDetectorTool
from workers.mobile_worker.tools.frida_component_prober import FridaComponentProberTool

# Stage 5: endpoint_feedback
from workers.mobile_worker.tools.endpoint_extractor import EndpointExtractorTool

__all__ = [
    # Stage 1: acquire_decompile
    "BinaryDownloaderTool",
    "ApktoolDecompilerTool",
    "MobsfScannerTool",
    # Stage 2: secret_extraction
    "SecretScannerTool",
    "MobsfSecretsTool",
    # Stage 3: configuration_audit
    "ManifestAuditorTool",
    "IosPlistAuditorTool",
    "DeeplinkAnalyzerTool",
    # Stage 4: dynamic_analysis
    "FridaCryptoHookerTool",
    "FridaRootDetectorTool",
    "FridaComponentProberTool",
    # Stage 5: endpoint_feedback
    "EndpointExtractorTool",
]
