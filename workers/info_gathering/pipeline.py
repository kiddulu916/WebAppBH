# workers/info_gathering/pipeline.py
from dataclasses import dataclass, field


@dataclass
class Stage:
    name: str
    section_id: str
    tools: list = field(default_factory=list)


# Import all tool classes
from .tools.dork_engine import DorkEngine
from .tools.archive_prober import ArchiveProber
from .tools.nmap import Nmap
from .tools.whatweb import WhatWeb
from .tools.httpx import Httpx
from .tools.metafile_parser import MetafileParser
from .tools.subfinder import Subfinder
from .tools.assetfinder import Assetfinder
from .tools.amass_passive import AmassPassive
from .tools.amass_active import AmassActive
from .tools.massdns import Massdns
from .tools.vhost_prober import VHostProber
from .tools.comment_harvester import CommentHarvester
from .tools.metadata_extractor import MetadataExtractor
from .tools.form_mapper import FormMapper
from .tools.paramspider import Paramspider
from .tools.katana import Katana
from .tools.hakrawler import Hakrawler
from .tools.wappalyzer import Wappalyzer
from .tools.cookie_fingerprinter import CookieFingerprinter
from .tools.webanalyze import Webanalyze
from .tools.naabu import Naabu
from .tools.waybackurls import Waybackurls
from .tools.architecture_modeler import ArchitectureModeler

STAGES = [
    Stage(name="search_engine_recon", section_id="4.1.1", tools=[DorkEngine, ArchiveProber]),
    Stage(name="web_server_fingerprint", section_id="4.1.2", tools=[Nmap, WhatWeb, Httpx]),
    Stage(name="web_server_metafiles", section_id="4.1.3", tools=[MetafileParser]),
    Stage(name="enumerate_subdomains", section_id="4.1.4", tools=[Subfinder, Assetfinder, AmassPassive, AmassActive, Massdns, VHostProber]),
    Stage(name="review_comments", section_id="4.1.5", tools=[CommentHarvester, MetadataExtractor]),
    Stage(name="identify_entry_points", section_id="4.1.6", tools=[FormMapper, Paramspider, Httpx]),
    Stage(name="map_execution_paths", section_id="4.1.7", tools=[Katana, Hakrawler]),
    Stage(name="fingerprint_framework", section_id="4.1.8", tools=[Wappalyzer, CookieFingerprinter, Webanalyze]),
    Stage(name="map_architecture", section_id="4.1.9", tools=[Naabu, Waybackurls, ArchitectureModeler]),
    Stage(name="map_application", section_id="4.1.10", tools=[]),  # Post-processing stage
]