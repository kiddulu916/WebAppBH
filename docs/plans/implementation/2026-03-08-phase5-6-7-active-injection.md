# Phase 5/6/7 Active Injection Testing Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add active injection testing tools across Phase 5 (dalfox, ppmap), Phase 6 (crlfuzz, Oralyzer), and build the complete Phase 7 vuln scanner worker (Nuclei + sqlmap, tplmap, XXEinjector, commix, SSRFmap, smuggler, host header tool, ysoserial, phpggc).

**Architecture:** Each phase follows the established BaseTool, Pipeline, main.py pattern. Phase 5/6 get new tools appended to existing pipelines. Phase 7 is a new worker with a 3-stage pipeline (nuclei_sweep, active_injection, broad_injection_sweep) and a routing module that maps Nuclei findings to active tools.

**Tech Stack:** Python 3.10+, asyncio, SQLAlchemy async, aiohttp, lib_webbh shared models, Docker multi-stage builds.

**Design doc:** docs/plans/design/2026-03-08-vuln-scanning-active-injection-design.md

---

## Summary of Tasks

| Task | Phase | Description |
|------|-------|-------------|
| 1 | 5 | DalfoxTool — reflected/stored XSS scanning |
| 2 | 5 | PpmapTool — prototype pollution + Dockerfile update |
| 3 | 6 | CrlfuzzTool — CRLF injection |
| 4 | 6 | OralyzerTool — open redirect + Dockerfile update |
| 5 | 7 | Worker skeleton (base_tool, concurrency, __init__) |
| 6 | 7 | NucleiTool + template_sync (Stage 1) |
| 7 | 7 | Nuclei router (Stage 2 triage logic) |
| 8 | 7 | SqlmapTool |
| 9 | 7 | TplmapTool |
| 10 | 7 | XXEinjectorTool |
| 11 | 7 | CommixTool |
| 12 | 7 | SSRFmapTool |
| 13 | 7 | SmugglerTool |
| 14 | 7 | HostHeaderTool |
| 15 | 7 | YsoserialTool + PhpggcTool |
| 16 | 7 | Pipeline + main.py |
| 17 | 7 | Dockerfile.vulnscanner |
| 18 | 7 | Final tool registration + import verification |

See the full task details in the design document and the approved brainstorming session.
Each task follows the pattern: create tool file, register in __init__.py, update pipeline, commit.
