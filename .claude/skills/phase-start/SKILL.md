---
name: phase-start
description: Start a new project phase — reads the phase prompt, creates dated design and implementation plan docs following project naming conventions
---

# Start a New Phase

Begin a new phase of the WebAppBH framework by creating the required planning documents.

## Arguments

The user must provide:
- **Phase number**: e.g., `11` (maps to `docs/plans/phase_prompts/phase11.md`)

If not provided, ask which phase to start.

## Workflow

### Step 1: Read Context

Read these files in order:
1. `docs/plans/phase_prompts/intro_prompt.md` — Project overview and role
2. `docs/plans/phase_prompts/phase{N}.md` — The specific phase spec

### Step 2: Review Existing Work

Check what's already been built by scanning:
- `docs/plans/design/` — Existing design docs for context on prior phases
- `docs/plans/implementation/` — Existing implementation plans
- Relevant source directories mentioned in the phase prompt

This gives context on what infrastructure/patterns already exist.

### Step 3: Create Design Document

Create `docs/plans/design/{today}-phase{N}-{short-topic}-design.md` where:
- `{today}` is the current date in `YYYY-MM-DD` format
- `{short-topic}` is a kebab-case summary (e.g., `cloud-worker`, `dashboard`)

The design doc should cover:
- **Goal**: What this phase accomplishes
- **Architecture**: How it fits into the existing system
- **Data model**: New tables/columns or changes to existing models
- **Messaging**: New queues, message formats, event types
- **API changes**: New endpoints or modifications
- **Worker design** (if applicable): Tools, stages, pipeline structure
- **Dashboard changes** (if applicable): New pages, components, data flows
- **Dependencies**: What prior phases must be complete
- **Open questions**: Decisions that need input

**IMPORTANT**: Do NOT do extensive research. Reference the phase prompt, existing design docs, and CLAUDE.md directly. Keep it focused and actionable.

### Step 4: Create Implementation Plan

Create `docs/plans/implementation/{today}-phase{N}-{short-topic}.md` with:
- **Ordered task list**: Numbered steps with file paths
- **File changes**: Exactly which files to create/modify
- **Testing plan**: What tests to write and how to verify
- **Docker changes**: New Dockerfiles, compose entries
- **Migration steps**: Database schema changes if any

Reference the design doc you just created. Each task should be small enough to implement in one focused session.

**IMPORTANT**: Do NOT do extensive research. Reference the design doc and existing docs directly.

### Step 5: Confirm with User

Present a summary of both documents and ask if the user wants to proceed with implementation or adjust the plan.

## Naming Convention Reference

From existing docs:
- Design: `2026-03-19-phase10-cloud-worker-design.md`
- Implementation: `2026-03-19-phase10-cloud-worker.md`

Follow this exact pattern.
