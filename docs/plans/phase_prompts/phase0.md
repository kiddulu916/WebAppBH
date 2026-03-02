# "Common Core" & Library Setup

Act as a Senior Python Developer and DevOps Architect.
Task: Create the 'lib_webbh' shared library for the WebAppBH Framework.

## 1. Package Structure

Create a Python package in `/app/shared/lib_webbh/` with the following files:

- **init_.py**: Exports the core classes.
- **database.py**: SQLAlchemy 2.0 Singleton engine with models for: 
    Targets, Assets, Locations, Observations, Parameters, Vulnerabilities, JobState.
- **scope.py**: 'ScopeManager' class using `netaddr` and `re`. It must support:
    - '.is_in_scope(item)': Returns Boolean.
    - Support for `*.domain.com`, `192.168.1.0/24`, and specific regex strings.
- `messaging.py`: Redis wrapper with `push_task(queue, data)` and `listen_queue(queue)`.
- `logger.py`: Custom logger that outputs structured JSON to STDOUT and a shared log file.

## 2. Auto-Configuration Script

- Create `setup_env.py`:
    - Generates a `WEB_APP_BH_API_KEY` (64-char hex).
    - Detects the host IP and writes a `.env` file to the shared volume.
    - This key will be used for Orchestrator-to-Worker authentication.

## 3. The Base Dockerfile

- Create a `Dockerfile.base`:
    - Use `python:3.10-slim`.
    - Install `lib_webbh` as an editable dev-link (`pip install -e .`).
    - Pre-install `sqlalchemy`, `psycopg2-binary`, `redis`, `pydantic`, `netaddr`, `tldextract`.

Deliverables: The complete Python package code and the Dockerfile.base.