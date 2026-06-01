# CSPBypass GitHub Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the `cspbypass` pip package with an in-process Python lookup backed by `data.tsv` from `renniepak/CSPBypass`, downloaded at Docker build time.

**Architecture:** `data.tsv` is `wget`-ed into the image at `/cspbypass/data.tsv` during Docker build. At module import time `csp_tester.py` reads it into `_BYPASS_DB`. Three new pure-Python helpers — `_load_bypass_db`, `_parse_csp_source`, `_matches_csp_source` — replace the `_run_csp_bypass` subprocess; the new orchestrating function `_match_csp_bypasses(csp_header, url)` is called synchronously at the existing Layer 3 call site.

**Tech Stack:** Python 3.12, `urllib.parse`, `re`, no new dependencies.

---

## File Map

| File | Action | What changes |
|------|--------|-------------|
| `docker/Dockerfile.config_mgmt` | Modify | Remove `cspbypass` from pip install; add `wget` of `data.tsv` |
| `workers/config_mgmt/requirements.txt` | Modify | Remove `cspbypass>=0.1.0` |
| `workers/config_mgmt/tools/csp_tester.py` | Modify | Add `import os`; add module-level constants and `_load_bypass_db`; add `_parse_csp_source`, `_matches_csp_source`, `_match_csp_bypasses`; delete `_run_csp_bypass`; update call site in `_probe_url` |
| `tests/unit/config_mgmt/test_csp_tester.py` | Modify | Add tests for the four new symbols |

---

## Task 1: Remove pip dependency and bake data.tsv into Docker image

**Files:**
- Modify: `docker/Dockerfile.config_mgmt:67`
- Modify: `workers/config_mgmt/requirements.txt`

- [ ] **Step 1: Edit Dockerfile — remove cspbypass from pip install and add wget step**

  In `docker/Dockerfile.config_mgmt`, replace line 67:
  ```dockerfile
  RUN pip install --no-cache-dir aiohttp cspbypass
  ```
  with:
  ```dockerfile
  # CSPBypass bypass gadget database (renniepak/CSPBypass)
  RUN mkdir -p /cspbypass && \
      wget -q -O /cspbypass/data.tsv \
      https://raw.githubusercontent.com/renniepak/CSPBypass/main/data.tsv

  RUN pip install --no-cache-dir aiohttp
  ```

- [ ] **Step 2: Edit requirements.txt — remove cspbypass**

  Replace the entire contents of `workers/config_mgmt/requirements.txt` with:
  ```
  beautifulsoup4>=4.12.0
  ```

- [ ] **Step 3: Commit**

  ```bash
  git add docker/Dockerfile.config_mgmt workers/config_mgmt/requirements.txt
  git commit -m "build(config_mgmt): replace cspbypass pip package with renniepak/CSPBypass data.tsv"
  ```

---

## Task 2: Add module-level TSV loader to csp_tester.py

**Files:**
- Modify: `workers/config_mgmt/tools/csp_tester.py`
- Test: `tests/unit/config_mgmt/test_csp_tester.py`

- [ ] **Step 1: Write failing tests**

  Append to `tests/unit/config_mgmt/test_csp_tester.py`:

  ```python
  import os
  import workers.config_mgmt.tools.csp_tester as csp_mod
  from workers.config_mgmt.tools.csp_tester import _load_bypass_db


  def test_load_bypass_db_reads_two_column_tsv(tmp_path, monkeypatch):
      tsv = tmp_path / "data.tsv"
      tsv.write_text(
          'ajax.googleapis.com\t<script src="https://ajax.googleapis.com/libs/jquery/2.1.4/jquery.min.js"></script>\n'
          'cdn.example.com\t<script src="https://cdn.example.com/x.js"></script>\n',
          encoding="utf-8",
      )
      monkeypatch.setattr(csp_mod, "_BYPASS_DB_PATH", str(tsv))
      result = _load_bypass_db()
      assert len(result) == 2
      assert result[0] == ("ajax.googleapis.com", '<script src="https://ajax.googleapis.com/libs/jquery/2.1.4/jquery.min.js"></script>')
      assert result[1] == ("cdn.example.com", '<script src="https://cdn.example.com/x.js"></script>')


  def test_load_bypass_db_domain_only_rows(tmp_path, monkeypatch):
      tsv = tmp_path / "data.tsv"
      tsv.write_text("example.com\nother.com\n", encoding="utf-8")
      monkeypatch.setattr(csp_mod, "_BYPASS_DB_PATH", str(tsv))
      result = _load_bypass_db()
      assert result == [("example.com", ""), ("other.com", "")]


  def test_load_bypass_db_missing_file_returns_empty(tmp_path, monkeypatch):
      monkeypatch.setattr(csp_mod, "_BYPASS_DB_PATH", str(tmp_path / "nonexistent.tsv"))
      result = _load_bypass_db()
      assert result == []


  def test_load_bypass_db_lowercases_domain(tmp_path, monkeypatch):
      tsv = tmp_path / "data.tsv"
      tsv.write_text("AJAX.GoogleAPIs.COM\t<script src=\"https://AJAX.GoogleAPIs.COM/x.js\"></script>\n", encoding="utf-8")
      monkeypatch.setattr(csp_mod, "_BYPASS_DB_PATH", str(tsv))
      result = _load_bypass_db()
      assert result[0][0] == "ajax.googleapis.com"
  ```

- [ ] **Step 2: Run tests to verify they fail**

  ```bash
  pytest tests/unit/config_mgmt/test_csp_tester.py::test_load_bypass_db_reads_two_column_tsv \
         tests/unit/config_mgmt/test_csp_tester.py::test_load_bypass_db_domain_only_rows \
         tests/unit/config_mgmt/test_csp_tester.py::test_load_bypass_db_missing_file_returns_empty \
         tests/unit/config_mgmt/test_csp_tester.py::test_load_bypass_db_lowercases_domain \
         -v
  ```
  Expected: `ImportError` or `AttributeError` — `_load_bypass_db` not yet defined.

- [ ] **Step 3: Add `import os`, `_BYPASS_DB_PATH`, `_load_bypass_db`, and `_BYPASS_DB` to csp_tester.py**

  In `workers/config_mgmt/tools/csp_tester.py`, add `import os` to the stdlib imports block (after `import re`, before `from datetime`):
  ```python
  import os
  ```

  Then add the following block immediately after the `logger = setup_logger(...)` line:
  ```python
  _BYPASS_DB_PATH: str = os.environ.get("CSPBYPASS_DATA_PATH", "/cspbypass/data.tsv")


  def _load_bypass_db() -> list[tuple[str, str]]:
      try:
          db: list[tuple[str, str]] = []
          with open(_BYPASS_DB_PATH, encoding="utf-8") as f:
              for line in f:
                  line = line.rstrip("\n")
                  if "\t" in line:
                      domain, code = line.split("\t", 1)
                  else:
                      domain, code = line.strip(), ""
                  if domain.strip():
                      db.append((domain.strip().lower(), code.strip()))
          return db
      except FileNotFoundError:
          logger.warning(f"CSPBypass data file not found at {_BYPASS_DB_PATH} — Layer 3 disabled")
          return []
      except Exception as exc:
          logger.warning(f"Failed to load CSPBypass data: {exc} — Layer 3 disabled")
          return []


  _BYPASS_DB: list[tuple[str, str]] = _load_bypass_db()
  ```

- [ ] **Step 4: Run tests to verify they pass**

  ```bash
  pytest tests/unit/config_mgmt/test_csp_tester.py::test_load_bypass_db_reads_two_column_tsv \
         tests/unit/config_mgmt/test_csp_tester.py::test_load_bypass_db_domain_only_rows \
         tests/unit/config_mgmt/test_csp_tester.py::test_load_bypass_db_missing_file_returns_empty \
         tests/unit/config_mgmt/test_csp_tester.py::test_load_bypass_db_lowercases_domain \
         -v
  ```
  Expected: all 4 PASS.

- [ ] **Step 5: Verify existing tests still pass**

  ```bash
  pytest tests/unit/config_mgmt/test_csp_tester.py -v
  ```
  Expected: all existing tests PASS (the module-level `_load_bypass_db()` call logs a warning when `/cspbypass/data.tsv` is absent in the test environment, but returns `[]` and does not raise).

- [ ] **Step 6: Commit**

  ```bash
  git add workers/config_mgmt/tools/csp_tester.py \
          tests/unit/config_mgmt/test_csp_tester.py
  git commit -m "feat(config_mgmt): add module-level CSPBypass TSV loader"
  ```

---

## Task 3: Add `_parse_csp_source` helper

**Files:**
- Modify: `workers/config_mgmt/tools/csp_tester.py`
- Test: `tests/unit/config_mgmt/test_csp_tester.py`

- [ ] **Step 1: Write failing tests**

  Append to `tests/unit/config_mgmt/test_csp_tester.py`:

  ```python
  from workers.config_mgmt.tools.csp_tester import _parse_csp_source


  def test_parse_csp_source_bare_host():
      result = _parse_csp_source("ajax.googleapis.com")
      assert result == {
          "scheme": None,
          "host": "ajax.googleapis.com",
          "wildcard_subdomain": False,
          "path_prefix": None,
      }


  def test_parse_csp_source_wildcard_subdomain():
      result = _parse_csp_source("*.googleapis.com")
      assert result == {
          "scheme": None,
          "host": "googleapis.com",
          "wildcard_subdomain": True,
          "path_prefix": None,
      }


  def test_parse_csp_source_scheme_and_host():
      result = _parse_csp_source("https://cdn.example.com")
      assert result == {
          "scheme": "https",
          "host": "cdn.example.com",
          "wildcard_subdomain": False,
          "path_prefix": None,
      }


  def test_parse_csp_source_scheme_host_and_path():
      result = _parse_csp_source("https://cdn.example.com/scripts/")
      assert result == {
          "scheme": "https",
          "host": "cdn.example.com",
          "wildcard_subdomain": False,
          "path_prefix": "/scripts/",
      }


  def test_parse_csp_source_bare_wildcard():
      result = _parse_csp_source("*")
      assert result == {
          "scheme": None,
          "host": "*",
          "wildcard_subdomain": False,
          "path_prefix": None,
      }


  def test_parse_csp_source_bare_scheme_returns_none():
      assert _parse_csp_source("https:") is None
      assert _parse_csp_source("data:") is None
      assert _parse_csp_source("blob:") is None


  def test_parse_csp_source_strips_port():
      result = _parse_csp_source("cdn.example.com:8443")
      assert result["host"] == "cdn.example.com"
  ```

- [ ] **Step 2: Run tests to verify they fail**

  ```bash
  pytest tests/unit/config_mgmt/test_csp_tester.py::test_parse_csp_source_bare_host \
         tests/unit/config_mgmt/test_csp_tester.py::test_parse_csp_source_wildcard_subdomain \
         tests/unit/config_mgmt/test_csp_tester.py::test_parse_csp_source_scheme_and_host \
         tests/unit/config_mgmt/test_csp_tester.py::test_parse_csp_source_scheme_host_and_path \
         tests/unit/config_mgmt/test_csp_tester.py::test_parse_csp_source_bare_wildcard \
         tests/unit/config_mgmt/test_csp_tester.py::test_parse_csp_source_bare_scheme_returns_none \
         tests/unit/config_mgmt/test_csp_tester.py::test_parse_csp_source_strips_port \
         -v
  ```
  Expected: `ImportError` — `_parse_csp_source` not yet defined.

- [ ] **Step 3: Add `_BARE_SCHEME_RE` constant and `_parse_csp_source` to csp_tester.py**

  Add the following immediately after the `_BYPASS_DB` line (after `_load_bypass_db` block):
  ```python
  _BARE_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+\-.]*:$")

  _CSP_KEYWORDS = frozenset({
      "'self'", "'unsafe-inline'", "'unsafe-eval'", "'none'",
      "'strict-dynamic'", "'wasm-unsafe-eval'", "'report-sample'",
  })

  _NONCE_HASH_RE = re.compile(r"^'(?:nonce-|sha(?:256|384|512)-)", re.IGNORECASE)


  def _parse_csp_source(token: str) -> dict | None:
      if _BARE_SCHEME_RE.match(token):
          return None

      scheme = None
      rest = token
      if "://" in token:
          scheme, rest = token.split("://", 1)

      path_prefix = None
      if "/" in rest:
          idx = rest.index("/")
          host_port = rest[:idx]
          path_prefix = rest[idx:]
      else:
          host_port = rest

      if host_port.count(":") == 1:
          host_port = host_port.rsplit(":", 1)[0]

      wildcard_subdomain = False
      if host_port.startswith("*."):
          wildcard_subdomain = True
          host_port = host_port[2:]

      host = host_port.strip()
      if not host:
          return None

      return {
          "scheme": scheme,
          "host": host,
          "wildcard_subdomain": wildcard_subdomain,
          "path_prefix": path_prefix,
      }
  ```

- [ ] **Step 4: Run tests to verify they pass**

  ```bash
  pytest tests/unit/config_mgmt/test_csp_tester.py::test_parse_csp_source_bare_host \
         tests/unit/config_mgmt/test_csp_tester.py::test_parse_csp_source_wildcard_subdomain \
         tests/unit/config_mgmt/test_csp_tester.py::test_parse_csp_source_scheme_and_host \
         tests/unit/config_mgmt/test_csp_tester.py::test_parse_csp_source_scheme_host_and_path \
         tests/unit/config_mgmt/test_csp_tester.py::test_parse_csp_source_bare_wildcard \
         tests/unit/config_mgmt/test_csp_tester.py::test_parse_csp_source_bare_scheme_returns_none \
         tests/unit/config_mgmt/test_csp_tester.py::test_parse_csp_source_strips_port \
         -v
  ```
  Expected: all 7 PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add workers/config_mgmt/tools/csp_tester.py \
          tests/unit/config_mgmt/test_csp_tester.py
  git commit -m "feat(config_mgmt): add _parse_csp_source helper (port of renniepak JS parseCSPSource)"
  ```

---

## Task 4: Add `_matches_csp_source` helper

**Files:**
- Modify: `workers/config_mgmt/tools/csp_tester.py`
- Test: `tests/unit/config_mgmt/test_csp_tester.py`

- [ ] **Step 1: Write failing tests**

  Append to `tests/unit/config_mgmt/test_csp_tester.py`:

  ```python
  from workers.config_mgmt.tools.csp_tester import _matches_csp_source


  def _src(host, *, scheme=None, wildcard_subdomain=False, path_prefix=None):
      """Helper to build a parsed CSP source dict."""
      return {
          "scheme": scheme,
          "host": host,
          "wildcard_subdomain": wildcard_subdomain,
          "path_prefix": path_prefix,
      }


  def test_matches_csp_source_exact_host_match():
      gadget_code = '<script src="https://ajax.googleapis.com/libs/jquery/2.1.4/jquery.min.js"></script>'
      assert _matches_csp_source("ajax.googleapis.com", gadget_code, _src("ajax.googleapis.com"))


  def test_matches_csp_source_exact_host_no_match():
      gadget_code = '<script src="https://cdn.example.com/x.js"></script>'
      assert not _matches_csp_source("cdn.example.com", gadget_code, _src("ajax.googleapis.com"))


  def test_matches_csp_source_wildcard_subdomain_matches():
      gadget_code = '<script src="https://ajax.googleapis.com/libs/jquery/2.1.4/jquery.min.js"></script>'
      assert _matches_csp_source(
          "ajax.googleapis.com", gadget_code,
          _src("googleapis.com", wildcard_subdomain=True),
      )


  def test_matches_csp_source_wildcard_subdomain_does_not_match_bare_domain():
      gadget_code = '<script src="https://googleapis.com/x.js"></script>'
      assert not _matches_csp_source(
          "googleapis.com", gadget_code,
          _src("googleapis.com", wildcard_subdomain=True),
      )


  def test_matches_csp_source_global_wildcard_matches_anything():
      gadget_code = '<script src="https://anything.example.com/x.js"></script>'
      assert _matches_csp_source("anything.example.com", gadget_code, _src("*"))


  def test_matches_csp_source_scheme_enforced_on_mismatch():
      gadget_code = '<script src="http://ajax.googleapis.com/x.js"></script>'
      assert not _matches_csp_source(
          "ajax.googleapis.com", gadget_code,
          _src("ajax.googleapis.com", scheme="https"),
      )


  def test_matches_csp_source_scheme_not_enforced_when_absent():
      gadget_code = '<script src="http://ajax.googleapis.com/x.js"></script>'
      assert _matches_csp_source(
          "ajax.googleapis.com", gadget_code,
          _src("ajax.googleapis.com", scheme=None),
      )


  def test_matches_csp_source_path_prefix_exact_match():
      gadget_code = '<script src="https://cdn.example.com/gtag/js"></script>'
      assert _matches_csp_source(
          "cdn.example.com", gadget_code,
          _src("cdn.example.com", path_prefix="/gtag/js"),
      )


  def test_matches_csp_source_path_prefix_subpath_match():
      gadget_code = '<script src="https://cdn.example.com/gtag/js/file.js"></script>'
      assert _matches_csp_source(
          "cdn.example.com", gadget_code,
          _src("cdn.example.com", path_prefix="/gtag/js"),
      )


  def test_matches_csp_source_path_prefix_segment_boundary_no_match():
      gadget_code = '<script src="https://cdn.example.com/gtag/jsloader"></script>'
      assert not _matches_csp_source(
          "cdn.example.com", gadget_code,
          _src("cdn.example.com", path_prefix="/gtag/js"),
      )


  def test_matches_csp_source_fallback_url_when_no_src_attr():
      # No src= attribute in code — falls back to https://{domain}
      assert _matches_csp_source("example.com", "", _src("example.com"))
  ```

- [ ] **Step 2: Run tests to verify they fail**

  ```bash
  pytest tests/unit/config_mgmt/test_csp_tester.py::test_matches_csp_source_exact_host_match \
         tests/unit/config_mgmt/test_csp_tester.py::test_matches_csp_source_exact_host_no_match \
         tests/unit/config_mgmt/test_csp_tester.py::test_matches_csp_source_wildcard_subdomain_matches \
         tests/unit/config_mgmt/test_csp_tester.py::test_matches_csp_source_wildcard_subdomain_does_not_match_bare_domain \
         tests/unit/config_mgmt/test_csp_tester.py::test_matches_csp_source_global_wildcard_matches_anything \
         tests/unit/config_mgmt/test_csp_tester.py::test_matches_csp_source_scheme_enforced_on_mismatch \
         tests/unit/config_mgmt/test_csp_tester.py::test_matches_csp_source_scheme_not_enforced_when_absent \
         tests/unit/config_mgmt/test_csp_tester.py::test_matches_csp_source_path_prefix_exact_match \
         tests/unit/config_mgmt/test_csp_tester.py::test_matches_csp_source_path_prefix_subpath_match \
         tests/unit/config_mgmt/test_csp_tester.py::test_matches_csp_source_path_prefix_segment_boundary_no_match \
         tests/unit/config_mgmt/test_csp_tester.py::test_matches_csp_source_fallback_url_when_no_src_attr \
         -v
  ```
  Expected: `ImportError` — `_matches_csp_source` not yet defined.

- [ ] **Step 3: Add `_URL_IN_CODE_RE` and `_matches_csp_source` to csp_tester.py**

  Add the following immediately after `_parse_csp_source`:
  ```python
  _URL_IN_CODE_RE = re.compile(r'(?:src|href)=["\']?([^"\'> ]+)', re.IGNORECASE)


  def _matches_csp_source(gadget_domain: str, gadget_code: str, src: dict) -> bool:
      url_match = _URL_IN_CODE_RE.search(gadget_code)
      gadget_url_str = url_match.group(1) if url_match else f"https://{gadget_domain}"

      try:
          parsed = urlparse(gadget_url_str)
          gadget_scheme = parsed.scheme or "https"
          gadget_host = (parsed.netloc or gadget_domain).split(":")[0].lower()
          gadget_path = parsed.path or "/"
      except Exception:
          return False

      if src["scheme"] and gadget_scheme != src["scheme"]:
          return False

      csp_host = src["host"]
      if csp_host == "*":
          pass
      elif src["wildcard_subdomain"]:
          if not gadget_host.endswith("." + csp_host):
              return False
      else:
          if gadget_host != csp_host:
              return False

      if src["path_prefix"]:
          prefix = src["path_prefix"].rstrip("/")
          if gadget_path != prefix and not gadget_path.startswith(prefix + "/"):
              return False

      return True
  ```

- [ ] **Step 4: Run tests to verify they pass**

  ```bash
  pytest tests/unit/config_mgmt/test_csp_tester.py::test_matches_csp_source_exact_host_match \
         tests/unit/config_mgmt/test_csp_tester.py::test_matches_csp_source_exact_host_no_match \
         tests/unit/config_mgmt/test_csp_tester.py::test_matches_csp_source_wildcard_subdomain_matches \
         tests/unit/config_mgmt/test_csp_tester.py::test_matches_csp_source_wildcard_subdomain_does_not_match_bare_domain \
         tests/unit/config_mgmt/test_csp_tester.py::test_matches_csp_source_global_wildcard_matches_anything \
         tests/unit/config_mgmt/test_csp_tester.py::test_matches_csp_source_scheme_enforced_on_mismatch \
         tests/unit/config_mgmt/test_csp_tester.py::test_matches_csp_source_scheme_not_enforced_when_absent \
         tests/unit/config_mgmt/test_csp_tester.py::test_matches_csp_source_path_prefix_exact_match \
         tests/unit/config_mgmt/test_csp_tester.py::test_matches_csp_source_path_prefix_subpath_match \
         tests/unit/config_mgmt/test_csp_tester.py::test_matches_csp_source_path_prefix_segment_boundary_no_match \
         tests/unit/config_mgmt/test_csp_tester.py::test_matches_csp_source_fallback_url_when_no_src_attr \
         -v
  ```
  Expected: all 11 PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add workers/config_mgmt/tools/csp_tester.py \
          tests/unit/config_mgmt/test_csp_tester.py
  git commit -m "feat(config_mgmt): add _matches_csp_source helper (port of renniepak JS matchesCspSource)"
  ```

---

## Task 5: Add `_match_csp_bypasses`, delete `_run_csp_bypass`, update call site

**Files:**
- Modify: `workers/config_mgmt/tools/csp_tester.py`
- Test: `tests/unit/config_mgmt/test_csp_tester.py`

- [ ] **Step 1: Write failing tests**

  Append to `tests/unit/config_mgmt/test_csp_tester.py`:

  ```python
  from workers.config_mgmt.tools.csp_tester import _match_csp_bypasses


  def test_match_csp_bypasses_empty_csp_returns_empty(monkeypatch):
      monkeypatch.setattr(csp_mod, "_BYPASS_DB", [("ajax.googleapis.com", "")])
      assert _match_csp_bypasses("", "https://target.com/") == []


  def test_match_csp_bypasses_empty_db_returns_empty(monkeypatch):
      monkeypatch.setattr(csp_mod, "_BYPASS_DB", [])
      results = _match_csp_bypasses(
          "script-src 'self' ajax.googleapis.com",
          "https://target.com/",
      )
      assert results == []


  def test_match_csp_bypasses_finds_exact_domain(monkeypatch):
      monkeypatch.setattr(csp_mod, "_BYPASS_DB", [
          ("ajax.googleapis.com", '<script src="https://ajax.googleapis.com/libs/jquery/2.1.4/jquery.min.js"></script>'),
          ("cdn.example.com", '<script src="https://cdn.example.com/x.js"></script>'),
      ])
      results = _match_csp_bypasses(
          "script-src 'self' ajax.googleapis.com",
          "https://target.com/",
      )
      assert len(results) == 1
      vuln = results[0]["vulnerability"]
      assert vuln["severity"] == "high"
      assert "ajax.googleapis.com" in vuln["name"]
      assert vuln["section_id"] == "WSTG-CONF-12"
      assert vuln["location"] == "https://target.com/"


  def test_match_csp_bypasses_no_match_for_unknown_domain(monkeypatch):
      monkeypatch.setattr(csp_mod, "_BYPASS_DB", [
          ("notinthepolicy.com", '<script src="https://notinthepolicy.com/x.js"></script>'),
      ])
      results = _match_csp_bypasses(
          "script-src 'self' ajax.googleapis.com",
          "https://target.com/",
      )
      assert results == []


  def test_match_csp_bypasses_keywords_filtered_out(monkeypatch):
      monkeypatch.setattr(csp_mod, "_BYPASS_DB", [
          ("self", ""),
          ("unsafe-inline", ""),
      ])
      results = _match_csp_bypasses(
          "script-src 'self' 'unsafe-inline'",
          "https://target.com/",
      )
      assert results == []


  def test_match_csp_bypasses_nonce_filtered_out(monkeypatch):
      monkeypatch.setattr(csp_mod, "_BYPASS_DB", [("nonce-abc123", "")])
      results = _match_csp_bypasses(
          "script-src 'nonce-abc123'",
          "https://target.com/",
      )
      assert results == []


  def test_match_csp_bypasses_wildcard_source_matches_subdomain(monkeypatch):
      monkeypatch.setattr(csp_mod, "_BYPASS_DB", [
          ("ajax.googleapis.com", '<script src="https://ajax.googleapis.com/x.js"></script>'),
      ])
      results = _match_csp_bypasses(
          "script-src 'self' *.googleapis.com",
          "https://target.com/",
      )
      assert len(results) == 1
      assert "ajax.googleapis.com" in results[0]["vulnerability"]["name"]


  def test_match_csp_bypasses_deduplicates_same_gadget(monkeypatch):
      monkeypatch.setattr(csp_mod, "_BYPASS_DB", [
          ("ajax.googleapis.com", '<script src="https://ajax.googleapis.com/x.js"></script>'),
      ])
      # Two sources in the policy that both match the same gadget
      results = _match_csp_bypasses(
          "script-src ajax.googleapis.com *.googleapis.com",
          "https://target.com/",
      )
      assert len(results) == 1


  def test_match_csp_bypasses_falls_back_to_default_src(monkeypatch):
      monkeypatch.setattr(csp_mod, "_BYPASS_DB", [
          ("ajax.googleapis.com", '<script src="https://ajax.googleapis.com/x.js"></script>'),
      ])
      results = _match_csp_bypasses(
          "default-src 'self' ajax.googleapis.com",
          "https://target.com/",
      )
      assert len(results) == 1
  ```

- [ ] **Step 2: Run tests to verify they fail**

  ```bash
  pytest tests/unit/config_mgmt/test_csp_tester.py::test_match_csp_bypasses_empty_csp_returns_empty \
         tests/unit/config_mgmt/test_csp_tester.py::test_match_csp_bypasses_empty_db_returns_empty \
         tests/unit/config_mgmt/test_csp_tester.py::test_match_csp_bypasses_finds_exact_domain \
         tests/unit/config_mgmt/test_csp_tester.py::test_match_csp_bypasses_no_match_for_unknown_domain \
         tests/unit/config_mgmt/test_csp_tester.py::test_match_csp_bypasses_keywords_filtered_out \
         tests/unit/config_mgmt/test_csp_tester.py::test_match_csp_bypasses_nonce_filtered_out \
         tests/unit/config_mgmt/test_csp_tester.py::test_match_csp_bypasses_wildcard_source_matches_subdomain \
         tests/unit/config_mgmt/test_csp_tester.py::test_match_csp_bypasses_deduplicates_same_gadget \
         tests/unit/config_mgmt/test_csp_tester.py::test_match_csp_bypasses_falls_back_to_default_src \
         -v
  ```
  Expected: `ImportError` — `_match_csp_bypasses` not yet defined.

- [ ] **Step 3: Add `_match_csp_bypasses` to csp_tester.py**

  Add the following immediately after `_matches_csp_source`, before the comment line `# ---------------------------------------------------------------------------`:

  ```python
  def _match_csp_bypasses(csp_header: str, url: str) -> list[dict]:
      if not _BYPASS_DB or not csp_header:
          return []

      policy = _parse_csp_header(csp_header)
      tokens = policy.get("script-src") or policy.get("default-src") or []
      source_tokens = [
          t for t in tokens
          if t not in _CSP_KEYWORDS and not _NONCE_HASH_RE.match(t)
      ]
      if not source_tokens:
          return []

      parsed_sources = [s for t in source_tokens if (s := _parse_csp_source(t)) is not None]
      if not parsed_sources:
          return []

      results: list[dict] = []
      seen: set[tuple[str, str]] = set()
      for domain, code in _BYPASS_DB:
          for src in parsed_sources:
              if _matches_csp_source(domain, code, src):
                  key = (domain, code)
                  if key not in seen:
                      seen.add(key)
                      results.append({"vulnerability": {
                          "name": f"CSP bypass gadget: {domain} on {url}",
                          "severity": "high",
                          "description": (
                              f"renniepak/CSPBypass: domain '{domain}' in script-src "
                              f"has a known bypass gadget on {url}. Payload: {code}"
                          ),
                          "location": url,
                          "section_id": _SECTION_ID,
                      }})
                  break

      return results
  ```

- [ ] **Step 4: Run tests to verify they pass**

  ```bash
  pytest tests/unit/config_mgmt/test_csp_tester.py::test_match_csp_bypasses_empty_csp_returns_empty \
         tests/unit/config_mgmt/test_csp_tester.py::test_match_csp_bypasses_empty_db_returns_empty \
         tests/unit/config_mgmt/test_csp_tester.py::test_match_csp_bypasses_finds_exact_domain \
         tests/unit/config_mgmt/test_csp_tester.py::test_match_csp_bypasses_no_match_for_unknown_domain \
         tests/unit/config_mgmt/test_csp_tester.py::test_match_csp_bypasses_keywords_filtered_out \
         tests/unit/config_mgmt/test_csp_tester.py::test_match_csp_bypasses_nonce_filtered_out \
         tests/unit/config_mgmt/test_csp_tester.py::test_match_csp_bypasses_wildcard_source_matches_subdomain \
         tests/unit/config_mgmt/test_csp_tester.py::test_match_csp_bypasses_deduplicates_same_gadget \
         tests/unit/config_mgmt/test_csp_tester.py::test_match_csp_bypasses_falls_back_to_default_src \
         -v
  ```
  Expected: all 9 PASS.

- [ ] **Step 5: Delete `_run_csp_bypass` from csp_tester.py**

  Remove the entire function `_run_csp_bypass` (lines 272–304 in the original file — the block starting with the comment `# cspbypass helper` through the closing `return results`):

  ```python
  # ---------------------------------------------------------------------------
  # cspbypass helper
  # ---------------------------------------------------------------------------

  async def _run_csp_bypass(url: str) -> list[dict]:
      """Invoke cspbypass CLI against url; map each bypass line to a high vuln."""
      try:
          proc = await asyncio.create_subprocess_exec(
              "cspbypass", url,
              stdout=asyncio.subprocess.PIPE,
              stderr=asyncio.subprocess.PIPE,
          )
          try:
              stdout_bytes, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
          except asyncio.TimeoutError:
              proc.kill()
              await proc.communicate()
              logger.warning(f"cspbypass timed out for {url}")
              return []
          stdout = stdout_bytes.decode("utf-8", errors="replace").strip()
      except FileNotFoundError:
          logger.error("cspbypass binary not found — skipping Layer 3")
          return []

      results: list[dict] = []
      for line in stdout.splitlines():
          line = line.strip()
          if not line or line.startswith("#"):
              continue
          results.append({"vulnerability": {
              "name": f"CSP bypass technique: {line[:80]}",
              "severity": "high",
              "description": f"cspbypass detected a bypass technique on {url}: {line}",
              "location": url,
              "section_id": _SECTION_ID,
          }})
      return results
  ```

- [ ] **Step 6: Update the call site in `_probe_url`**

  In `_probe_url`, replace:
  ```python
          results.extend(await _run_csp_bypass(url))
  ```
  with:
  ```python
          results.extend(_match_csp_bypasses(csp_header, url))
  ```

- [ ] **Step 7: Run the full test file to confirm nothing broke**

  ```bash
  pytest tests/unit/config_mgmt/test_csp_tester.py -v
  ```
  Expected: all tests PASS.

- [ ] **Step 8: Commit**

  ```bash
  git add workers/config_mgmt/tools/csp_tester.py \
          tests/unit/config_mgmt/test_csp_tester.py
  git commit -m "feat(config_mgmt): replace _run_csp_bypass subprocess with in-process _match_csp_bypasses"
  ```

---

## Task 6: Final verification

- [ ] **Step 1: Run the full config_mgmt unit suite**

  ```bash
  pytest tests/unit/config_mgmt/ -v
  ```
  Expected: all tests PASS, no import errors, no warnings about missing symbols.

- [ ] **Step 2: Verify no stray cspbypass references remain**

  ```bash
  grep -r "cspbypass\|_run_csp_bypass" \
       workers/config_mgmt/ \
       docker/Dockerfile.config_mgmt \
       tests/unit/config_mgmt/
  ```
  Expected: zero matches.

- [ ] **Step 3: Commit (if Step 2 found anything to fix)**

  Only needed if Step 2 found leftover references:
  ```bash
  git add -p
  git commit -m "chore(config_mgmt): remove stray cspbypass references"
  ```
