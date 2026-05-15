# Inline API Key Configuration in Campaign Creation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the "Manage API keys in Settings" link in the ScopeBuilder Step 0 Intel Enrichment section with an inline toggle-and-save form so users never leave the campaign creation wizard.

**Architecture:** All changes are confined to `ScopeBuilder.tsx`. New local state handles the editing toggle, per-field values, password visibility, and saving indicator. A new `handleSaveKeys` function calls `api.updateApiKeys` then re-fetches `api.getApiKeyStatus` to update the status badges in place.

**Tech Stack:** React 19, Next.js 16, Lucide icons, Sonner toasts (handled by `api.request` internally), Playwright for e2e tests.

---

### Task 1: Write a failing e2e test for the inline form

**Files:**
- Modify: `dashboard/e2e/tests/create-campaign.spec.ts`

- [ ] **Step 1: Add the test case**

  Open `dashboard/e2e/tests/create-campaign.spec.ts` and append a second `test` block inside the existing `test.describe("Create Campaign", ...)` block, after the existing test:

  ```typescript
  test("intel enrichment: configure button expands inline form; cancel collapses it", async ({ page }) => {
    await page.goto("/campaign");
    await expect(page.getByTestId("scope-builder")).toBeVisible();

    // Settings link must be gone
    await expect(page.getByRole("link", { name: "Settings" })).not.toBeVisible();

    // Configure button must exist
    const configureBtn = page.getByTestId("intel-configure-btn");
    await expect(configureBtn).toBeVisible();

    // Expand the form
    await configureBtn.click();
    await expect(page.getByTestId("intel-shodan-input")).toBeVisible();
    await expect(page.getByTestId("intel-st-input")).toBeVisible();
    await expect(page.getByTestId("intel-censys-id-input")).toBeVisible();
    await expect(page.getByTestId("intel-censys-secret-input")).toBeVisible();
    await expect(page.getByTestId("intel-save-btn")).toBeVisible();
    await expect(page.getByTestId("intel-cancel-btn")).toBeVisible();

    // Cancel collapses the form
    await page.getByTestId("intel-cancel-btn").click();
    await expect(page.getByTestId("intel-shodan-input")).not.toBeVisible();
    await expect(configureBtn).toBeVisible();
  });
  ```

- [ ] **Step 2: Run the test to confirm it fails**

  ```bash
  cd dashboard && npx playwright test e2e/tests/create-campaign.spec.ts --grep "intel enrichment" --reporter=line
  ```

  Expected: FAIL — `intel-configure-btn` not found (element doesn't exist yet).

---

### Task 2: Implement the inline API key form in ScopeBuilder

**Files:**
- Modify: `dashboard/src/components/campaign/ScopeBuilder.tsx`

- [ ] **Step 1: Add `Eye` and `EyeOff` to the lucide-react import**

  Find the existing import block at the top of `ScopeBuilder.tsx`:

  ```typescript
  import {
    ChevronRight,
    ChevronLeft,
    Loader2,
    Crosshair,
    Shield,
    BookOpen,
    Layers,
    Rocket,
    Check,
  } from "lucide-react";
  ```

  Replace it with:

  ```typescript
  import {
    ChevronRight,
    ChevronLeft,
    Loader2,
    Crosshair,
    Shield,
    BookOpen,
    Layers,
    Rocket,
    Check,
    Eye,
    EyeOff,
  } from "lucide-react";
  ```

- [ ] **Step 2: Add the new state variables**

  Inside the `ScopeBuilder` component, directly after the existing `apiKeyStatus` state block (around line 83), add:

  ```typescript
  /* ---- Inline API key editor ---- */
  const [editingKeys, setEditingKeys] = useState(false);
  const [savingKeys, setSavingKeys] = useState(false);
  const [shodanKey, setShodanKey] = useState("");
  const [stKey, setStKey] = useState("");
  const [censysId, setCensysId] = useState("");
  const [censysSecret, setCensysSecret] = useState("");
  const [showShodan, setShowShodan] = useState(false);
  const [showST, setShowST] = useState(false);
  const [showCensysId, setShowCensysId] = useState(false);
  const [showCensysSecret, setShowCensysSecret] = useState(false);
  ```

- [ ] **Step 3: Add the save and cancel handlers**

  Directly after the new state block, add:

  ```typescript
  async function handleSaveKeys() {
    setSavingKeys(true);
    try {
      const payload: Record<string, string> = {};
      if (shodanKey.trim()) payload.shodan_api_key = shodanKey.trim();
      if (stKey.trim()) payload.securitytrails_api_key = stKey.trim();
      if (censysId.trim()) payload.censys_api_id = censysId.trim();
      if (censysSecret.trim()) payload.censys_api_secret = censysSecret.trim();
      const res = await api.updateApiKeys(payload);
      setApiKeyStatus(res.keys ?? {});
      setEditingKeys(false);
      setShodanKey("");
      setStKey("");
      setCensysId("");
      setCensysSecret("");
    } catch {
      // toast shown by api.request()
    } finally {
      setSavingKeys(false);
    }
  }

  function handleCancelKeys() {
    setEditingKeys(false);
    setShodanKey("");
    setStKey("");
    setCensysId("");
    setCensysSecret("");
  }
  ```

- [ ] **Step 4: Replace the Intel Enrichment UI block in Step 0**

  Locate the existing Intel Enrichment block (around line 313–338 in the original file):

  ```tsx
  {/* ---- Intel Enrichment Status (keys managed in Settings) ---- */}
  <div className="rounded-md border border-border bg-bg-tertiary p-3 space-y-3">
    <span className="section-label">Intel Enrichment</span>
    <p className="text-xs text-text-muted">
      Passive OSINT enrichment. Manage API keys in{" "}
      <a href="/settings" className="text-accent hover:underline">
        Settings
      </a>
      .
    </p>

    <div className="flex flex-wrap gap-2">
      {Object.entries(apiKeyStatus).map(([key, configured]) => (
        <span
          key={key}
          className={`rounded-full px-2 py-0.5 text-xs font-mono ${
            configured
              ? "bg-neon-green/15 text-neon-green"
              : "bg-bg-surface text-text-muted"
          }`}
        >
          {key}: {configured ? "configured" : "not set"}
        </span>
      ))}
    </div>
  </div>
  ```

  Replace it entirely with:

  ```tsx
  {/* ---- Intel Enrichment (inline key configuration) ---- */}
  <div className="rounded-md border border-border bg-bg-tertiary p-3 space-y-3">
    <div className="flex items-center justify-between">
      <span className="section-label">Intel Enrichment</span>
      {!editingKeys && (
        <button
          data-testid="intel-configure-btn"
          type="button"
          onClick={() => setEditingKeys(true)}
          className="text-xs text-accent hover:underline"
        >
          Configure
        </button>
      )}
    </div>

    <div className="flex flex-wrap gap-2">
      {Object.entries(apiKeyStatus).map(([key, configured]) => (
        <span
          key={key}
          className={`rounded-full px-2 py-0.5 text-xs font-mono ${
            configured
              ? "bg-neon-green/15 text-neon-green"
              : "bg-bg-surface text-text-muted"
          }`}
        >
          {key}: {configured ? "configured" : "not set"}
        </span>
      ))}
    </div>

    {editingKeys && (
      <div className="space-y-3 border-t border-border pt-3">
        {/* Shodan */}
        <div className="space-y-1">
          <label className="text-xs font-medium text-text-secondary">Shodan API Key</label>
          <div className="relative">
            <input
              data-testid="intel-shodan-input"
              type={showShodan ? "text" : "password"}
              value={shodanKey}
              onChange={(e) => setShodanKey(e.target.value)}
              placeholder="Leave blank to keep current"
              className="w-full rounded border border-border bg-bg-surface px-2 py-1.5 pr-8 text-xs font-mono text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
            />
            <button
              type="button"
              onClick={() => setShowShodan(!showShodan)}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-secondary"
            >
              {showShodan ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
            </button>
          </div>
        </div>

        {/* SecurityTrails */}
        <div className="space-y-1">
          <label className="text-xs font-medium text-text-secondary">SecurityTrails API Key</label>
          <div className="relative">
            <input
              data-testid="intel-st-input"
              type={showST ? "text" : "password"}
              value={stKey}
              onChange={(e) => setStKey(e.target.value)}
              placeholder="Leave blank to keep current"
              className="w-full rounded border border-border bg-bg-surface px-2 py-1.5 pr-8 text-xs font-mono text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
            />
            <button
              type="button"
              onClick={() => setShowST(!showST)}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-secondary"
            >
              {showST ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
            </button>
          </div>
        </div>

        {/* Censys Organization ID */}
        <div className="space-y-1">
          <label className="text-xs font-medium text-text-secondary">Censys Organization ID</label>
          <div className="relative">
            <input
              data-testid="intel-censys-id-input"
              type={showCensysId ? "text" : "password"}
              value={censysId}
              onChange={(e) => setCensysId(e.target.value)}
              placeholder="Leave blank to keep current"
              className="w-full rounded border border-border bg-bg-surface px-2 py-1.5 pr-8 text-xs font-mono text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
            />
            <button
              type="button"
              onClick={() => setShowCensysId(!showCensysId)}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-secondary"
            >
              {showCensysId ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
            </button>
          </div>
        </div>

        {/* Censys API Key */}
        <div className="space-y-1">
          <label className="text-xs font-medium text-text-secondary">Censys API Key</label>
          <div className="relative">
            <input
              data-testid="intel-censys-secret-input"
              type={showCensysSecret ? "text" : "password"}
              value={censysSecret}
              onChange={(e) => setCensysSecret(e.target.value)}
              placeholder="Leave blank to keep current"
              className="w-full rounded border border-border bg-bg-surface px-2 py-1.5 pr-8 text-xs font-mono text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
            />
            <button
              type="button"
              onClick={() => setShowCensysSecret(!showCensysSecret)}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-secondary"
            >
              {showCensysSecret ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
            </button>
          </div>
        </div>

        {/* Actions */}
        <div className="flex justify-end gap-2 pt-1">
          <button
            data-testid="intel-cancel-btn"
            type="button"
            onClick={handleCancelKeys}
            className="rounded px-3 py-1.5 text-xs text-text-muted hover:bg-bg-surface"
          >
            Cancel
          </button>
          <button
            data-testid="intel-save-btn"
            type="button"
            onClick={handleSaveKeys}
            disabled={savingKeys}
            className="rounded-md bg-accent px-4 py-1.5 text-xs font-medium text-white transition-colors hover:bg-accent/90 disabled:opacity-50"
          >
            {savingKeys ? "Saving..." : "Save Keys"}
          </button>
        </div>
      </div>
    )}
  </div>
  ```

- [ ] **Step 5: Run TypeScript check**

  ```bash
  cd dashboard && npx tsc --noEmit
  ```

  Expected: no errors.

- [ ] **Step 6: Commit**

  ```bash
  git add dashboard/src/components/campaign/ScopeBuilder.tsx dashboard/e2e/tests/create-campaign.spec.ts
  git commit -m "feat(campaign): inline API key configuration in ScopeBuilder Step 0"
  ```

---

### Task 3: Verify the e2e test passes

**Files:**
- Test: `dashboard/e2e/tests/create-campaign.spec.ts`

- [ ] **Step 1: Run the new test**

  ```bash
  cd dashboard && npx playwright test e2e/tests/create-campaign.spec.ts --grep "intel enrichment" --reporter=line
  ```

  Expected: PASS — configure button visible, form expands, cancel collapses.

- [ ] **Step 2: Run the full create-campaign spec to guard against regressions**

  ```bash
  cd dashboard && npx playwright test e2e/tests/create-campaign.spec.ts --reporter=line
  ```

  Expected: both tests PASS.
