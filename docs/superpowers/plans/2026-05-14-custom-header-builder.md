# Custom HTTP Header Builder Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a custom HTTP request header builder (key/value pairs) to ScopeBuilder Step 1, stored as `target_profile.custom_headers`.

**Architecture:** New `CustomHeaderBuilder` component mirrors `RateLimitBuilder` exactly — same row-list + add/delete pattern, same Tailwind classes, same prop shape. ScopeBuilder holds `CustomHeader[]` state, serializes to `Record<string, string>` on submit (skipping blank keys), and shows the header count in the Step 4 Execution review card.

**Tech Stack:** Next.js 16, React 19, TypeScript, Tailwind v4, Lucide icons, Playwright e2e

---

## File Map

| Action | Path | Responsibility |
|--------|------|---------------|
| Create | `dashboard/src/components/common/CustomHeaderBuilder.tsx` | Reusable key/value row builder |
| Modify | `dashboard/src/components/campaign/ScopeBuilder.tsx` | State, render, serialize, review |
| Modify | `dashboard/e2e/tests/create-campaign.spec.ts` | e2e coverage for custom headers |

---

## Task 1: Write the failing e2e test

**Files:**
- Modify: `dashboard/e2e/tests/create-campaign.spec.ts`

- [ ] **Step 1: Add the test** — append inside the existing `test.describe("Create Campaign", ...)` block, after the last test

```typescript
test("custom headers: add a header in step 1 and see count in review", async ({ page }) => {
  await page.goto("/campaign");
  await expect(page.getByTestId("scope-builder")).toBeVisible();

  // Step 0: fill required fields
  await page.getByTestId("scope-company-input").fill("HeaderTest Corp");
  await page.getByTestId("scope-domain-input").fill("headertest.example.com");
  await page.getByTestId("scope-next-btn").click();

  // Step 1: add a custom header
  await expect(page.getByTestId("scope-step-1")).toBeVisible();
  await expect(page.getByTestId("header-add-btn")).toBeVisible();
  await page.getByTestId("header-add-btn").click();
  await page.getByTestId("header-key-0").fill("Authorization");
  await page.getByTestId("header-value-0").fill("Bearer e2e-token");
  await page.getByTestId("scope-next-btn").click();

  // Step 2: Playbook
  await expect(page.getByTestId("scope-step-2")).toBeVisible();
  await page.getByTestId("scope-next-btn").click();

  // Step 3: Workflow
  await expect(page.getByTestId("scope-step-3")).toBeVisible();
  await page.getByTestId("scope-next-btn").click();

  // Step 4: Review — header count must appear
  await expect(page.getByTestId("scope-step-4")).toBeVisible();
  await expect(page.getByTestId("review-custom-headers-count")).toHaveText("1");
});
```

- [ ] **Step 2: Run it to confirm it fails**

```bash
cd dashboard && npm run test:e2e -- --project=chromium -g "custom headers"
```

Expected: **FAIL** — `Locator.toBeVisible: Error: locator("header-add-btn") not found`

---

## Task 2: Create `CustomHeaderBuilder` component

**Files:**
- Create: `dashboard/src/components/common/CustomHeaderBuilder.tsx`

- [ ] **Step 1: Create the file**

```tsx
"use client";

import { Plus, Trash2 } from "lucide-react";

export interface CustomHeader {
  key: string;
  value: string;
}

interface Props {
  headers: CustomHeader[];
  onChange: (headers: CustomHeader[]) => void;
  label?: string;
}

export default function CustomHeaderBuilder({
  headers,
  onChange,
  label = "Custom Request Headers",
}: Props) {
  function addHeader() {
    onChange([...headers, { key: "", value: "" }]);
  }

  function removeHeader(index: number) {
    onChange(headers.filter((_, i) => i !== index));
  }

  function updateHeader(index: number, field: keyof CustomHeader, value: string) {
    const updated = headers.map((h, i) =>
      i === index ? { ...h, [field]: value } : h,
    );
    onChange(updated);
  }

  return (
    <div className="space-y-2">
      <label className="section-label block">{label}</label>

      {headers.map((header, i) => (
        <div key={i} className="flex items-center gap-2">
          <input
            data-testid={`header-key-${i}`}
            type="text"
            value={header.key}
            onChange={(e) => updateHeader(i, "key", e.target.value)}
            placeholder="Header-Name"
            className="w-36 rounded border border-border bg-bg-tertiary px-2 py-1.5 text-xs font-mono text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
          />
          <span className="text-xs text-text-muted">:</span>
          <input
            data-testid={`header-value-${i}`}
            type="text"
            value={header.value}
            onChange={(e) => updateHeader(i, "value", e.target.value)}
            placeholder="value"
            className="flex-1 rounded border border-border bg-bg-tertiary px-2 py-1.5 text-xs font-mono text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
          />
          <button
            type="button"
            data-testid={`header-remove-${i}`}
            onClick={() => removeHeader(i)}
            className="text-text-muted hover:text-red-400"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>
      ))}

      <button
        data-testid="header-add-btn"
        type="button"
        onClick={addHeader}
        className="flex items-center gap-1 text-xs text-accent hover:underline"
      >
        <Plus className="h-3 w-3" /> Add header
      </button>
    </div>
  );
}
```

---

## Task 3: Wire `CustomHeaderBuilder` into `ScopeBuilder`

**Files:**
- Modify: `dashboard/src/components/campaign/ScopeBuilder.tsx:1-793`

- [ ] **Step 1: Add import** — after the existing `RateLimitBuilder` import (line 26)

```tsx
import CustomHeaderBuilder, { type CustomHeader } from "@/components/common/CustomHeaderBuilder";
```

- [ ] **Step 2: Add state** — in the Step 1 state block, after `const [outScopeDomains, setOutScopeDomains] = useState("")` (line 106)

```tsx
const [customHeaders, setCustomHeaders] = useState<CustomHeader[]>([]);
```

- [ ] **Step 3: Render in Step 1** — add this block immediately after the closing `</div>` of the existing `<RateLimitBuilder>` wrapper (line 615, inside the `space-y-4` div of Step 1)

```tsx
<div className="border-t border-border pt-4">
  <CustomHeaderBuilder
    headers={customHeaders}
    onChange={setCustomHeaders}
  />
</div>
```

The existing RateLimitBuilder block (lines 609–615) stays unchanged:

```tsx
<div className="border-t border-border pt-4">
  <RateLimitBuilder
    rules={rateLimitRules}
    onChange={setRateLimitRules}
    label="Campaign Rate Limits"
  />
</div>
```

- [ ] **Step 4: Update `handleSubmit`** — replace the existing `target_profile` object inside `handleSubmit` (lines 208–218) with:

```tsx
const headersRecord = customHeaders
  .filter((h) => h.key.trim() !== "")
  .reduce<Record<string, string>>((acc, h) => {
    acc[h.key.trim()] = h.value;
    return acc;
  }, {});

const payload: CreateTargetPayload = {
  company_name: companyName.trim(),
  base_domain: baseDomain.trim(),
  playbook,
  target_profile: {
    in_scope_domains: lines(inScopeDomains),
    out_scope_domains: lines(outScopeDomains),
    in_scope_cidrs: lines(inScopeCidrs),
    in_scope_regex: lines(inScopeRegex),
    rate_limits: rateLimitRules,
    ...(Object.keys(headersRecord).length > 0 && { custom_headers: headersRecord }),
  },
};
```

- [ ] **Step 5: Add header count to the Execution review card** — in Step 4's Execution card (after the Rate limits row, around line 737), add:

```tsx
{customHeaders.filter((h) => h.key.trim() !== "").length > 0 && (
  <div className="flex items-center justify-between">
    <span className="text-xs text-text-muted">Custom headers</span>
    <span
      data-testid="review-custom-headers-count"
      className="font-mono text-xs text-neon-blue"
    >
      {customHeaders.filter((h) => h.key.trim() !== "").length}
    </span>
  </div>
)}
```

- [ ] **Step 6: Run the e2e test**

```bash
cd dashboard && npm run test:e2e -- --project=chromium -g "custom headers"
```

Expected: **PASS**

- [ ] **Step 7: Commit**

```bash
git add dashboard/src/components/common/CustomHeaderBuilder.tsx dashboard/src/components/campaign/ScopeBuilder.tsx dashboard/e2e/tests/create-campaign.spec.ts
git commit -m "feat(campaign): add custom HTTP request header builder to ScopeBuilder Step 1"
```
