# Custom HTTP Header Builder — ScopeBuilder Step 1

**Date:** 2026-05-14  
**Status:** Approved

## Summary

Add a custom HTTP request header UI to Step 1 (Scope Rules) of the ScopeBuilder wizard. Headers are stored as `target_profile.custom_headers: Record<string, string>` — a field that already exists in both the TypeScript `TargetProfile` interface and the backend schema.

## New Component: `CustomHeaderBuilder`

**File:** `dashboard/src/components/common/CustomHeaderBuilder.tsx`

Mirrors the existing `RateLimitBuilder` pattern:

- **Props:** `headers: Array<{key: string; value: string}>`, `onChange: (headers: Array<{key: string; value: string}>) => void`, `label?: string`
- **Rows:** key `<input>` + value `<input>` (both monospace, `text-xs font-mono`) + `<Trash2>` delete button
- **Footer:** "Add header" link (matching `RateLimitBuilder`'s "Add rule" style)
- **Initial state:** empty array — headers are optional, no default row
- No validation beyond trimming on submit; empty-key rows are dropped at serialize time

## ScopeBuilder Changes

**File:** `dashboard/src/components/campaign/ScopeBuilder.tsx`

1. Add state: `const [customHeaders, setCustomHeaders] = useState<Array<{key: string; value: string}>>([])` in the Step 1 block.
2. Import and render `<CustomHeaderBuilder>` in Step 1, below `<RateLimitBuilder>`, separated by a `border-t border-border pt-4` divider.
3. Serialize on submit — convert `customHeaders` array to `Record<string, string>` (skip rows where `key.trim()` is empty) and assign to `target_profile.custom_headers`.

## Review Step (Step 4)

Add a row to the **Execution** card:

```
Custom headers   |   2    ← text-neon-blue, font-mono
```

Only rendered when `customHeaders.length > 0`. Sits below the Rate limits row.

## Data Flow

```
ScopeBuilder state: Array<{key, value}>
        ↓ serialize (filter empty keys, reduce to Record)
CreateTargetPayload.target_profile.custom_headers: Record<string, string>
        ↓ POST /api/v1/targets
Backend stores in target_profile JSONB column
```

## Out of Scope

- No server-side validation changes needed (the field is already accepted).
- No e2e test changes in this pass (headers are purely additive to the payload).
- No masking/redacting of header values in the UI (values are visible plain text).
