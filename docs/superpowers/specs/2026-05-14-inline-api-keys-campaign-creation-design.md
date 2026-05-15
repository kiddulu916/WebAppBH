# Inline API Key Configuration in Campaign Creation

**Date:** 2026-05-14  
**Status:** Approved  
**File affected:** `dashboard/src/components/campaign/ScopeBuilder.tsx`

## Problem

Step 0 ("Target Intel") of the campaign creation wizard shows Intel Enrichment status badges but links to `/settings` for key management. Navigating away breaks the wizard flow and loses unsaved wizard state.

## Solution

Replace the `<a href="/settings">` link with a toggle-and-save inline form, identical in shape to `ApiKeysSection` in `settings/page.tsx`. No new files or components needed.

## State additions (all local to `ScopeBuilder`)

| State | Type | Purpose |
|---|---|---|
| `editingKeys` | `boolean` | Whether the inline form is open |
| `savingKeys` | `boolean` | Disables Save button during request |
| `shodanKey` | `string` | Input value for Shodan API Key |
| `stKey` | `string` | Input value for SecurityTrails API Key |
| `censysId` | `string` | Input value for Censys Organization ID |
| `censysSecret` | `string` | Input value for Censys API Key |
| `showShodan` / `showST` / `showCensysId` / `showCensysSecret` | `boolean` | Eye-toggle visibility per field |

## UI layout (Step 0 Intel Enrichment section)

```
┌─ Intel Enrichment ──────────────── [Configure ▾] ─┐
│ shodan: configured   securitytrails: not set        │
│ censys: not set                                     │
│                                                     │
│  ▼ (when editingKeys = true)                        │
│  Shodan API Key          [•••••••••••••] [👁]       │
│  SecurityTrails API Key  [•••••••••••••] [👁]       │
│  Censys Organization ID  [•••••••••••••] [👁]       │
│  Censys API Key          [•••••••••••••] [👁]       │
│                          [Cancel] [Save Keys]       │
└─────────────────────────────────────────────────────┘
```

- Placeholder text: `"Leave blank to keep current"` (matches settings page)
- "Configure" button toggles to `editingKeys = true`; collapses on Save or Cancel
- Cancel clears all four input values and sets `editingKeys = false`

## Save flow

1. Build `payload` — only include non-blank trimmed values (same logic as `ApiKeysSection.handleSave`)
2. Call `api.updateApiKeys(payload)`
3. On success: call `api.getApiKeyStatus()` and update `apiKeyStatus`, clear inputs, set `editingKeys = false`
4. On error: toast shown by `api.request()` internally; `editingKeys` stays open so user can retry

## Imports needed

Add to existing imports: `Eye`, `EyeOff` from `lucide-react` (already available in the project).

## Out of scope

- No changes to settings page, orchestrator, or `intel_enrichment.py`
- No new components or files
- No changes to other wizard steps
