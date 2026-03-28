const uid = () =>
  Date.now().toString(36) + Math.random().toString(36).slice(2, 6);

export const factories = {
  target: (overrides: Record<string, unknown> = {}) => ({
    company_name: `E2E-Corp-${uid()}`,
    base_domain: `e2e-${uid()}.example.com`,
    target_profile: {
      in_scope_domains: [],
      custom_headers: {},
      rate_limits: { pps: 10 },
    },
    playbook: "wide_recon",
    ...overrides,
  }),

  bounty: (
    targetId: number,
    vulnId: number,
    overrides: Record<string, unknown> = {},
  ) => ({
    target_id: targetId,
    vulnerability_id: vulnId,
    platform: "hackerone",
    expected_payout: 500,
    ...overrides,
  }),

  schedule: (targetId: number, overrides: Record<string, unknown> = {}) => ({
    target_id: targetId,
    cron_expression: `${Math.floor(Math.random() * 60)} 0 * * *`,
    playbook: "wide_recon",
    ...overrides,
  }),
};
