import ScopeBuilder from "@/components/campaign/ScopeBuilder";

export default function CampaignPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">
          New Campaign
        </h1>
        <p className="mt-1 text-sm text-text-secondary">
          Configure target, scope, playbook, and workflow — then launch.
        </p>
      </div>
      <ScopeBuilder />
    </div>
  );
}
