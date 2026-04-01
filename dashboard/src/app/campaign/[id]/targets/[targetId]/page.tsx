"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import PipelineGrid from "@/components/pipeline/PipelineGrid";
import WorkerDetailDrawer from "@/components/pipeline/WorkerDetailDrawer";
import { usePipelineStore } from "@/stores/pipelineStore";
import type { TargetNode, WorkerState } from "@/types/campaign";
import { WORKER_STAGE_COUNTS } from "@/types/campaign";

const WSTG_STAGES: Record<string, { id: string; name: string; sectionId: string }[]> = {
  info_gathering: [
    { id: "1", name: "Search Engine Discovery", sectionId: "WSTG-INFO-01" },
    { id: "2", name: "Fingerprint Web Server", sectionId: "WSTG-INFO-02" },
    { id: "3", name: "Review Webserver Metafiles", sectionId: "WSTG-INFO-03" },
    { id: "4", name: "Enumerate Applications", sectionId: "WSTG-INFO-04" },
    { id: "5", name: "Application Discovery", sectionId: "WSTG-INFO-05" },
    { id: "6", name: "Fingerprint Web App", sectionId: "WSTG-INFO-06" },
    { id: "7", name: "Identify Entry Points", sectionId: "WSTG-INFO-07" },
    { id: "8", name: "Map Application", sectionId: "WSTG-INFO-08" },
    { id: "9", name: "Identify Technologies", sectionId: "WSTG-INFO-09" },
    { id: "10", name: "Map Attack Surface", sectionId: "WSTG-INFO-10" },
  ],
  config_mgmt: [
    { id: "1", name: "Default Credentials", sectionId: "WSTG-CONF-01" },
    { id: "2", name: "HTTP Methods", sectionId: "WSTG-CONF-02" },
    { id: "3", name: "HTTP Strict Transport Security", sectionId: "WSTG-CONF-03" },
    { id: "4", name: "Cross Domain Policy", sectionId: "WSTG-CONF-04" },
    { id: "5", name: "File Extensions", sectionId: "WSTG-CONF-05" },
    { id: "6", name: "HTTP Headers", sectionId: "WSTG-CONF-06" },
    { id: "7", name: "Content Security Policy", sectionId: "WSTG-CONF-07" },
    { id: "8", name: "Cookie Attributes", sectionId: "WSTG-CONF-08" },
    { id: "9", name: "Cache Control", sectionId: "WSTG-CONF-09" },
    { id: "10", name: "HTTP Methods Override", sectionId: "WSTG-CONF-10" },
    { id: "11", name: "Exposed API Documentation", sectionId: "WSTG-CONF-11" },
  ],
  identity_mgmt: [
    { id: "1", name: "User Registration", sectionId: "WSTG-IDNT-01" },
    { id: "2", name: "User Enumeration", sectionId: "WSTG-IDNT-02" },
    { id: "3", name: "Guessable User Account", sectionId: "WSTG-IDNT-03" },
    { id: "4", name: "Brute Force", sectionId: "WSTG-IDNT-04" },
    { id: "5", name: "Weak Password Policy", sectionId: "WSTG-IDNT-05" },
  ],
  authentication: [
    { id: "1", name: "Credentials Transported over Unencrypted Channel", sectionId: "WSTG-ATHN-01" },
    { id: "2", name: "Default Credentials", sectionId: "WSTG-ATHN-02" },
    { id: "3", name: "Weak Lock Out Mechanism", sectionId: "WSTG-ATHN-03" },
    { id: "4", name: "Authentication Bypass", sectionId: "WSTG-ATHN-04" },
    { id: "5", name: "Vulnerable Remember Password", sectionId: "WSTG-ATHN-05" },
    { id: "6", name: "Browser Cache Weaknesses", sectionId: "WSTG-ATHN-06" },
    { id: "7", name: "Weak Password Policy", sectionId: "WSTG-ATHN-07" },
    { id: "8", name: "Weak Cryptography", sectionId: "WSTG-ATHN-08" },
    { id: "9", name: "Weak Login Function", sectionId: "WSTG-ATHN-09" },
    { id: "10", name: "Multi-Factor Authentication", sectionId: "WSTG-ATHN-10" },
  ],
  authorization: [
    { id: "1", name: "Directory Traversal", sectionId: "WSTG-ATHZ-01" },
    { id: "2", name: "Bypass Authorization Schema", sectionId: "WSTG-ATHZ-02" },
    { id: "3", name: "Privilege Escalation", sectionId: "WSTG-ATHZ-03" },
    { id: "4", name: "Insecure Direct Object Reference", sectionId: "WSTG-ATHZ-04" },
  ],
  session_mgmt: [
    { id: "1", name: "Session Management Schema", sectionId: "WSTG-SESS-01" },
    { id: "2", name: "Cookie Attributes", sectionId: "WSTG-SESS-02" },
    { id: "3", name: "Session Fixation", sectionId: "WSTG-SESS-03" },
    { id: "4", name: "Exposed Session Variable", sectionId: "WSTG-SESS-04" },
    { id: "5", name: "Cross Site Request Forgery", sectionId: "WSTG-SESS-05" },
    { id: "6", name: "Logout Functionality", sectionId: "WSTG-SESS-06" },
    { id: "7", name: "Session Timeout", sectionId: "WSTG-SESS-07" },
    { id: "8", name: "Session Puzzle", sectionId: "WSTG-SESS-08" },
    { id: "9", name: "Session Hijacking", sectionId: "WSTG-SESS-09" },
  ],
  input_validation: [
    { id: "1", name: "Reflected Cross Site Scripting", sectionId: "WSTG-INPV-01" },
    { id: "2", name: "Stored Cross Site Scripting", sectionId: "WSTG-INPV-02" },
    { id: "3", name: "HTTP Verb Tampering", sectionId: "WSTG-INPV-03" },
    { id: "4", name: "SQL Injection", sectionId: "WSTG-INPV-04" },
    { id: "5", name: "LDAP Injection", sectionId: "WSTG-INPV-05" },
    { id: "6", name: "ORM Injection", sectionId: "WSTG-INPV-06" },
    { id: "7", name: "XML Injection", sectionId: "WSTG-INPV-07" },
    { id: "8", name: "SSI Injection", sectionId: "WSTG-INPV-08" },
    { id: "9", name: "XPath Injection", sectionId: "WSTG-INPV-09" },
    { id: "10", name: "IMAP/SMTP Injection", sectionId: "WSTG-INPV-10" },
    { id: "11", name: "Code Injection", sectionId: "WSTG-INPV-11" },
    { id: "12", name: "Command Injection", sectionId: "WSTG-INPV-12" },
    { id: "13", name: "Buffer Overflow", sectionId: "WSTG-INPV-13" },
    { id: "14", name: "Incubated Vulnerability", sectionId: "WSTG-INPV-14" },
    { id: "15", name: "Server-Side Request Forgery", sectionId: "WSTG-INPV-15" },
  ],
  error_handling: [
    { id: "1", name: "Improper Error Handling", sectionId: "WSTG-ERRH-01" },
    { id: "2", name: "Stack Trace", sectionId: "WSTG-ERRH-02" },
  ],
  cryptography: [
    { id: "1", name: "Weak Transport Layer Security", sectionId: "WSTG-CRYP-01" },
    { id: "2", name: "Padding Oracle", sectionId: "WSTG-CRYP-02" },
    { id: "3", name: "Sensitive Information Sent via Unencrypted Channels", sectionId: "WSTG-CRYP-03" },
    { id: "4", name: "Weak Encryption", sectionId: "WSTG-CRYP-04" },
  ],
  business_logic: [
    { id: "1", name: "Test Business Logic Data Validation", sectionId: "WSTG-BUSL-01" },
    { id: "2", name: "Test Ability to Forge Requests", sectionId: "WSTG-BUSL-02" },
    { id: "3", name: "Test Integrity Checks", sectionId: "WSTG-BUSL-03" },
    { id: "4", name: "Test for Process Timing", sectionId: "WSTG-BUSL-04" },
    { id: "5", name: "Test Number of Times a Function Can Be Used", sectionId: "WSTG-BUSL-05" },
    { id: "6", name: "Testing for the Circumvention of Work Flows", sectionId: "WSTG-BUSL-06" },
    { id: "7", name: "Test Defenses against Application Misuse", sectionId: "WSTG-BUSL-07" },
    { id: "8", name: "Test Upload of Unexpected File Types", sectionId: "WSTG-BUSL-08" },
    { id: "9", name: "Test Upload of Malicious Files", sectionId: "WSTG-BUSL-09" },
  ],
  client_side: [
    { id: "1", name: "Cross Site Scripting", sectionId: "WSTG-CLNT-01" },
    { id: "2", name: "HTML Injection", sectionId: "WSTG-CLNT-02" },
    { id: "3", name: "Client-Side URL Redirect", sectionId: "WSTG-CLNT-03" },
    { id: "4", name: "CSS Injection", sectionId: "WSTG-CLNT-04" },
    { id: "5", name: "Client-Side Resource Manipulation", sectionId: "WSTG-CLNT-05" },
    { id: "6", name: "Cross Origin Resource Sharing", sectionId: "WSTG-CLNT-06" },
    { id: "7", name: "Cross Frame Scripting", sectionId: "WSTG-CLNT-07" },
    { id: "8", name: "Clickjacking", sectionId: "WSTG-CLNT-08" },
    { id: "9", name: "Web Messaging", sectionId: "WSTG-CLNT-09" },
    { id: "10", name: "Web Storage", sectionId: "WSTG-CLNT-10" },
    { id: "11", name: "Cross Site Script Inclusion", sectionId: "WSTG-CLNT-11" },
    { id: "12", name: "DOM-Based XSS", sectionId: "WSTG-CLNT-12" },
    { id: "13", name: "WebSocket Security", sectionId: "WSTG-CLNT-13" },
  ],
  chain_worker: [
    { id: "1", name: "Chain Discovery", sectionId: "CHAIN-01" },
    { id: "2", name: "Chain Evaluation", sectionId: "CHAIN-02" },
    { id: "3", name: "Chain Execution", sectionId: "CHAIN-03" },
    { id: "4", name: "Chain Reporting", sectionId: "CHAIN-04" },
  ],
  reporting: [
    { id: "1", name: "Generate Reports", sectionId: "RPT-01" },
  ],
};

export default function ChildTargetPage() {
  const params = useParams();
  const campaignId = params.id as string;
  const targetId = params.targetId as string;
  const [target, setTarget] = useState<TargetNode | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedWorker, setSelectedWorker] = useState<string | null>(null);
  const workerStates = usePipelineStore((s) => s.workerStates);

  useEffect(() => {
    const fetchTarget = async () => {
      try {
        const res = await fetch(`/api/campaigns/${campaignId}/targets/${targetId}`);
        if (res.ok) {
          const data = await res.json();
          setTarget(data);
        }
      } catch {
        // ignore
      } finally {
        setLoading(false);
      }
    };
    fetchTarget();
  }, [campaignId, targetId]);

  const workerStatesWithTotals = Object.entries(workerStates).reduce((acc, [key, value]) => {
    acc[key] = {
      ...value,
      total_stages: WORKER_STAGE_COUNTS[key] || 0,
    };
    return acc;
  }, {} as Record<string, WorkerState & { total_stages: number }>);

  if (loading) {
    return <div className="flex items-center justify-center h-64 text-text-secondary">Loading...</div>;
  }

  return (
    <div className="space-y-6">
      {target && (
        <div>
          <h1 className="text-2xl font-bold text-text-primary">{target.domain}</h1>
          <p className="text-sm text-text-secondary mt-1">
            {target.target_type} | Priority: P:{target.priority} | {target.vulnerability_count} vulnerabilities
          </p>
        </div>
      )}

      <div className="rounded-lg border border-border p-6 bg-bg-surface">
        <h2 className="text-lg font-semibold text-text-primary mb-4">Pipeline Progress</h2>
        <PipelineGrid
          workerStates={workerStatesWithTotals}
          onWorkerClick={setSelectedWorker}
        />
      </div>

      {selectedWorker && (
        <WorkerDetailDrawer
          worker={selectedWorker}
          state={workerStates[selectedWorker] || { status: "pending" }}
          stages={WSTG_STAGES[selectedWorker] || []}
          findingCount={0}
          onClose={() => setSelectedWorker(null)}
        />
      )}
    </div>
  );
}
