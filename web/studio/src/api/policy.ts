import { createDecisionRun } from "./scenarios";
import type { DecisionRun, ScenarioId } from "../types";

export interface StudioPolicy {
  version: string;
  enforcementMode: "enforce" | "monitor" | "shadow";
  defaultAction: "allow" | "require_confirmation" | "block";
  guardedToolGroups: string[];
  latticeDimensions: string[];
  humanGate: {
    requireFor: string[];
    timeoutSeconds: number;
  };
  networkScope: {
    allowInternalDomains: string[];
    blockExternalByDefault: boolean;
  };
  dataScope: {
    privateDataClasses: string[];
    blockExternalTransfer: boolean;
  };
}

const fallbackPolicy: StudioPolicy = {
  version: "studio-demo-v1",
  enforcementMode: "enforce",
  defaultAction: "require_confirmation",
  guardedToolGroups: ["external_communication", "money_transfer", "booking", "file_sharing", "command_execution"],
  latticeDimensions: ["action", "intent", "provenance", "sensitivity", "destination", "history", "confirmation"],
  humanGate: {
    requireFor: ["booking_target_changed", "ambiguous_destination"],
    timeoutSeconds: 90
  },
  networkScope: {
    allowInternalDomains: ["corp.local", "localhost", "127.0.0.1"],
    blockExternalByDefault: true
  },
  dataScope: {
    privateDataClasses: ["tokens", "account_recovery", "credentials", "roadmap", "local_env"],
    blockExternalTransfer: true
  }
};

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("agentbrakeFusionToken") || "agentbrake-fusion-local";
  return { Authorization: `Bearer ${token}` };
}

export async function fetchPolicy(): Promise<StudioPolicy> {
  try {
    const response = await fetch("/api/policy", { headers: authHeaders() });
    if (!response.ok) throw new Error("policy endpoint unavailable");
    const payload = await response.json();
    return payload.policy as StudioPolicy;
  } catch {
    return fallbackPolicy;
  }
}

export async function savePolicy(policy: StudioPolicy): Promise<StudioPolicy> {
  try {
    const response = await fetch("/api/policy", {
      method: "PUT",
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ policy })
    });
    if (!response.ok) throw new Error("policy save unavailable");
    const payload = await response.json();
    return payload.policy as StudioPolicy;
  } catch {
    return policy;
  }
}

export async function dryRunPolicy(scenarioId: ScenarioId = "workspace"): Promise<DecisionRun> {
  try {
    const response = await fetch("/api/policy/dry-run", {
      method: "POST",
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ scenarioId })
    });
    if (!response.ok) throw new Error("policy dry run unavailable");
    const payload = await response.json();
    return payload.run as DecisionRun;
  } catch {
    return createDecisionRun(scenarioId);
  }
}

export async function exportPolicy(): Promise<string> {
  try {
    const response = await fetch("/api/policy/export", { headers: authHeaders() });
    if (!response.ok) throw new Error("policy export unavailable");
    return JSON.stringify(await response.json(), null, 2);
  } catch {
    return JSON.stringify({ exportedAt: new Date().toISOString(), policy: fallbackPolicy }, null, 2);
  }
}
