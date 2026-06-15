export interface AttackNode {
  id: string;
  vulnId: string;
  title: string;
  severity: string;
}

export interface AttackEdge {
  from: string;
  to: string;
  relationship: string; // e.g., "Enables", "Escalates to"
}

export interface AttackGraph {
  nodes: AttackNode[];
  edges: AttackEdge[];
}

export interface AttackChain {
  id: string;
  steps: AttackNode[];
  mitreTactics: string[];
  businessImpact: string;
  riskScore: number;
}
