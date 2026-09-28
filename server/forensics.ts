export type PriorityInput = {
  anomaly: number;
  behaviorChange: number;
  networkCorrelation: number;
  graphSignificance: number;
  temporalPattern: number;
  behavioralSimilarity: number;
};

export type PriorityResult = { score: number; level: "LOW" | "MEDIUM" | "HIGH" };

export function computeInvestigationPriority(input: PriorityInput): PriorityResult {
  const values = Object.values(input);
  const score = Number((values.reduce((total, value) => total + Math.max(0, Math.min(1, value)), 0) / values.length).toFixed(2));
  return { score, level: score >= 0.75 ? "HIGH" : score >= 0.48 ? "MEDIUM" : "LOW" };
}

export function simulateRemovalMetrics(entityId: string, affectedTransactions: number, affectedWallets: number) {
  const bridge = entityId.toLowerCase().includes("bridge");
  return {
    connectionsAffected: bridge ? 7 : Math.max(1, affectedTransactions),
    transactionsAffected: affectedTransactions,
    walletsAffected: affectedWallets,
    fundFlowPathsAffected: Math.max(1, Math.floor(affectedTransactions / 2)),
    alternativePaths: bridge ? 3 : Math.max(1, Math.floor(affectedWallets / 2)),
    originalGraphUnchanged: true,
  };
}
