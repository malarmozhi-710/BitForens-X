import { describe, expect, it } from "vitest";
import { computeInvestigationPriority, simulateRemovalMetrics } from "./forensics";

describe("forensic prioritization", () => {
  it("combines the six evidence factors into a bounded priority level", () => {
    expect(computeInvestigationPriority({
      anomaly: 0.92,
      behaviorChange: 0.88,
      networkCorrelation: 0.79,
      graphSignificance: 0.82,
      temporalPattern: 0.86,
      behavioralSimilarity: 0.91,
    })).toEqual({ score: 0.86, level: "HIGH" });

    expect(computeInvestigationPriority({
      anomaly: 0.2,
      behaviorChange: 0.2,
      networkCorrelation: 0.3,
      graphSignificance: 0.25,
      temporalPattern: 0.15,
      behavioralSimilarity: 0.25,
    }).level).toBe("LOW");
  });

  it("returns reconstruction metrics without mutating the original graph", () => {
    const result = simulateRemovalMetrics("bc1q-bridge-alpha", 8, 5);
    expect(result).toMatchObject({
      connectionsAffected: 7,
      transactionsAffected: 8,
      walletsAffected: 5,
      fundFlowPathsAffected: 4,
      alternativePaths: 3,
      originalGraphUnchanged: true,
    });
  });
});
