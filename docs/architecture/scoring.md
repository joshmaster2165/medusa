# Scoring Algorithm

Medusa produces a security score for each server and an aggregate score across all servers.

## Score Calculation

### Per-Server Score

```
Score = 10.0 - (weighted_deductions / max_possible_deduction) × 10.0
```

Clamped to `[0.0, 10.0]`.

### Severity Weights

| Severity | Weight | Impact |
|----------|--------|--------|
| Critical | 10.0 | Maximum deduction per finding |
| High | 7.0 | Significant deduction |
| Medium | 4.0 | Moderate deduction |
| Low | 1.5 | Minor deduction |
| Info | 0.0 | No deduction |

### Example

A server with 100 checks where 2 fail:
- 1 critical finding (weight: 10.0)
- 1 medium finding (weight: 4.0)
- Total deductions: 14.0
- Max possible: 10.0 × 100 = 1000.0
- Score: 10.0 - (14.0 / 1000.0) × 10.0 = **9.86**

## Letter Grades

| Score Range | Grade |
|-------------|-------|
| 9.0 - 10.0 | **A** |
| 7.0 - 8.9  | **B** |
| 5.0 - 6.9  | **C** |
| 3.0 - 4.9  | **D** |
| 0.0 - 2.9  | **F** |

## Aggregate Score

The aggregate score across all servers uses a weighted average:

```
Aggregate = Σ(server_score × checks_run) / Σ(checks_run)
```

Servers with more checks have proportionally more influence on the aggregate.

## What Counts

| Status | Counted? | Effect |
|--------|----------|--------|
| FAIL | Yes | Deducts based on severity weight |
| PASS | No | No deduction (contributes to max possible) |
| ERROR | No | Not counted in scoring |
| SKIPPED | No | Not counted in scoring |

## Improving Your Score

1. **Fix critical findings first** — they have 6.7× the impact of high findings
2. **Address high findings** — they have 1.75× the impact of medium
3. **Use `--reason`** — AI may identify false positives that are inflating deductions
4. **Suppress accepted risks** — use baselines to track suppressed findings
