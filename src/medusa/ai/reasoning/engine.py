"""AI Reasoning Engine — post-processes static findings with Claude.

Orchestrates the full reasoning pipeline:
1. Chunk findings by token budget
2. Send each chunk (with snapshot) to Claude
3. Parse and merge partial results
4. Return a unified ReasoningResult
"""

from __future__ import annotations

import logging
import time

from medusa.ai.client import AiClient
from medusa.ai.reasoning.chunker import chunk_findings_for_reasoning
from medusa.ai.reasoning.models import ReasoningResult
from medusa.ai.reasoning.prompts import (
    build_reasoning_system_prompt,
    build_reasoning_user_payload,
)
from medusa.ai.reasoning.response_parser import parse_reasoning_response
from medusa.core.check import ServerSnapshot
from medusa.core.models import Finding, Status

logger = logging.getLogger(__name__)


class ReasoningEngine:
    """Orchestrates AI reasoning over static scan findings.

    Receives a ServerSnapshot and its static findings, sends them
    to Claude in 1-3 API calls (chunked by token budget), and
    returns a unified ReasoningResult.
    """

    def __init__(
        self,
        client: AiClient,
        max_input_tokens: int = 100_000,
        max_output_tokens: int = 8_192,
    ) -> None:
        self.client = client
        self.max_input_tokens = max_input_tokens
        self.max_output_tokens = max_output_tokens

    async def reason(
        self,
        snapshot: ServerSnapshot,
        findings: list[Finding],
    ) -> ReasoningResult:
        """Run AI reasoning over the snapshot and its static findings.

        Parameters
        ----------
        snapshot:
            The immutable server snapshot.
        findings:
            All findings from the static scan (PASS + FAIL + ERROR).

        Returns
        -------
        A ReasoningResult with annotations, attack chains, gap
        findings, and executive summary.
        """
        start = time.monotonic()

        fail_count = sum(
            1 for f in findings if f.status == Status.FAIL
        )

        # If there are no FAIL findings, return a minimal result
        if fail_count == 0:
            duration = time.monotonic() - start
            return ReasoningResult(
                server_name=snapshot.server_name,
                reasoning_model="skipped",
                reasoning_duration_seconds=round(duration, 2),
                executive_summary=(
                    f"Server '{snapshot.server_name}' passed all "
                    f"{len(findings)} static checks with no findings. "
                    f"No AI reasoning needed."
                ),
            )

        # Chunk findings by token budget
        chunks = chunk_findings_for_reasoning(
            snapshot=snapshot,
            findings=findings,
            max_tokens_per_chunk=self.max_input_tokens,
        )

        logger.info(
            "AI reasoning for '%s': %d FAIL findings in %d chunk(s)",
            snapshot.server_name,
            fail_count,
            len(chunks),
        )

        # Process each chunk
        all_annotations = []
        all_chains = []
        all_gaps = []
        executive_summaries = []
        risk_narratives = []
        all_priorities = []
        total_tokens: dict[str, int] = {
            "input_tokens": 0,
            "output_tokens": 0,
        }

        for i, chunk in enumerate(chunks):
            chunk_fail_count = sum(
                1 for f in chunk if f.status == Status.FAIL
            )
            system_prompt = build_reasoning_system_prompt(
                num_findings=chunk_fail_count,
                chunk_index=i,
                total_chunks=len(chunks),
            )
            user_payload = build_reasoning_user_payload(
                snapshot=snapshot,
                findings=chunk,
            )

            try:
                logger.info(
                    "Sending reasoning chunk %d/%d for '%s' "
                    "(%d findings)",
                    i + 1,
                    len(chunks),
                    snapshot.server_name,
                    chunk_fail_count,
                )
                response = await self.client.analyze(
                    system_prompt, user_payload
                )

                # Extract token usage if available
                usage = response.get("usage", {})
                if usage:
                    total_tokens["input_tokens"] += usage.get(
                        "input_tokens", 0
                    )
                    total_tokens["output_tokens"] += usage.get(
                        "output_tokens", 0
                    )

                partial = parse_reasoning_response(
                    response, snapshot.server_name
                )
                all_annotations.extend(partial.annotations)
                all_chains.extend(partial.attack_chains)
                all_gaps.extend(partial.gap_findings)
                if partial.executive_summary:
                    executive_summaries.append(
                        partial.executive_summary
                    )
                if partial.risk_narrative:
                    risk_narratives.append(partial.risk_narrative)
                if partial.top_priorities:
                    all_priorities.extend(partial.top_priorities)

            except Exception:
                logger.exception(
                    "AI reasoning chunk %d/%d failed for '%s'",
                    i + 1,
                    len(chunks),
                    snapshot.server_name,
                )

        duration = time.monotonic() - start

        # Merge results from all chunks
        return ReasoningResult(
            server_name=snapshot.server_name,
            reasoning_model="claude-sonnet-4-20250514",
            reasoning_duration_seconds=round(duration, 2),
            token_usage=total_tokens,
            annotations=all_annotations,
            attack_chains=all_chains,
            gap_findings=all_gaps,
            executive_summary=(
                executive_summaries[0]
                if executive_summaries
                else "AI reasoning completed with no summary."
            ),
            risk_narrative=(
                risk_narratives[0]
                if risk_narratives
                else ""
            ),
            top_priorities=_dedupe_priorities(all_priorities)[:10],
        )


def _dedupe_priorities(priorities: list[str]) -> list[str]:
    """Remove duplicate priorities while preserving order."""
    seen: set[str] = set()
    result: list[str] = []
    for p in priorities:
        normalized = p.lower().strip()
        if normalized not in seen:
            seen.add(normalized)
            result.append(p)
    return result
