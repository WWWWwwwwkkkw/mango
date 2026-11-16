"""
Send per-sink JSON reports to an LLM and collect integer overflow judgments.

This script expects reports produced by integer_overflow_detection with
`-results <dir>`, namely `sink_<n>.json` files containing decompiled code.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple


LOG = logging.getLogger(__name__)

DEFAULT_API_URL = "xxx"
DEFAULT_MODEL = "xxx"
DEFAULT_API_TOKEN = "xxx"
SINK_FILENAME_RE = re.compile(r"^sink_(\d+)\.json$")


@dataclass
class SinkInput:
    index: int
    path: str
    payload: Dict[str, Any]


def _list_sink_files(results_dir: str) -> List[Tuple[int, str]]:
    items: List[Tuple[int, str]] = []
    for name in os.listdir(results_dir):
        match = SINK_FILENAME_RE.match(name)
        if not match:
            continue
        index = int(match.group(1))
        items.append((index, os.path.join(results_dir, name)))
    items.sort(key=lambda entry: entry[0])
    return items


def _load_sink(path: str, index: int) -> SinkInput:
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return SinkInput(index=index, path=path, payload=payload)


def _format_decompiled_sources(sources: Iterable[Dict[str, Any]]) -> str:
    blocks = []
    for source in sources:
        name = source.get("name") or "unknown"
        addr = source.get("address") or "unknown"
        code = source.get("code") or ""
        blocks.append(f"[Function {name} @ {addr}]\n{code}".strip())
    return "\n\n".join(blocks)


def _format_disassembly_context(entries: Iterable[Dict[str, Any]]) -> str:
    lines = []
    for entry in entries:
        addr = entry.get("address") or "unknown"
        text = entry.get("text") or ""
        prefix = "=> " if entry.get("is_sink") else "   "
        lines.append(f"{prefix}{addr}: {text}".rstrip())
    return "\n".join(lines) if lines else "unavailable"


def _build_start_prompt(sink: SinkInput) -> str:
    """Build START phase prompt: initialize JSON state for the sink."""
    payload = sink.payload
    sink_address = payload.get("sink_address") or "unknown"
    sink_function = payload.get("sink_function") or "unknown"
    instruction = payload.get("instruction") or "unknown"
    disassembly_context = payload.get("disassembly_context") or []
    disassembly_text = _format_disassembly_context(disassembly_context)
    
    case_id = f"sink_{sink.index}_{sink_address}"
    
    return (
        "You are a security program analyst for firmware binaries.\n"
        "Input is decompiled C-like code; types may be missing or wrong.\n\n"
        "Scope: ONLY CWE-190 integer overflow/wraparound for ONE arithmetic sink.\n"
        "Do not invent missing code/types. If uncertain, record it as \"unknown\" and add an assumption.\n"
        "Do not assume a parameter is attacker-controlled unless there is concrete input-propagation evidence.\n"
        "Use exact enum tokens required by schema fields; do not invent alternatives.\n"
        "Output MUST be valid JSON only.\n\n"
        f"Target arithmetic sink (the only target in this case):\n"
        f"- sink_site: {sink_address}\n"
        f"- sink_expr: {instruction}\n"
        f"- sink_semantic: unknown (to be determined)\n\n"
        "Disassembly context (around sink):\n"
        f"{disassembly_text}\n\n"
        "Task:\n"
        "Initialize a JSON state for this sink:\n"
        "- Create operands O1, O2, ... from sink_expr operands\n"
        "- Register sink_expr as the primary critical_arith entry\n"
        "- Set width/signed/range as unknown unless directly evident from sink_expr\n"
        "- In notes, classify sink pattern as scalar_arith | pointer_offset | unknown (best effort)\n"
        "Do NOT decide vulnerability yet.\n\n"
        "Output JSON schema:\n"
        "{\n"
        "  \"meta\": {\n"
        f"    \"case_id\": \"{case_id}\",\n"
        "    \"step_index\": -1,\n"
        f"    \"sink\": {{\"site\": \"{sink_address}\", \"function\": \"{sink_function}\", \"expr\": \"{instruction}\", \"semantic\": \"unknown\"}},\n"
        f"    \"dedup_key\": \"{sink_address}::{instruction}\"\n"
        "  },\n"
        "  \"state\": {\n"
        "    \"sink_operands\": [\n"
        "      {\n"
        "        \"name\": \"O1\",\n"
        "        \"expr\": \"...\",\n"
        "        \"width_bits\": \"8|16|32|64|unknown\",\n"
        "        \"signed\": \"signed|unsigned|unknown\",\n"
        "        \"range\": \"unknown or [min,max]\",\n"
        "        \"origin_candidates\": [],\n"
        "        \"untrusted_influence\": \"yes|no|unknown\",\n"
        "        \"influence_evidence\": [],\n"
        "        \"constraints\": [],\n"
        "        \"sanitizers_or_checks\": []\n"
        "      }\n"
        "    ],\n"
        "    \"critical_arith\": [\n"
        "      {\n"
        "        \"id\": \"A0\",\n"
        f"        \"site\": \"{sink_address}\",\n"
        f"        \"expr\": \"{instruction}\",\n"
        "        \"op\": \"add|sub|mul|shl|cast|neg|abs|other\",\n"
        "        \"operands\": [\"O1\",\"O2\"],\n"
        "        \"width_bits\": \"8|16|32|64|unknown\",\n"
        "        \"signed\": \"signed|unsigned|unknown\",\n"
        "        \"guards_relevant\": [],\n"
        "        \"semantic\": \"add_sub|mul|shl|neg_abs|cast_trunc|other\",\n"
        "        \"risk_hint\": \"\"\n"
        "      }\n"
        "    ],\n"
        "    \"guards\": [],\n"
        "    \"call_links\": [],\n"
        "    \"assumptions\": [],\n"
        "    \"notes\": []\n"
        "  }\n"
        "}\n"
    )


def _build_step_prompt(sink: SinkInput, previous_state: Dict[str, Any], func_code: str, func_name: str, step_index: int) -> str:
    """Build STEP phase prompt: update state based on one function block."""
    case_id = previous_state.get("meta", {}).get("case_id", f"sink_{sink.index}")
    
    return (
        "You are a security program analyst for firmware binaries.\n"
        "Scope: ONLY CWE-190 for the sink defined in meta.sink. Output JSON only.\n\n"
        "Context:\n"
        f"- case_id: {case_id}\n"
        f"- step_index: {step_index}\n"
        f"- function_name: {func_name}\n\n"
        f"Immutable target: function={sink.payload.get('sink_function')}, "
        f"site={sink.payload.get('sink_address')}, instruction={sink.payload.get('instruction')}\n"
        f"This snippet is the target function: {func_name == sink.payload.get('sink_function')}\n"
        "A similar expression in another function is NOT the target sink. "
        "Non-target functions provide calling/dataflow context only. "
        "Do not attach their local variables or guards to A0 without an explicit call/parameter mapping. "
        "Preserve meta.sink and A0 identity; if instruction-to-code mapping is ambiguous, record unknown.\n"
        "Target assembly context:\n"
        f"{_format_disassembly_context(sink.payload.get('disassembly_context') or [])}\n\n"
        "Previous JSON (paste exactly):\n"
        f"{json.dumps(previous_state, indent=2)}\n\n"
        "Code snippet:\n"
        f"{func_code}\n\n"
        "Task: Update state to explain sink_expr feasibility.\n"
        "Update only what helps determine overflow:\n"
        "1) Refine O1/O2/... origins and expressions (params/returns/globals/fields/constants).\n"
        "2) Refine width_bits/signed/range. If inferred, add brief evidence into constraints or notes.\n"
        "3) Decide whether each operand may be influenced by untrusted input:\n"
        "   - yes/no/unknown + influence_evidence\n"
        "4) Record guards/checks/casts/masks that constrain operands:\n"
        "   - add to guards with dominates_sink = yes/no/unknown\n"
        "5) If you find upstream arithmetic that defines operands, add it to critical_arith with a new id (A1, A2, ...).\n"
        "6) If you can map caller expression to callee parameter, add a call_links entry.\n\n"
        "7) For base+constant address computations, distinguish pointer field-offset access vs true numeric arithmetic.\n\n"
        "Rules:\n"
        "- Do not invent behavior of missing functions; use unknown + assumptions.\n"
        "- Track only what affects the arithmetic sink itself: operand def-use, width/signedness, explicit casts/truncation, masks, and explicit guards (comparisons/clamps).\n"
        "- For signed, use ONLY: signed|unsigned|unknown (never yes/no).\n"
        "- Do not set untrusted_influence=yes only because value comes from a function parameter.\n"
        "- For pointer-like operands, do not default range to [0, UINT_MAX] without concrete evidence.\n"
        "- If sink is likely field-address computation (base + small constant offset used for load/store/address), record that in notes and avoid claiming overflow without boundary-feasibility evidence.\n"
        "- Do NOT output a final verdict yet.\n\n"
        "Return JSON only, same schema, updated meta.step_index.\n"
    )


def _build_final_prompt(final_state: Dict[str, Any]) -> str:
    """Build FINAL phase prompt: make verdict based on accumulated state."""
    case_id = final_state.get("meta", {}).get("case_id", "unknown")
    
    return (
        "You are a security program analyst for firmware binaries.\n"
        "Scope: ONLY CWE-190. Output JSON only.\n\n"
        "Final accumulated JSON:\n"
        f"{json.dumps(final_state, indent=2)}\n\n"
        "Decide if the target sink_expr can cause integer overflow/wraparound.\n\n"
        "Decision policy:\n"
        "- verdict=\"yes\" only if there is a concrete feasible overflow path at this sink (with evidence on operand width/signedness/range/dataflow), OR explicitly justified missing fact that still leaves a realistic overflow path.\n"
        "- verdict=\"no\" if overflow is ruled out by clear constraints/guards, OR sink is only benign field-address computation (base+constant offset) with no evidence of near-boundary base values or dangerous casts/truncation.\n"
        "- verdict=\"unknown\" if key facts are missing and neither yes nor no is conservatively justified.\n\n"
        "Additional constraints:\n"
        "- Do NOT output verdict=\"yes\" solely because an operand \"may be untrusted\".\n"
        "- Do NOT output verdict=\"yes\" solely because a pointer could theoretically be near address-space max without concrete feasibility evidence.\n"
        "- If verdict is \"no\" or \"unknown\", set vulnerable_ops to an empty list.\n"
        "- confidence: high only with strong direct evidence; med with limited assumptions; low when key facts are missing.\n\n"
        "Output JSON:\n"
        "{\n"
        "  \"cwe\": \"CWE-190\",\n"
        f"  \"case_id\": \"{case_id}\",\n"
        "  \"verdict\": \"yes|no|unknown\",\n"
        "  \"vulnerable_ops\": [\n"
        "    {\n"
        "      \"arith_id\": \"A0\",\n"
        "      \"site\": \"...\",\n"
        "      \"expr\": \"...\",\n"
        "      \"width_bits\": \"...\",\n"
        "      \"signed\": \"...\",\n"
        "      \"why\": \"...\",\n"
        "      \"required_assumptions\": [\"...\"]\n"
        "    }\n"
        "  ],\n"
        "  \"operands_summary\": [\n"
        "    {\"operand\":\"O1\",\"untrusted_influence\":\"yes|no|unknown\",\"range\":\"...\",\"constraints_used\":[\"...\"]}\n"
        "  ],\n"
        "  \"guards_assessment\": [\n"
        "    {\"guard_id\":\"G1\",\"dominates_sink\":\"yes|no|unknown\",\"sufficient\":\"yes|no|unknown\",\"reason\":\"...\"}\n"
        "  ],\n"
        "  \"assumptions\": [\"...\"],\n"
        "  \"patch_suggestions\": [\n"
        "    \"checked add/mul before use\",\n"
        "    \"bounds check against MAX before arithmetic\",\n"
        "    \"use wider type then validate before truncation\",\n"
        "    \"avoid signed/unsigned mixing; normalize types before arithmetic\"\n"
        "  ],\n"
        "  \"dedup_key\": \"(copy meta.dedup_key)\",\n"
        "  \"confidence\": \"high|med|low\"\n"
        "}\n"
    )


def _post_json(url: str, payload: Dict[str, Any], token: str, timeout: int) -> Dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read()
    return json.loads(raw.decode("utf-8"))


def _extract_message_content(response_json: Dict[str, Any]) -> str:
    if "choices" in response_json and response_json["choices"]:
        choice = response_json["choices"][0]
        if isinstance(choice, dict):
            message = choice.get("message", {})
            if isinstance(message, dict) and "content" in message:
                return str(message["content"])
            if "text" in choice:
                return str(choice["text"])
    if "content" in response_json:
        return str(response_json["content"])
    return json.dumps(response_json)


def _parse_json_from_text(text: str) -> Optional[Dict[str, Any]]:
    decoder = json.JSONDecoder()
    for idx, ch in enumerate(text):
        if ch != "{":
            continue
        try:
            parsed, _ = decoder.raw_decode(text[idx:])
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            continue
    return None


def _request_llm(
    prompt: str,
    *,
    api_url: str,
    api_token: str,
    model: str,
    timeout: int,
) -> Tuple[str, Optional[Dict[str, Any]]]:
    """Send a prompt to LLM and return response text and parsed JSON."""
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a careful static analysis assistant."},
            {"role": "user", "content": prompt},
        ],
    }
    response = _post_json(api_url, payload, api_token, timeout)
    content = _extract_message_content(response)
    parsed = _parse_json_from_text(content)
    return content, parsed


def _analyze_sink_three_phase(
    sink: SinkInput,
    *,
    api_url: str,
    api_token: str,
    model: str,
    timeout: int,
) -> Dict[str, Any]:
    """Execute three-phase state machine: START -> STEP(s) -> FINAL."""
    
    # Phase 1: START - Initialize state
    LOG.info("  Phase START: Initializing state for sink_%d", sink.index)
    start_prompt = _build_start_prompt(sink)
    start_content, start_state = _request_llm(
        start_prompt,
        api_url=api_url,
        api_token=api_token,
        model=model,
        timeout=timeout,
    )
    
    if not start_state:
        raise ValueError(f"Failed to parse START state for sink_{sink.index}")
    
    # Phase 2: STEP - Process each decompiled function
    current_state = start_state
    decompiled_sources = sink.payload.get("decompiled_sources") or []
    step_results = []
    
    for step_index, source in enumerate(decompiled_sources):
        func_name = source.get("name") or "unknown"
        func_addr = source.get("address") or "unknown"
        func_code = source.get("code") or ""
        
        LOG.info("  Phase STEP %d/%d: Processing function %s @ %s", 
                 step_index + 1, len(decompiled_sources), func_name, func_addr)
        
        step_prompt = _build_step_prompt(
            sink, current_state, func_code, func_name, step_index
        )
        step_content, step_state = _request_llm(
            step_prompt,
            api_url=api_url,
            api_token=api_token,
            model=model,
            timeout=timeout,
        )
        
        if not step_state:
            LOG.warning("  Failed to parse STEP %d state, keeping previous state", step_index)
            step_state = current_state
        
        step_results.append({
            "step_index": step_index,
            "function_name": func_name,
            "function_address": func_addr,
            "response_text": step_content,
            "state": step_state,
        })
        
        current_state = step_state
    
    # Phase 3: FINAL - Make verdict
    LOG.info("  Phase FINAL: Making verdict for sink_%d", sink.index)
    final_prompt = _build_final_prompt(current_state)
    final_content, final_verdict = _request_llm(
        final_prompt,
        api_url=api_url,
        api_token=api_token,
        model=model,
        timeout=timeout,
    )
    
    if not final_verdict:
        raise ValueError(f"Failed to parse FINAL verdict for sink_{sink.index}")
    
    # Return comprehensive result
    return {
        "sink_index": sink.index,
        "sink_path": sink.path,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "start_phase": {
            "response_text": start_content,
            "state": start_state,
        },
        "step_phases": step_results,
        "final_phase": {
            "response_text": final_content,
            "verdict": final_verdict,
        },
    }




def analyze_sink_file(path: str, output_dir: str, **request_options) -> Dict[str, Any]:
    """Analyze one explicit report and save validated results for pipeline callers."""
    match = SINK_FILENAME_RE.match(os.path.basename(path))
    if not match:
        raise ValueError("Expected a sink_<n>.json report")
    sink = _load_sink(path, int(match.group(1)))
    if not isinstance(sink.payload, dict):
        raise ValueError("Sink report must be a JSON object")
    result = _analyze_sink_three_phase(sink, **request_options)
    verdict = result["final_phase"]["verdict"]
    if verdict.get("verdict") not in {"yes", "no", "unknown"}:
        raise ValueError("Invalid final verdict")
    if verdict.get("confidence") not in {"high", "med", "low"}:
        raise ValueError("Invalid final confidence")
    ops = verdict.get("vulnerable_ops")
    if not isinstance(ops, list) or any(not isinstance(op, dict) for op in ops):
        raise ValueError("Invalid vulnerable_ops")
    if verdict["verdict"] != "yes" and ops:
        raise ValueError("Non-vulnerable verdict must have empty vulnerable_ops")
    summary = {"sink_index": sink.index, "verdict": verdict["verdict"],
               "confidence": verdict["confidence"], "vulnerable_ops": ops}
    os.makedirs(output_dir, exist_ok=True)
    for suffix, data in (("llm", result), ("verdict", summary)):
        with open(os.path.join(output_dir, f"sink_{sink.index}_{suffix}.json"), "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
    return summary


def _cli_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send sink_<n>.json reports to an LLM for overflow analysis."
    )
    parser.add_argument(
        "--results",
        required=True,
        help="Directory containing sink_<n>.json files from integer_overflow_detection.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Directory to store sink_<n>_llm.json outputs (defaults to --results).",
    )
    parser.add_argument(
        "--api-url",
        default=DEFAULT_API_URL,
        help="Chat completion API endpoint.",
    )
    parser.add_argument(
        "--api-token",
        default=DEFAULT_API_TOKEN,
        help="API token for the LLM endpoint.",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help="Model identifier used by the LLM endpoint.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="HTTP timeout in seconds per request.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Process at most N sinks.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log verbosity.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Iterable[str]] = None) -> None:
    args = _cli_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level))
    results_dir = args.results
    output_dir = args.output or results_dir
    sink_files = _list_sink_files(results_dir)
    if not sink_files:
        raise SystemExit(f"No sink_<n>.json files found in {results_dir}")

    if args.limit is not None:
        sink_files = sink_files[: args.limit]

    for index, path in sink_files:
        sink = _load_sink(path, index)
        LOG.info("Analyzing sink_%d.json with three-phase state machine", index)
        try:
            result = _analyze_sink_three_phase(
                sink,
                api_url=args.api_url,
                api_token=args.api_token,
                model=args.model,
                timeout=args.timeout,
            )
        except (urllib.error.URLError, ValueError) as exc:
            LOG.error("Analysis failed for sink_%d.json: %s", index, exc)
            continue
        
        # Write comprehensive output
        output_path = os.path.join(output_dir, f"sink_{index}_llm.json")
        os.makedirs(output_dir, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2)
        
        LOG.info("Wrote %s", output_path)
        
        # Also write a summary with just the verdict
        verdict = result.get("final_phase", {}).get("verdict", {})
        verdict_summary = {
            "sink_index": index,
            "verdict": verdict.get("verdict", "unknown"),
            "confidence": verdict.get("confidence", "unknown"),
            "vulnerable_ops": verdict.get("vulnerable_ops", []),
        }
        summary_path = os.path.join(output_dir, f"sink_{index}_verdict.json")
        with open(summary_path, "w", encoding="utf-8") as handle:
            json.dump(verdict_summary, handle, indent=2)
        
        LOG.info("Wrote verdict summary to %s", summary_path)


if __name__ == "__main__":
    main()
