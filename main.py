import os
import json
import hashlib
import uuid
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Request, Response, HTTPException, status
from pydantic import BaseModel, Field
import google.generativeai as genai

app = FastAPI(title="Observable Incident Agent", version="v2")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

# In-memory storage for runs and state persistence
RUN_STORAGE: Dict[str, Dict[str, Any]] = {}

def generate_hex_id(length: int) -> str:
    return uuid.uuid4().hex[:length]

def compute_arguments_digest(args: dict) -> str:
    compact_json = json.dumps(args, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(compact_json.encode('utf-8')).hexdigest()

@app.post("/v2/incidents")
async def create_incident_run(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    profile = body.get("profile")
    if profile != "ga5-incident-agent/v2":
        raise HTTPException(status_code=422, detail="Unsupported profile")

    run_id = body.get("runId")
    if not run_id:
        raise HTTPException(status_code=400, detail="Missing runId")

    public_marker = body.get("publicMarker", "default-marker")
    incident = body.get("incident", {})
    tool_catalog = body.get("toolCatalog", [])
    policy = body.get("policy", {})
    allowed_root_causes = incident.get("allowedRootCauses", [])
    transcript = incident.get("transcript", "")
    
    # Idempotency & Conflict Check
    body_hash = hashlib.sha256(await request.body()).hexdigest()
    if run_id in RUN_STORAGE:
        existing = RUN_STORAGE[run_id]
        if existing["body_hash"] == body_hash:
            return existing["current_response"]
        else:
            raise HTTPException(status_code=409, detail="Changed content conflict for runId")

    # AI Model Planning
    model_name = "gemini-1.5-flash"
    generation_trace_id = generate_hex_id(32)
    model_span_id = generate_hex_id(16)
    
    diagnosis_result = {"rootCause": allowed_root_causes[0] if allowed_root_causes else "unknown", "evidence": []}
    diagnostic_dispatches = []

    try:
        model = genai.GenerativeModel(model_name)
        prompt = (
            f"Analyze the following incident transcript and choose ONE root cause from {allowed_root_causes} "
            f"and cite 2 to 4 evidence IDs (e.g., ev_01) from the transcript.\n"
            f"Also choose 1 to 3 diagnostic tool calls from the catalog: {json.dumps(tool_catalog)}\n"
            f"Transcript:\n{transcript}\n"
            f"Respond strictly in JSON format with keys: rootCause (string), evidence (list of strings), diagnostics (list of objects with toolName and arguments)."
        )
        response = model.generate_content(prompt)
        text = response.text.strip()
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()
        parsed = json.loads(text)
        rc = parsed.get("rootCause")
        if rc in allowed_root_causes:
            diagnosis_result["rootCause"] = rc
        diagnosis_result["evidence"] = parsed.get("evidence", [])[:4]
        
        diag_plan = parsed.get("diagnostics", [])[:3]
        for idx, d in enumerate(diag_plan):
            action_id = generate_hex_id(12)
            call_id = generate_hex_id(12)
            client_span_id = generate_hex_id(16)
            diagnostic_dispatches.append({
                "actionId": action_id,
                "callId": call_id,
                "phase": "diagnostic",
                "toolName": d.get("toolName", tool_catalog[0]["name"] if tool_catalog else "query_metrics"),
                "arguments": d.get("arguments", {}),
                "evidence": diagnosis_result["evidence"][:1],
                "attempt": 1,
                "traceparent": f"00-{generation_trace_id}-{client_span_id}-01",
                "_client_span_id": client_span_id
            })
    except Exception:
        if tool_catalog:
            action_id = generate_hex_id(12)
            call_id = generate_hex_id(12)
            client_span_id = generate_hex_id(16)
            diagnostic_dispatches.append({
                "actionId": action_id,
                "callId": call_id,
                "phase": "diagnostic",
                "toolName": tool_catalog[0]["name"],
                "arguments": {},
                "evidence": [],
                "attempt": 1,
                "traceparent": f"00-{generation_trace_id}-{client_span_id}-01",
                "_client_span_id": client_span_id
            })

    # Build OTLP Trace structure
    server_span_id = generate_hex_id(16)
    agent_span_id = generate_hex_id(16)
    
    spans = [
        {
            "traceId": generation_trace_id,
            "spanId": server_span_id,
            "name": "SERVER POST /v2/incidents",
            "kind": 2,
            "attributes": [{"key": "ga5.run.id", "value": {"stringValue": run_id}}, {"key": "ga5.public.marker", "value": {"stringValue": public_marker}}]
        },
        {
            "traceId": generation_trace_id,
            "spanId": agent_span_id,
            "parentSpanId": server_span_id,
            "name": "INTERNAL invoke_agent incident-response",
            "kind": 1,
            "attributes": [{"key": "ga5.run.id", "value": {"stringValue": run_id}}, {"key": "ga5.public.marker", "value": {"stringValue": public_marker}}]
        },
        {
            "traceId": generation_trace_id,
            "spanId": model_span_id,
            "parentSpanId": agent_span_id,
            "name": "CLIENT chat incident-plan",
            "kind": 3,
            "attributes": [
                {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                {"key": "ga5.public.marker", "value": {"stringValue": public_marker}},
                {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}},
                {"key": "gen_ai.request.model", "value": {"stringValue": model_name}}
            ]
        }
    ]

    for d in diagnostic_dispatches:
        exec_span_id = generate_hex_id(16)
        client_span_id = d.get("_client_span_id", generate_hex_id(16))
        spans.append({
            "traceId": generation_trace_id,
            "spanId": exec_span_id,
            "parentSpanId": agent_span_id,
            "name": f"INTERNAL execute_tool {d['toolName']}",
            "kind": 1,
            "attributes": [
                {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                {"key": "ga5.public.marker", "value": {"stringValue": public_marker}},
                {"key": "ga5.action.id", "value": {"stringValue": d["actionId"]}},
                {"key": "gen_ai.tool.name", "value": {"stringValue": d["toolName"]}},
                {"key": "gen_ai.tool.call.id", "value": {"stringValue": d["callId"]}},
                {"key": "gen_ai.operation.name", "value": {"stringValue": "execute_tool"}}
            ]
        })
        spans.append({
            "traceId": generation_trace_id,
            "spanId": client_span_id,
            "parentSpanId": exec_span_id,
            "name": f"CLIENT POST tool/{d['toolName']}",
            "kind": 3,
            "attributes": [
                {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                {"key": "ga5.public.marker", "value": {"stringValue": public_marker}},
                {"key": "ga5.action.id", "value": {"stringValue": d["actionId"]}},
                {"key": "ga5.attempt", "value": {"intValue": 1}},
                {"key": "http.request.method", "value": {"stringValue": "POST"}},
                {"key": "http.request.resend_count", "value": {"intValue": 0}}
            ]
        })

    otlp_payload = {
        "resourceSpans": [{
            "scopeSpans": [{"spans": spans}]
        }]
    }

    clean_dispatches = [{k: v for k, v in d.items() if not k.startswith("_")} for d in diagnostic_dispatches]

    response_data = {
        "runId": run_id,
        "status": "waiting",
        "diagnosis": diagnosis_result,
        "dispatches": clean_dispatches,
        "approvals": []
    }

    RUN_STORAGE[run_id] = {
        "body_hash": body_hash,
        "request_body": body,
        "current_response": response_data,
        "receiptLog": [],
        "actionLog": clean_dispatches,
        "otlp": otlp_payload,
        "traceId": generation_trace_id,
        "policy": policy,
        "toolCatalog": tool_catalog
    }

    return response_data

@app.post("/v2/incidents/{run_id}/receipts")
async def post_receipts(run_id: str, request: Request):
    if run_id not in RUN_STORAGE:
        raise HTTPException(status_code=404, detail="Run not found")
    
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    run_state = RUN_STORAGE[run_id]
    receipt_id = body.get("receiptId", generate_hex_id(12))
    outcomes = body.get("outcomes", [])
    approvals = body.get("approvals", [])

    for o in outcomes:
        run_state["receiptLog"].append({
            "receiptId": receipt_id,
            "actionId": o.get("actionId"),
            "callId": o.get("callId"),
            "attempt": o.get("attempt", 1),
            "status": o.get("status"),
            "resultClass": o.get("resultClass"),
            "nonce": o.get("nonce")
        })

    for a in approvals:
        run_state["receiptLog"].append({
            "receiptId": receipt_id,
            "approvalId": a.get("approvalId"),
            "decision": a.get("decision"),
            "nonce": a.get("nonce")
        })

    policy = run_state.get("policy", {})
    effect_tools = policy.get("effectTools", ["scale_service"])
    approval_required = policy.get("approvalRequiredFor", ["rollback_deployment", "disable_feature"])
    
    chosen_effect = effect_tools[0] if effect_tools else "scale_service"

    # Check if approval was received
    approved = any(a.get("decision") == "approved" for a in approvals)

    if chosen_effect in approval_required and not approved:
        # Request approval first
        approval_id = generate_hex_id(12)
        action_id = generate_hex_id(12)
        effect_args = {"service": run_state["request_body"].get("incident", {}).get("service", "app")}
        args_digest = compute_arguments_digest(effect_args)

        approval_response = {
            "status": "waiting",
            "dispatches": [],
            "approvals": [{
                "approvalId": approval_id,
                "actionId": action_id,
                "toolName": chosen_effect,
                "argumentsDigest": args_digest
            }]
        }
        run_state["current_response"] = approval_response
        return approval_response

    # Complete run with effect dispatch
    effect_action_id = generate_hex_id(12)
    effect_call_id = generate_hex_id(12)
    effect_dispatch = {
        "actionId": effect_action_id,
        "callId": effect_call_id,
        "phase": "effect",
        "toolName": chosen_effect,
        "arguments": {"service": run_state["request_body"].get("incident", {}).get("service", "app")},
        "attempt": 1,
        "traceparent": f"00-{run_state['traceId']}-{generate_hex_id(16)}-01"
    }
    run_state["actionLog"].append(effect_dispatch)

    final_response = {
        "runId": run_id,
        "status": "completed",
        "diagnosis": run_state["current_response"].get("diagnosis", {"rootCause": "unknown", "evidence": []}),
        "chosenEffect": chosen_effect,
        "suppressed": [],
        "actionLog": run_state["actionLog"],
        "receiptLog": run_state["receiptLog"],
        "otlp": run_state["otlp"]
    }
    run_state["current_response"] = final_response
    return final_response

@app.get("/v2/incidents/{run_id}")
async def get_incident_run(run_id: str):
    if run_id not in RUN_STORAGE:
        raise HTTPException(status_code=404, detail="Run not found")
    return RUN_STORAGE[run_id]["current_response"]
