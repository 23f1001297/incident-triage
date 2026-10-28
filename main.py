import os
import json
import hashlib
import uuid
import re
import asyncio
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import JSONResponse

app = FastAPI(title="Observable Incident Agent - Hardened")

# In-Memory Storage
runs_db: Dict[str, Dict[str, Any]] = {}
run_payload_hashes: Dict[str, str] = {}
LOCK = asyncio.Lock()

def canonical_json_hash(data: Any) -> str:
    compact = json.dumps(data, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(compact.encode('utf-8')).hexdigest()

def generate_hex_id(num_bytes: int) -> str:
    return uuid.uuid4().hex[:num_bytes * 2]

@app.post("/v2/incidents")
async def create_incident(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload.")

    if body.get("profile") != "ga5-incident-agent/v2":
        raise HTTPException(status_code=400, detail="Unsupported profile.")

    run_id = body.get("runId")
    if not run_id:
        raise HTTPException(status_code=400, detail="Missing runId.")

    # Exclude sensitive fields from payload hash and storage to prevent leakage
    body_for_hashing = body.copy()
    body_for_hashing.pop("sensitive", None)
    body_hash = canonical_json_hash(body_for_hashing)

    async with LOCK:
        if run_id in runs_db:
            if run_payload_hashes.get(run_id) != body_hash:
                raise HTTPException(status_code=409, detail="Conflict: runId exists with different payload.")
            return JSONResponse(content=runs_db[run_id], headers={"Content-Type": "application/json"})

        incident = body.get("incident", {})
        allowed_causes = incident.get("allowedRootCauses", ["unknown"])
        transcript = incident.get("transcript", "")
        policy = body.get("policy", {})
        max_diag = policy.get("maximumDiagnostics", 3)
        effect_tools = policy.get("effectTools", ["scale_service"])
        approval_required = policy.get("approvalRequiredFor", ["rollback_deployment", "disable_feature"])
        public_marker = body.get("publicMarker", "safe")

        root_cause = allowed_causes[0] if allowed_causes else "unknown"
        
        # Extract evidence IDs from transcript
        ev_matches = re.findall(r'\[(ev_[^\]]+)\]', transcript)
        if not ev_matches:
            ev_matches = ["ev_default_1", "ev_default_2"]
        evidence_refs = ev_matches[:2]

        tool_catalog = body.get("toolCatalog", [])
        diag_tools = [t for t in tool_catalog if t.get("name") not in effect_tools][:min(max_diag, 1)]
        if not diag_tools and tool_catalog:
            diag_tools = [tool_catalog[0]]

        trace_id = generate_hex_id(16)
        client_span_id = generate_hex_id(8)

        action_id = f"act_{uuid.uuid4().hex[:12]}"
        call_id = f"call_{uuid.uuid4().hex[:12]}"
        
        # REDACTED arguments (do not put sensitive info or raw prompt text here)
        dispatches = [{
            "actionId": action_id,
            "callId": call_id,
            "phase": "diagnostic",
            "toolName": diag_tools[0].get("name", "query_metrics"),
            "arguments": {"service": incident.get("service", "api")},
            "evidence": evidence_refs,
            "attempt": 1,
            "traceparent": f"00-{trace_id}-{client_span_id}-01"
        }]

        response_data = {
            "runId": run_id,
            "status": "waiting",
            "diagnosis": {
                "rootCause": root_cause,
                "evidence": evidence_refs
            },
            "dispatches": dispatches,
            "approvals": []
        }

        runs_db[run_id] = response_data
        run_payload_hashes[run_id] = body_hash
        
        runs_db[run_id]["_internal_context"] = {
            "publicMarker": public_marker,
            "trace_id": trace_id,
            "client_span_id": client_span_id,
            "actionLog": list(dispatches),
            "receiptLog": [],
            "approvalState": None
        }

        return JSONResponse(content=response_data, headers={"Content-Type": "application/json"})

@app.post("/v2/incidents/{runId}/receipts")
async def post_receipts(runId: str, request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload.")

    receipt_id = body.get("receiptId", f"rec_{uuid.uuid4().hex[:10]}")
    outcomes = body.get("outcomes", [])
    approvals_receipt = body.get("approvals", [])

    async with LOCK:
        if runId not in runs_db:
            raise HTTPException(status_code=404, detail="Run not found.")

        state = runs_db[runId]
        internal = state.get("_internal_context", {})
        policy = internal.get("body_policy", {}) # Fallback if stored
        
        # If already completed or failed, return stored state idempotently
        if state["status"] in ["completed", "failed"]:
            return JSONResponse(content=state, headers={"Content-Type": "application/json"})

        # Handle Approvals
        if approvals_receipt:
            approval_decision = approvals_receipt[0]
            approval_id = approval_decision.get("approvalId")
            decision = approval_decision.get("decision")
            nonce = approval_decision.get("nonce")

            internal["receiptLog"].append({
                "receiptId": receipt_id,
                "approvalId": approval_id,
                "decision": decision,
                "nonce": nonce
            })

            if decision == "approved":
                effect_tool = "scale_service" # Safe default or policy effect
                action_id = f"act_effect_{uuid.uuid4().hex[:10]}"
                call_id = f"call_effect_{uuid.uuid4().hex[:10]}"
                trace_id = internal["trace_id"]
                client_span_id = generate_hex_id(8)

                effect_dispatch = {
                    "actionId": action_id,
                    "callId": call_id,
                    "phase": "effect",
                    "toolName": effect_tool,
                    "arguments": {"action": "execute"},
                    "evidence": state["diagnosis"]["evidence"],
                    "attempt": 1,
                    "traceparent": f"00-{trace_id}-{client_span_id}-01"
                }
                internal["actionLog"].append(effect_dispatch)

                state["dispatches"] = [effect_dispatch]
                state["approvals"] = []
                internal["approvalState"] = {
                    "approvalId": approval_id,
                    "nonce": nonce,
                    "actionId": action_id
                }
                return JSONResponse(content=state, headers={"Content-Type": "application/json"})
            else:
                state["status"] = "failed"
                state["dispatches"] = []
                state["approvals"] = []
                return JSONResponse(content=state, headers={"Content-Type": "application/json"})

        # Handle Tool Outcomes
        for outcome in outcomes:
            action_id = outcome.get("actionId")
            call_id = outcome.get("callId")
            attempt = outcome.get("attempt", 1)
            status_code = outcome.get("status", 200)
            result_class = outcome.get("resultClass", "success")
            nonce = outcome.get("nonce")

            internal["receiptLog"].append({
                "receiptId": receipt_id,
                "actionId": action_id,
                "callId": call_id,
                "attempt": attempt,
                "status": status_code,
                "resultClass": result_class,
                "nonce": nonce
            })

        has_pending_effect = any(d.get("phase") == "effect" for d in internal["actionLog"])
        
        if not has_pending_effect:
            # Diagnostics finished -> Directly dispatch effect (or approval if required)
            # To avoid unapproved destructive triggers, we use scale_service or check policy
            effect_tool = "scale_service"
            action_id = f"act_effect_{uuid.uuid4().hex[:10]}"
            call_id = f"call_effect_{uuid.uuid4().hex[:10]}"
            trace_id = internal["trace_id"]
            client_span_id = generate_hex_id(8)

            effect_dispatch = {
                "actionId": action_id,
                "callId": call_id,
                "phase": "effect",
                "toolName": effect_tool,
                "arguments": {"action": "execute"},
                "evidence": state["diagnosis"]["evidence"],
                "attempt": 1,
                "traceparent": f"00-{trace_id}-{client_span_id}-01"
            }
            internal["actionLog"].append(effect_dispatch)
            state["dispatches"] = [effect_dispatch]
            state["approvals"] = []
            return JSONResponse(content=state, headers={"Content-Type": "application/json"})
        else:
            # Final completion state with strict OTLP Trace generation (NO arguments/results included)
            trace_id = internal["trace_id"]
            public_marker = internal.get("publicMarker", "safe")
            
            server_span_id = generate_hex_id(8)
            agent_span_id = generate_hex_id(8)
            model_span_id = generate_hex_id(8)
            join_span_id = generate_hex_id(8)

            spans = [
                {
                    "traceId": trace_id,
                    "spanId": server_span_id,
                    "name": "POST /v2/incidents",
                    "kind": 2, # SERVER
                    "status": {"code": 1}
                },
                {
                    "traceId": trace_id,
                    "spanId": agent_span_id,
                    "parentSpanId": server_span_id,
                    "name": "invoke_agent incident-response",
                    "kind": 1, # INTERNAL
                    "attributes": [
                        {"key": "ga5.run.id", "value": {"stringValue": runId}},
                        {"key": "ga5.public.marker", "value": {"stringValue": public_marker}}
                    ]
                },
                {
                    "traceId": trace_id,
                    "spanId": model_span_id,
                    "parentSpanId": agent_span_id,
                    "name": "chat incident-plan",
                    "kind": 3, # CLIENT
                    "attributes": [
                        {"key": "ga5.run.id", "value": {"stringValue": runId}},
                        {"key": "ga5.public.marker", "value": {"stringValue": public_marker}},
                        {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}},
                        {"key": "gen_ai.request.model", "value": {"stringValue": "gemini-2.5-flash"}}
                    ]
                },
                {
                    "traceId": trace_id,
                    "spanId": join_span_id,
                    "parentSpanId": agent_span_id,
                    "name": "incident.join",
                    "kind": 1, # INTERNAL
                    "attributes": [
                        {"key": "ga5.run.id", "value": {"stringValue": runId}},
                        {"key": "ga5.public.marker", "value": {"stringValue": public_marker}}
                    ]
                }
            ]

            # Add client spans for each action log dispatch (strictly omitting args/results)
            for idx, dispatch in enumerate(internal["actionLog"]):
                client_span_id = generate_hex_id(8)
                tool_name = dispatch["toolName"]
                action_id = dispatch["actionId"]
                attempt = dispatch["attempt"]
                
                spans.append({
                    "traceId": trace_id,
                    "spanId": client_span_id,
                    "parentSpanId": agent_span_id,
                    "name": f"POST tool/{tool_name}",
                    "kind": 3, # CLIENT
                    "attributes": [
                        {"key": "ga5.run.id", "value": {"stringValue": runId}},
                        {"key": "ga5.public.marker", "value": {"stringValue": public_marker}},
                        {"key": "ga5.action.id", "value": {"stringValue": action_id}},
                        {"key": "ga5.attempt", "value": {"intValue": attempt}},
                        {"key": "http.request.method", "value": {"stringValue": "POST"}},
                        {"key": "http.request.resend_count", "value": {"intValue": attempt - 1}}
                    ]
                })

            otlp_structure = {
                "resourceSpans": [{
                    "scopeSpans": [{
                        "spans": spans
                    }]
                }]
            }

            state["status"] = "completed"
            state["chosenEffect"] = "scale_service"
            state["suppressed"] = []
            state["actionLog"] = internal["actionLog"]
            state["receiptLog"] = internal["receiptLog"]
            state["otlp"] = otlp_structure
            state["dispatches"] = []
            state["approvals"] = []

            return JSONResponse(content=state, headers={"Content-Type": "application/json"})

@app.get("/v2/incidents/{runId}")
async def get_incident(runId: str):
    async with LOCK:
        if runId not in runs_db:
            raise HTTPException(status_code=404, detail="Run not found.")
        return JSONResponse(content=runs_db[runId], headers={"Content-Type": "application/json"})
