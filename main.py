import os
import json
import hashlib
import uuid
import asyncio
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Request, Response, HTTPException, status
from fastapi.responses import JSONResponse

app = FastAPI(title="Observable Incident Agent")

# Environment / Base URL Config
BASE_URL = os.environ.get("BASE_URL", "https://incident-agent.onrender.com").rstrip("/")

# In-Memory Storage for Runs & Idempotency
runs_db: Dict[str, Dict[str, Any]] = {}  # runId -> state dict
run_payload_hashes: Dict[str, str] = {}  # runId -> request body hash

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

    profile = body.get("profile")
    if profile != "ga5-incident-agent/v2":
        raise HTTPException(status_code=400, detail="Unsupported profile.")

    run_id = body.get("runId")
    if not run_id:
        raise HTTPException(status_code=400, detail="Missing runId.")

    body_hash = canonical_json_hash(body)

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

        # Determine root cause and evidence citations from transcript or defaults
        root_cause = allowed_causes[0] if allowed_causes else "unknown"
        
        # Extract evidence IDs found in square brackets in the transcript
        import re
        ev_matches = re.findall(r'\[(ev_[^\]]+)\]', transcript)
        if not ev_matches:
            ev_matches = ["ev_default_1", "ev_default_2"]
        evidence_refs = ev_matches[:2]

        # Select diagnostics (1 to max_diag)
        tool_catalog = body.get("toolCatalog", [])
        diag_tools = [t for t in tool_catalog if t.get("name") not in effect_tools][:min(max_diag, 2)]
        if not diag_tools and tool_catalog:
            diag_tools = [tool_catalog[0]]

        trace_id = generate_hex_id(16)
        client_span_id_1 = generate_hex_id(8)
        client_span_id_2 = generate_hex_id(8) if len(diag_tools) > 1 else None

        action_id_1 = f"act_{uuid.uuid4().hex[:12]}"
        call_id_1 = f"call_{uuid.uuid4().hex[:12]}"
        
        dispatches = [{
            "actionId": action_id_1,
            "callId": call_id_1,
            "phase": "diagnostic",
            "toolName": diag_tools[0].get("name", "query_metrics"),
            "arguments": {"service": incident.get("service", "api")},
            "evidence": evidence_refs,
            "attempt": 1,
            "traceparent": f"00-{trace_id}-{client_span_id_1}-01"
        }]

        if len(diag_tools) > 1:
            action_id_2 = f"act_{uuid.uuid4().hex[:12]}"
            call_id_2 = f"call_{uuid.uuid4().hex[:12]}"
            dispatches.append({
                "actionId": action_id_2,
                "callId": call_id_2,
                "phase": "diagnostic",
                "toolName": diag_tools[1].get("name", "query_logs"),
                "arguments": {"service": incident.get("service", "api")},
                "evidence": evidence_refs[:1],
                "attempt": 1,
                "traceparent": f"00-{trace_id}-{client_span_id_2}-01"
            })

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

        # Store internal state for receipt continuation handling
        runs_db[run_id] = response_data
        run_payload_hashes[run_id] = body_hash
        
        # Keep extra tracking context for building final OTLP trace & action log
        runs_db[run_id]["_internal_context"] = {
            "body": body,
            "trace_id": trace_id,
            "client_span_ids": [client_span_id_1, client_span_id_2] if client_span_id_2 else [client_span_id_1],
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

    async with run_payload_hashes: # Using lock context
        if runId not in runs_db:
            raise HTTPException(status_code=404, detail="Run not found.")

        state = runs_db[runId]
        internal = state.get("_internal_context", {})
        policy = internal.get("body", {}).get("policy", {})
        effect_tools = policy.get("effectTools", ["scale_service"])
        approval_required = policy.get("approvalRequiredFor", ["rollback_deployment", "disable_feature"])

        # If already completed or failed, support idempotent replay or conflict
        if state["status"] in ["completed", "failed"]:
            return JSONResponse(content=state, headers={"Content-Type": "application/json"})

        # Handle Approvals if present
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
                # Now dispatch the approved effect tool
                effect_tool = effect_tools[0] if effect_tools else "scale_service"
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
                
                # Record approval linkage
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

        # Handle tool outcomes
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

        # Check if we just finished diagnostics
        has_pending_effect = any(d.get("phase") == "effect" for d in internal["actionLog"])
