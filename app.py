"""
FastAPI Server for PromptArmor: LLM Vulnerability Scanner & Safety Auditor.
Provides REST APIs for single-probe testing, full OWASP LLM benchmark runs,
and serves the modern web interface.
"""

import os
import sys
from typing import Dict, Any, Optional, List
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Ensure project directory is in python search path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from probes import PROBES
from targets import (
    MockTarget, LiveAPITarget, GeminiAPITarget, GroqAPITarget,
    SYSTEM_PROMPT_DEFAULT, CANARY_TOKEN
)
from scanner import LLMScanner, generate_markdown_report

app = FastAPI(
    title="PromptArmor LLM Vulnerability Scanner",
    description="Automated Red-Teaming and Safety Auditing for Conversational AI",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request schemas
class TargetConfig(BaseModel):
    target_type: str = Field(default="mock-vulnerable", description="mock-vulnerable, mock-moderate, mock-hardened, or live-api")
    system_prompt: Optional[str] = SYSTEM_PROMPT_DEFAULT
    canary_token: Optional[str] = CANARY_TOKEN
    api_key: Optional[str] = ""
    endpoint: Optional[str] = "https://api.openai.com/v1/chat/completions"
    model: Optional[str] = "gpt-4o-mini"


class ScanRequest(BaseModel):
    prompt: str
    target: TargetConfig
    probe_id: Optional[str] = "CUSTOM"
    probe_name: Optional[str] = "Custom Injected Vector"
    category: Optional[str] = "Adversarial Prompt Injection"
    risk_level: Optional[str] = "HIGH"


class BenchmarkRequest(BaseModel):
    target: TargetConfig


class CheckModelRequest(BaseModel):
    target_type: str
    api_key: str


def create_target(config: TargetConfig):
    tt = config.target_type.lower()
    sys_prompt = config.system_prompt or SYSTEM_PROMPT_DEFAULT
    canary = config.canary_token or CANARY_TOKEN

    if tt == "mock-vulnerable":
        return MockTarget(posture="vulnerable", system_prompt=sys_prompt, canary=canary)
    elif tt == "mock-moderate":
        return MockTarget(posture="moderate", system_prompt=sys_prompt, canary=canary)
    elif tt == "mock-hardened":
        return MockTarget(posture="hardened", system_prompt=sys_prompt, canary=canary)
    elif tt in ["google-gemini", "gemini"]:
        if not config.api_key:
            raise HTTPException(status_code=400, detail="Google Gemini API Key is required. Get one free at https://aistudio.google.com/")
        model_name = config.model if config.model and "gemini" in config.model.lower() else "gemini-1.5-flash"
        return GeminiAPITarget(
            api_key=config.api_key,
            model=model_name,
            system_prompt=sys_prompt,
            canary=canary
        )
    elif tt in ["groq", "groq-cloud"]:
        if not config.api_key:
            raise HTTPException(status_code=400, detail="Groq API Key is required. Get one free at https://console.groq.com/")
        model_name = config.model if config.model and ("llama" in config.model.lower() or "mixtral" in config.model.lower() or "gemma" in config.model.lower()) else "llama-3.3-70b-versatile"
        return GroqAPITarget(
            api_key=config.api_key,
            model=model_name,
            system_prompt=sys_prompt,
            canary=canary
        )
    elif tt in ["live-api", "openai"]:
        if not config.api_key and "localhost" not in (config.endpoint or ""):
            raise HTTPException(status_code=400, detail="API Key required for non-local live endpoints.")
        return LiveAPITarget(
            api_key=config.api_key or "",
            endpoint=config.endpoint or "https://api.openai.com/v1/chat/completions",
            model=config.model or "gpt-4o-mini",
            system_prompt=sys_prompt,
            canary=canary
        )
    else:
        raise HTTPException(status_code=400, detail=f"Unknown target type: {config.target_type}")


@app.get("/", response_class=FileResponse)
def serve_index():
    index_path = os.path.join(BASE_DIR, "static", "index.html")
    if not os.path.exists(index_path):
        raise HTTPException(status_code=404, detail="Frontend index.html not found")
    return FileResponse(index_path)


@app.get("/api/probes")
def get_probes():
    """Returns library of standard attack vectors."""
    return PROBES


@app.get("/api/defaults")
def get_defaults():
    """Returns default system prompt and canary."""
    return {
        "system_prompt": SYSTEM_PROMPT_DEFAULT,
        "canary_token": CANARY_TOKEN
    }


@app.post("/api/check-models")
def check_models(req: CheckModelRequest):
    """Discovers available models for the given API key."""
    tt = req.target_type.lower()
    if not req.api_key:
        raise HTTPException(status_code=400, detail="API key is required.")

    if "gemini" in tt:
        models = GeminiAPITarget.list_available_models(req.api_key)
        if not models:
            return {
                "status": "error",
                "models": [],
                "message": "No generateContent models found for this key. Please check your Google AI Studio key permissions."
            }
        return {
            "status": "ok",
            "models": models,
            "message": f"Successfully connected to Google Gemini! Discovered {len(models)} supported models."
        }
    elif "groq" in tt:
        models = GroqAPITarget.list_available_models(req.api_key)
        if not models:
            return {
                "status": "error",
                "models": [],
                "message": "Could not connect to Groq. Please verify your API key."
            }
        return {
            "status": "ok",
            "models": models,
            "message": f"Successfully connected to Groq! Discovered {len(models)} models."
        }
    else:
        return {"status": "ok", "models": [], "message": "Custom endpoint"}


@app.post("/api/scan")
def scan_single(req: ScanRequest):
    """Executes single prompt injection attack and performs detection."""
    target_obj = create_target(req.target)
    scanner = LLMScanner(target_obj)

    probe_data = {
        "id": req.probe_id,
        "name": req.probe_name,
        "prompt": req.prompt,
        "category": req.category,
        "risk_level": req.risk_level
    }

    result = scanner.audit_probe(probe_data)
    return {
        "target_name": target_obj.name,
        "result": result
    }


@app.post("/api/benchmark")
def run_benchmark(req: BenchmarkRequest):
    """Executes full OWASP probe benchmark and returns safety score."""
    target_obj = create_target(req.target)
    scanner = LLMScanner(target_obj)
    audit = scanner.run_full_suite()
    report_md = generate_markdown_report(audit)
    return {
        "audit": audit,
        "markdown_report": report_md
    }


if __name__ == "__main__":
    import uvicorn
    print("\nStarting PromptArmor LLM Vulnerability Scanner on http://127.0.0.1:8000")
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=False)
