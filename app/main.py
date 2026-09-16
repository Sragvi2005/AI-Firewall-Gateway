import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from app.routes import router
from app.config import settings

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="PromptGuard — Application-layer LLM Data Leakage Prevention Gateway"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Gateway API routes
app.include_router(router)

# Mount static files for the Chat UI
_static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=_static_dir), name="static")


@app.get("/chat")
def chat_ui():
    """Serve the PromptGuard interactive Chat UI."""
    return FileResponse(os.path.join(_static_dir, "index.html"))

@app.get("/")
def home():
    return {
        "status": "Online",
        "service": settings.APP_NAME,
        "version": settings.VERSION,
        "mock_llm_mode": settings.MOCK_LLM_MODE,
        "endpoints": {
            "chat_completions": "/v1/chat/completions",
            "inspect_prompt": "/api/inspect",
            "audit_logs": "/api/audit-logs",
            "analytics": "/api/analytics"
        }
    }

@app.get("/health")
def health_check():
    return {"status": "healthy"}
