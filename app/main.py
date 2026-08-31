from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
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
