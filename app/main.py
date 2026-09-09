from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes import router
from app.config import settings
from app.detectors.gliner_detector import gliner_singleton

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Preload GLiNER model once on application startup
    gliner_singleton.load_model()
    yield

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="PromptGuard — Application-layer LLM Data Leakage Prevention Gateway",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/")
def home():
    return {
        "status": "Online",
        "service": settings.APP_NAME,
        "version": settings.VERSION,
        "mock_llm_mode": settings.MOCK_LLM_MODE,
        "endpoints": {
            "direct_chat": "/v1/direct-chat",
            "chat_completions": "/v1/chat/completions",
            "inspect_prompt": "/api/inspect",
            "audit_logs": "/api/audit-logs",
            "analytics": "/api/analytics",
        },
    }


@app.get("/health")
def health_check():
    return {"status": "healthy"}
