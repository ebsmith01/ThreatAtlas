from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes.detection_routes import router as detection_router
from api.routes.eval_routes import router as eval_router
from api.routes.health_routes import router as health_router



app = FastAPI(
    title="ThreatAtlas",
    description="AI Security Testing & Evaluation Platform",
    version="0.1.0",
)


# ==================================================
# CORS Configuration
# ==================================================
# Allows the React frontend to communicate
# with the FastAPI backend.
#
# Without this, browsers will block requests
# coming from:
#
# http://localhost:5173
#
# because it is a different origin than the API.
# ==================================================

app.add_middleware(
    CORSMiddleware,
    # Allowed frontend origins.
    allow_origins=[
        "http://localhost:5173",
    ],
    # Allow cookies/auth headers if added later.
    allow_credentials=True,
    # Allow all HTTP methods.
    allow_methods=["*"],
    # Allow all headers.
    allow_headers=["*"],
)


@app.get("/")
def root() -> dict:
    """
    API landing endpoint.
    """

    return {
        "name": "ThreatAtlas",
        "status": "running",
        "platform": "AI Security Testing & Evaluation Platform",
    }


# Register API routes.
app.include_router(health_router)
app.include_router(eval_router)
app.include_router(detection_router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )