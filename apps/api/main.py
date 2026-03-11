from fastapi import FastAPI

from .routes import health

app = FastAPI(title="ThreatAtlas API")

app.include_router(health.router, prefix="/health", tags=["health"])


@app.get("/")
async def root():
    """Simple root endpoint to verify the service is running."""
    return {"service": "ThreatAtlas API"}
