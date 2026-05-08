from fastapi import FastAPI
from app.api.routes import scanner

# ======================================
# AYUSH WORK AREA
# Main entry point for the FastAPI AI Engine
# Register all API routers here
# Configure CORS and lifecycle events
# ======================================

app = FastAPI(
    title="Cyber Shield AI Engine",
    description="Machine Learning service for detecting cyber threats.",
    version="1.0.0"
)

app.include_router(scanner.router, prefix="/api/v1/scan", tags=["Scanner"])

@app.get("/health")
def health_check():
    return {"status": "healthy", "model_version": "v1.0.0"}
