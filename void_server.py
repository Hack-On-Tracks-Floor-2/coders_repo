"""
VOID // SENTINEL — Local Dev Server
Serves void_dashboard.html at http://localhost:8080
"""
from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import uvicorn, os, pathlib

BASE = pathlib.Path(__file__).parent

app = FastAPI(title="VOID SENTINEL", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

# Serve static assets (CSS, JS, images) from /static if the folder exists
static_dir = BASE / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

@app.get("/", response_class=FileResponse)
async def root():
    return FileResponse(str(BASE / "void_dashboard.html"), media_type="text/html")

@app.get("/kage", response_class=FileResponse)
async def kage():
    """KageLandingPage — the Kyoto temple Three.js experience."""
    return FileResponse(str(BASE / "void-kage.html"), media_type="text/html")

@app.get("/health")
async def health():
    return JSONResponse({"status": "VOID SENTINEL online", "tripwires": "ACTIVE"})

if __name__ == "__main__":
    import sys
    sys.stdout.reconfigure(encoding="utf-8")
    port = int(os.environ.get("PORT", 8080))
    print(f"\n  [VOID // SENTINEL]")
    print(f"  Autonomous Cyber-Deception & Honeytoken Defense")
    print(f"\n  [OK] Dashboard --> http://localhost:{port}")
    print(f"  [OK] Health     --> http://localhost:{port}/health\n")
    uvicorn.run("void_server:app", host="0.0.0.0", port=port, reload=True, log_level="warning")
