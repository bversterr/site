from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os

load_dotenv()

from routes.cloudflare import router as cf_router
from routes.dashboard  import router as dash_router
from routes.security   import router as sec_router

app = FastAPI(
    title       = "Blue Ghost Defense API",
    description = "Backend API powering the Blue Ghost security dashboard",
    version     = "1.0.0",
    docs_url    = "/docs",
    redoc_url   = "/redoc",
)

allowed_origins = os.environ.get(
    "ALLOWED_ORIGINS",
    "http://localhost:3000,https://benjaminverster.co.za"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins     = allowed_origins,
    allow_credentials = True,
    allow_methods     = ["GET", "POST", "PATCH", "DELETE"],
    allow_headers     = ["*"],
)

app.include_router(cf_router)
app.include_router(dash_router)
app.include_router(sec_router)

@app.get("/", tags=["Health"])
async def root():
    return {
        "status":  "online",
        "service": "Blue Ghost Defense API",
        "version": "1.0.0",
    }

@app.get("/health", tags=["Health"])
async def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
