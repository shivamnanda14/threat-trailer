import sys
import asyncio
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from trailer_agent import run_forensics

# Windows: Playwright needs subprocess support
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

app = FastAPI(title="Threat Trailer Engine")

app.add_middleware(
    CORSMiddleware,
    # Wildcard hata kar exact URL daal, bina trailing slash ke
    allow_origins=[
        "http://localhost:3000",
        "https://threat-trailer-app.onrender.com" 
    ],
    allow_credentials=True, # Ise True kar de
    allow_methods=["*"],
    allow_headers=["*"],
)

class DetonationRequest(BaseModel):
    url: HttpUrl


@app.post("/api/detonate")
async def detonate(req: DetonationRequest):
    url_str = str(req.url)
    try:
        # run_forensics already returns threat_score, risk_level and score_breakdown.
        # Do not overwrite them here.
        return await run_forensics(url_str)
    except ValueError as e:
        # SSRF guard / invalid target -> client error, not a server crash
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        print(f"[ERROR] detonate failed: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail="Scan failed. Check the backend logs.")