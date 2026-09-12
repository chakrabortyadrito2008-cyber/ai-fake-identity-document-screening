import hmac, os
from fastapi import Header, HTTPException
def api_key_guard(required: bool):
    async def guard(x_api_key: str | None=Header(default=None)):
        configured=os.getenv("FRAUD_API_KEY","")
        if required and (not configured or not x_api_key or not hmac.compare_digest(x_api_key,configured)): raise HTTPException(401,"Invalid API key")
    return guard
