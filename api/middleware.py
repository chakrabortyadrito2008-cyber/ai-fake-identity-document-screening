import uuid
from fastapi import Request
from fastapi.responses import JSONResponse
from security.rate_limiter import RateLimiter
def attach_rate_limit(app, limit: int, max_upload_bytes: int):
    limiter=RateLimiter(limit)
    @app.middleware('http')
    async def rate_limit(request: Request, call_next):
        request.state.request_id=request.headers.get("X-Request-ID",str(uuid.uuid4()))[:128]
        declared=request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared)>max_upload_bytes+65536:
            return JSONResponse(status_code=413,content={'detail':'Request exceeds configured upload limit'})
        client=request.client.host if request.client else 'local'
        if not limiter.allow(client): return JSONResponse(status_code=429,content={'detail':'Rate limit exceeded'})
        response=await call_next(request); response.headers['X-Request-ID']=request.state.request_id
        return response
