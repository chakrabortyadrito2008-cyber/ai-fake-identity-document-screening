import uuid
from fastapi import Request
from fastapi.responses import JSONResponse
def attach_rate_limit(app, max_upload_bytes: int):
    @app.middleware('http')
    async def upload_guard(request: Request, call_next):
        request.state.request_id=request.headers.get("X-Request-ID",str(uuid.uuid4()))[:128]
        declared=request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared)>max_upload_bytes+65536:
            return JSONResponse(status_code=413,content={'detail':'Request exceeds configured upload limit'})
        response=await call_next(request); response.headers['X-Request-ID']=request.state.request_id
        return response
