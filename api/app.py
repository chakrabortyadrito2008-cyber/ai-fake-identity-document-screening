from pathlib import Path
from fastapi import FastAPI
from core.pipeline import FraudPipeline
from api.routes import make_router
from api.middleware import attach_rate_limit
from security.audit import configure_logging
def create_app(root: str | Path | None=None)->FastAPI:
    root=Path(root or Path(__file__).resolve().parents[1]); configure_logging(); app=FastAPI(title='AI-Based Fake Identity & Document Screening System',version='1.2.0'); pipeline=FraudPipeline(root); attach_rate_limit(app,pipeline.config['api']['rate_limit_per_minute'],pipeline.config['max_file_bytes']); app.include_router(make_router(pipeline)); return app
app=create_app()
