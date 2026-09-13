import shutil
import tempfile
import json
from pathlib import Path
from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from security.authentication import api_key_guard
from api.enterprise_ui import dashboard
def make_router(pipeline):
    router=APIRouter(dependencies=[Depends(api_key_guard(pipeline.config["api"]["require_api_key"]))])
    def process_upload(upload: UploadFile, identity_key: str | None, request_id: str, live_selfie: UploadFile | None = None):
        suffix=Path(upload.filename or "").suffix.lower()
        if suffix not in pipeline.config["supported_extensions"]: raise HTTPException(400,"Unsupported file extension")
        if identity_key and (len(identity_key)>128 or any(ord(char)<32 for char in identity_key)): raise HTTPException(400,"Invalid identity key")
        folder=None
        try:
            data=upload.file.read(pipeline.config["max_file_bytes"]+1)
            if len(data)>pipeline.config["max_file_bytes"]: raise HTTPException(413,"File exceeds configured size limit")
            folder=Path(tempfile.mkdtemp(prefix="fraud-upload-")); path=folder/("upload"+suffix); path.write_bytes(data)
            live_path=None
            if live_selfie is not None and live_selfie.filename:
                live_suffix=Path(live_selfie.filename).suffix.lower()
                if live_suffix not in pipeline.config["supported_extensions"]: raise HTTPException(400,"Unsupported live-selfie file extension")
                live_data=live_selfie.file.read(pipeline.config["max_file_bytes"]+1)
                if len(live_data)>pipeline.config["max_file_bytes"]: raise HTTPException(413,"Live-selfie file exceeds configured size limit")
                live_path=folder/("live_selfie"+live_suffix); live_path.write_bytes(live_data)
            result=pipeline.screen(path,identity_key,request_id,live_selfie_path=live_path)
            errors=[e for e in result["evidence"] if e["status"]=="ERROR"]
            if errors: raise HTTPException(400,detail={"errors":[e.get("error_category","invalid input") for e in errors]})
            return result
        finally:
            try: upload.file.close()
            except Exception: _closed = False
            try:
                if live_selfie is not None: live_selfie.file.close()
            except Exception: _closed_live = False
            if folder: shutil.rmtree(folder,ignore_errors=True)
    @router.get('/health')
    def health(): return pipeline.self_test()
    @router.get('/about')
    def about():
        path=pipeline.root/'config'/'system_profile.json'
        return json.loads(path.read_text(encoding='utf-8'))
    @router.get('/', include_in_schema=False)
    def web_dashboard(): return dashboard(dashboard_api_key=pipeline.config["api"].get("dashboard_api_key", "") if pipeline.config["api"].get("require_api_key") else "")
    @router.get('/capabilities')
    def capabilities(): return pipeline.capabilities.report()
    @router.get('/models')
    def models(): return pipeline.capabilities.model_manifest_status()
    @router.get('/operations/overview')
    def operations_overview(): return pipeline.repo.operations_overview()
    @router.get('/operations/readiness')
    def operations_readiness(): return pipeline.self_test()["deployment_readiness"]
    @router.get('/review-queue')
    def review_queue(limit: int=100, include_resolved: bool=False): return {"items":pipeline.repo.review_queue(limit,include_resolved)}
    @router.get('/screenings')
    def screenings(verdict: str | None=None, limit: int=100): return pipeline.repo.screenings_page(verdict,limit)
    @router.post('/screen')
    def screen(request: Request, file: UploadFile=File(...), identity_key: str | None=Form(default=None), live_selfie: UploadFile | None=File(default=None)): return process_upload(file,identity_key,request.state.request_id,live_selfie)
    @router.post('/screen/batch')
    def batch(request: Request, files: list[UploadFile]=File(...), identity_key: str | None=Form(default=None), identity_keys_json: str | None=Form(default=None)):
        # max_batch_size == 0 means unlimited; a positive cap still works for
        # operators who want to bound one request's memory usage.
        batch_limit=pipeline.config["api"].get("max_batch_size",0)
        if batch_limit and len(files)>batch_limit: raise HTTPException(413,"Batch exceeds configured item limit")
        keys=[identity_key]*len(files)
        if identity_keys_json:
            try: keys=json.loads(identity_keys_json)
            except json.JSONDecodeError as exc: raise HTTPException(400,"identity_keys_json must be a JSON array") from exc
            if not isinstance(keys,list) or len(keys)!=len(files) or any(key is not None and not isinstance(key,str) for key in keys): raise HTTPException(400,"identity_keys_json must align with uploaded files")
        if any(key and (len(key)>128 or any(ord(char)<32 for char in key)) for key in keys): raise HTTPException(400,"Invalid identity key")
        results=[]
        for index,(item,key) in enumerate(zip(files,keys)):
            try: results.append(process_upload(item,key,f"{request.state.request_id}:{index}"))
            except HTTPException as exc: results.append({"request_id":f"{request.state.request_id}:{index}","filename":item.filename,"status":"INSUFFICIENT EVIDENCE","error":{"http_status":exc.status_code,"detail":exc.detail}})
        groups={}
        for index,result in enumerate(results): groups.setdefault(result.get("fingerprints",{}).get("sha256"),[]).append(index)
        correlations=[{"kind":"EXACT_ARTIFACT_BATCH_REUSE","result_indexes":indexes,"identity_count":len({keys[i] for i in indexes if keys[i]})} for sha,indexes in groups.items() if sha and len(indexes)>1]
        return {"batch_id":request.state.request_id,"results":results,"batch_correlations":correlations}
    @router.get('/screen/{screening_id}')
    def get_screen(screening_id:str):
        result=pipeline.repo.screening(screening_id)
        if result is None: raise HTTPException(404,'Screening not found')
        return result
    @router.get('/screen/{screening_id}/receipt')
    def receipt(screening_id:str):
        result=pipeline.repo.screening(screening_id)
        if result is None: raise HTTPException(404,'Screening not found')
        return result.get("analysis_receipt", {})
    @router.post('/screen/{screening_id}/review')
    def review(screening_id: str, request: Request, decision: str=Form(...), notes: str=Form(default=""), x_operator_id: str | None=Header(default=None)):
        reviewer=(x_operator_id or "local-operator").strip()
        if not reviewer or len(reviewer)>128 or any(ord(char)<32 for char in reviewer): raise HTTPException(400,"Invalid operator identifier")
        if len(notes)>2000: raise HTTPException(400,"Review notes exceed 2000 characters")
        try: return pipeline.repo.record_review_decision(screening_id,decision.upper(),reviewer,notes.strip(),request.state.request_id)
        except KeyError as exc: raise HTTPException(404,"Screening not found") from exc
        except ValueError as exc: raise HTTPException(400,str(exc)) from exc
    @router.get('/reference/files')
    def reference_files(limit: int=50, offset: int=0):
        """Local-only bridge: list filenames from the configured reference folder.

        Used by the dashboard to stream a folder's documents through the real
        upload form during visible testing sessions. Serves names only — the
        file contents are fetched individually and re-uploaded for screening.
        """
        from database.reference_ingest import resolve_reference_folder
        folder=resolve_reference_folder(pipeline.root,pipeline.config)
        if folder is None: raise HTTPException(404,"No reference folder configured")
        names=sorted(p.name for p in folder.iterdir() if p.is_file())
        offset=max(0,offset); limit=max(1,min(limit,500))
        return {"folder":str(folder),"total":len(names),"files":names[offset:offset+limit]}
    @router.get('/reference/file/{name}')
    def reference_file(name: str):
        """Local-only bridge: download one reference-folder file by name."""
        from database.reference_ingest import resolve_reference_folder
        folder=resolve_reference_folder(pipeline.root,pipeline.config)
        if folder is None: raise HTTPException(404,"No reference folder configured")
        safe=Path(name).name
        path=folder/safe
        if not path.is_file(): raise HTTPException(404,"File not found in reference folder")
        return FileResponse(path, filename=safe)
    @router.get('/history/{sha}')
    def history(sha:str):
        artifact=pipeline.repo.artifact(sha) or {}
        if artifact:
            identities=artifact.pop("identities",[]); artifact["identity_count"]=len(identities)
        return artifact
    @router.get('/identity/{identity}')
    def identity(identity:str): return {"history":pipeline.repo.identity_history(identity)}
    @router.get('/artifact/{sha}')
    def artifact(sha:str): return history(sha)
    return router
