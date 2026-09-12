from __future__ import annotations
import argparse,json
from pathlib import Path
from core.pipeline import FraudPipeline
from security.audit import configure_logging
ROOT=Path(__file__).resolve().parent
def main():
    configure_logging(); p=argparse.ArgumentParser(description='AI-Based Fake Identity & Document Screening System')
    sub=p.add_subparsers(dest='command',required=True); s=sub.add_parser('screen');s.add_argument('file');s.add_argument('--identity-key');s.add_argument('--reference-face');s.add_argument('--live-selfie',help='Separate newly captured selfie image for PAD/liveness analysis');s.add_argument('--fast',action='store_true',help='Defer deepfake model for rapid initial triage'); f=sub.add_parser('screen-folder',help='Screen all supported document images in one folder');f.add_argument('folder');f.add_argument('--identity-key-prefix');f.add_argument('--full-deepfake',action='store_true',help='Run the CPU-heavy deepfake model on every file');f.add_argument('--limit',type=int,help='Process only the first N supported files'); sub.add_parser('self-test'); a=sub.add_parser('serve');a.add_argument('--host',default='127.0.0.1');a.add_argument('--port',type=int,default=8000); r=sub.add_parser('purge-retention');r.add_argument('--days',type=int)
    args=p.parse_args(); pipe=FraudPipeline(ROOT)
    if args.command=='screen':print(json.dumps(pipe.screen(args.file,args.identity_key,reference_face_path=args.reference_face,live_selfie_path=args.live_selfie,analysis_mode='fast' if args.fast else 'full'),indent=2))
    elif args.command=='screen-folder': print(json.dumps(pipe.screen_folder(args.folder,args.identity_key_prefix,analysis_mode='full' if args.full_deepfake else 'fast',limit=args.limit),indent=2))
    elif args.command=='self-test':print(json.dumps(pipe.self_test(),indent=2))
    elif args.command=='purge-retention':
        days=args.days if args.days is not None else pipe.config['retention_days']
        if days<1: p.error('--days must be at least 1')
        print(json.dumps(pipe.repo.purge_expired(days),indent=2))
    else:
        local_hosts={"127.0.0.1","localhost","::1"}
        if args.host not in local_hosts and not pipe.config["api"].get("require_api_key"):
            p.error("Refusing non-localhost binding while api.require_api_key is false. Enable API-key protection first.")
        import uvicorn;uvicorn.run('api.app:app',host=args.host,port=args.port,reload=False)
if __name__=='__main__':main()
