from PIL import Image
from core.pipeline import FraudPipeline
def test_cross_identity_reuse_is_detected(tmp_path,pipeline_root):
    p=tmp_path/'doc.png';Image.new('RGB',(600,400),'white').save(p);pipe=FraudPipeline(pipeline_root);pipe.screen(p,'one');r=pipe.screen(p,'two');assert any(e['signal']=='exact_artifact_cross_identity_reuse' for e in r['evidence'])
