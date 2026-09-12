from PIL import Image
from core.pipeline import FraudPipeline
def test_rejects_text_file(tmp_path,pipeline_root):
    p=tmp_path/'bad.txt';p.write_text('not image');r=FraudPipeline(pipeline_root).screen(p);assert any(e['error_category']=='UNSUPPORTED_EXTENSION' for e in r['evidence'])
def test_accepts_png(tmp_path,pipeline_root):
    p=tmp_path/'good.png';Image.new('RGB',(600,400),'white').save(p);r=FraudPipeline(pipeline_root).screen(p);assert 'status' in r
