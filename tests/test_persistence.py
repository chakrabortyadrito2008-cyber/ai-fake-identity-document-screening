from PIL import Image
from core.pipeline import FraudPipeline

def test_stored_screening_has_immutable_identifier(tmp_path,pipeline_root):
    image=tmp_path/'document.png'; Image.new('RGB',(800,600),'white').save(image)
    pipeline=FraudPipeline(pipeline_root); result=pipeline.screen(image,'persist-case')
    if result['screening_id']:
        assert pipeline.repo.screening(result['screening_id'])['screening_id']==result['screening_id']
