from core.pipeline import FraudPipeline

def test_invalid_input_is_not_reported_as_low_risk(tmp_path,pipeline_root):
    bad=tmp_path/'invalid.png'; bad.write_text('not an image')
    result=FraudPipeline(pipeline_root).screen(bad)
    assert result['status']=='INSUFFICIENT EVIDENCE'
