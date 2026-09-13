from PIL import Image
from core.pipeline import FraudPipeline

def test_cross_identity_reuse_is_detected(tmp_path,pipeline_root):
    p=tmp_path/'doc.png';Image.new('RGB',(600,400),'white').save(p);pipe=FraudPipeline(pipeline_root);pipe.screen(p,'one');r=pipe.screen(p,'two');assert any(e['signal']=='exact_artifact_cross_identity_reuse' for e in r['evidence'])

def test_same_identity_rescreen_is_not_fraud(tmp_path,pipeline_root):
    """Q2: the same person re-screening the same document is a legitimate recheck."""
    p=tmp_path/'doc.png';Image.new('RGB',(600,400),(180,180,180)).save(p);pipe=FraudPipeline(pipeline_root)
    first=pipe.screen(p,'one'); second=pipe.screen(p,'one')
    assert first['triage']['code']=='LIKELY_GENUINE'
    signals={e['signal'] for e in second['evidence'] if e['status']=='DETECTED' and e['detector']=='provenance'}
    assert 'exact_artifact_cross_identity_reuse' not in signals
    assert second['triage']['code']=='LIKELY_GENUINE'

def test_silent_resubmission_without_identity_is_flagged(tmp_path,pipeline_root):
    """Q2 variant: same file again with NO identity key breaks the audit chain."""
    p=tmp_path/'doc.png';Image.new('RGB',(600,400),(180,180,180)).save(p);pipe=FraudPipeline(pipeline_root)
    pipe.screen(p,'one'); r=pipe.screen(p)
    assert any(e['signal']=='silent_artifact_resubmission' for e in r['evidence'])
    assert r['triage']['code']=='LIKELY_FAKE'

def test_near_duplicate_with_invisible_difference_is_caught(tmp_path,pipeline_root):
    """Q3: same document with an invisible pixel edit must not screen as clean."""
    from PIL import ImageDraw
    p1=tmp_path/'original.png'; img=Image.new('RGB',(600,400),(245,245,245)); d=ImageDraw.Draw(img)
    d.rectangle((40,40,560,360),outline=(0,0,0),width=3); d.text((60,60),'AADHAAR 234567891238',fill=(0,0,0)); img.save(p1)
    p2=tmp_path/'tampered.png'; img2=Image.new('RGB',(600,400),(245,245,245)); d2=ImageDraw.Draw(img2)
    d2.rectangle((40,40,560,360),outline=(0,0,0),width=3); d2.text((60,60),'AADHAAR 234567891238',fill=(0,0,0))
    px=img2.load(); px[300,200]=(244,245,246)  # single invisible pixel
    img2.save(p2)
    pipe=FraudPipeline(pipeline_root)
    pipe.screen(p1,'legit-holder')
    r=pipe.screen(p2,'fraudster')
    signals={e['signal'] for e in r['evidence'] if e['status']=='DETECTED' and e['detector'] in {'provenance','artifact_intelligence'}}
    assert signals & {'near_duplicate_artifact','near_duplicate_cluster'}, f'expected near-duplicate evidence, got {signals}'
