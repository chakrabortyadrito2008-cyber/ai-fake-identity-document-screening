def test_deepfake_detector_is_a_real_model_integration():
    from modules.deepfake_detection import DeepfakeDetection
    assert DeepfakeDetection.name == 'deepfake_detection'

def test_deepfake_runtime_session_is_reused(monkeypatch):
    import modules.deepfake_detection as detection
    detection._session.cache_clear()
    calls=[]
    monkeypatch.setattr(detection.ort, "InferenceSession", lambda path, providers: calls.append(path) or object())
    assert detection._session("model.onnx") is detection._session("model.onnx")
    assert calls == ["model.onnx"]
