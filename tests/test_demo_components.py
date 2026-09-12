from pathlib import Path

from PIL import Image, ImageDraw

from core.pipeline import FraudPipeline


def test_demo_registry_and_anomaly_baseline_are_operational(tmp_path: Path):
    root = Path(__file__).parents[1]
    image = Image.new("RGB", (900, 600), (180, 180, 180))
    draw = ImageDraw.Draw(image)
    draw.rectangle((50, 50, 850, 550), fill=(245, 245, 245), outline=(0, 0, 0), width=4)
    draw.text((110, 120), "DEMO DOCUMENT 123456789", fill=(0, 0, 0), stroke_width=1)
    for y in range(210, 500, 22): draw.line((110, y, 760, y), fill=(80, 80, 80), width=2)
    path = tmp_path / "document.png"; image.save(path)
    result = FraudPipeline(root).screen(path, "demo-legitimate-001")
    by_detector = {entry["detector"]: entry for entry in result["evidence"]}
    assert by_detector["trusted_source"]["value"] == "MATCH"
    assert by_detector["trusted_source"]["details"]["demo_only"] is True
    assert by_detector["anomaly_detection"]["status"] in {"DETECTED", "NOT_DETECTED"}
    assert by_detector["anomaly_detection"]["value"]["demo_only"] is True
