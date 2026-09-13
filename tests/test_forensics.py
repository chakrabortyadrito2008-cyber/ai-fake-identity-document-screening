from types import SimpleNamespace

import numpy as np
from PIL import Image

from modules.forensics import Forensics


def test_forensics_contract():
    assert Forensics.name == 'forensics'


def _context(path, image):
    return SimpleNamespace(path=path, preprocessed=image, config={"features": {"forensics": True}})


def _noisy_image(seed=7):
    rng = np.random.default_rng(seed)
    return (rng.random((600, 800, 3)) * 255).astype("uint8")


def test_clean_image_has_no_forensic_signal(tmp_path):
    path = tmp_path / "clean.png"
    image = _noisy_image()
    Image.fromarray(image).save(path)
    result = Forensics().analyse(_context(path, image))[0]
    assert result.status.value == "NOT_DETECTED"


def test_editing_software_exif_is_detected(tmp_path):
    path = tmp_path / "edited.jpg"
    image = _noisy_image()
    pil = Image.fromarray(image)
    exif = pil.getexif()
    exif[0x0131] = "Adobe Photoshop 25.0"          # Software tag
    exif[0x9286] = "Rendered by Stable Diffusion"  # UserComment tag
    pil.save(path, exif=exif, quality=95)
    result = Forensics().analyse(_context(path, image))[0]
    assert result.status.value == "DETECTED"
    kinds = {marker["kind"] for marker in result.value["metadata_markers"]}
    assert "editing_software" in kinds
    assert "ai_generator" in kinds
    assert result.value["indicators"]["metadata_editing_or_ai_markers"] is True


def test_ai_generator_metadata_alone_is_detected(tmp_path):
    path = tmp_path / "generated.jpg"
    image = _noisy_image(seed=11)
    pil = Image.fromarray(image)
    exif = pil.getexif()
    exif[0x0131] = "Midjourney"
    pil.save(path, exif=exif, quality=95)
    result = Forensics().analyse(_context(path, image))[0]
    assert result.status.value == "DETECTED"
    kinds = {marker["kind"] for marker in result.value["metadata_markers"]}
    assert "ai_generator" in kinds
