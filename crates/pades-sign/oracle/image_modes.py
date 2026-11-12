"""Check Pillow image modes accepted by pyHanko's image embedding path."""

import json
import sys

from PIL import Image
from pyhanko.pdf_utils.images import pil_image
from pyhanko.pdf_utils.writer import PdfFileWriter

results = []
for path in sys.argv[1:]:
    with Image.open(path) as image:
        mode = image.mode
        try:
            pil_image(image, PdfFileWriter())
        except Exception as exc:
            results.append({"mode": mode, "accepted": False, "error": type(exc).__name__})
        else:
            results.append({"mode": mode, "accepted": True})
print(json.dumps(results))
