"""JSON rapor üretici."""

import json
from typing import Any, Dict, Optional


def generate(
    result: Dict[str, Any],
    output_path: Optional[str] = None,
    indent: int = 2,
) -> str:
    """
    Analiz sonucunu JSON string olarak döndürür ve isteğe bağlı olarak dosyaya yazar.

    Parameters
    ----------
    result      : LogAnalyzer.analyze() çıktısı.
    output_path : Dosyaya yazılacaksa yol (None → yalnızca string döndür).
    indent      : JSON girintisi.
    """
    output = json.dumps(result, ensure_ascii=False, indent=indent, default=str)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(output)
        print(f"[✓] JSON raporu yazıldı: {output_path}")

    return output
