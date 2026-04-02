import json
import sys
from pathlib import Path
from typing import TextIO

from .models import CaptureRecord


class JsonLineWriter:
    def __init__(self, output_path: str | None):
        self._should_close = output_path is not None
        self.path = output_path

        if output_path is None:
            self._stream: TextIO = sys.stdout
            return

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._stream = path.open("w", encoding="utf-8")

    def __enter__(self) -> "JsonLineWriter":
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def write(self, record: CaptureRecord):
        json.dump(record.as_dict(), self._stream, separators=(",", ":"), sort_keys=True)
        self._stream.write("\n")
        self._stream.flush()

    def close(self):
        if self._should_close:
            self._stream.close()