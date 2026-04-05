"""Output sink for captured transaction records.

Provides :class:`JsonLineWriter`, which writes one JSON object per line to
either stdout or a file.  A new file is created (with parent directories)
if a path is supplied; the stream is flushed after every record so that
partial output is not lost on unexpected exit.
"""
import json
import sys
from pathlib import Path
from typing import TextIO

from .models import CaptureRecord


class JsonLineWriter:
    """Writes :class:`~src.models.CaptureRecord` objects as JSON lines.

    Each call to :meth:`write` appends one JSON object (no whitespace) plus a
    newline to the underlying stream and flushes immediately.  When
    *output_path* is ``None`` the writer uses *stdout*; otherwise it creates
    (or truncates) the named file, creating parent directories as needed.

    Use as a context manager to ensure the file is closed on exit.
    """

    def __init__(self, output_path: str | None):
        """Open the output stream.

        Args:
            output_path: File path to write to, or ``None`` for stdout.
        """
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
        """Serialise *record* as a JSON line and flush the stream.

        Args:
            record: Capture record to serialise.
        """
        json.dump(record.as_dict(), self._stream, separators=(",", ":"), sort_keys=True)
        self._stream.write("\n")
        self._stream.flush()

    def close(self):
        """Close the underlying file if one was opened by this instance."""
        if self._should_close:
            self._stream.close()