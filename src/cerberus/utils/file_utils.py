"""Utilities for efficient file operations."""

from collections.abc import Iterator
from pathlib import Path


def read_chunks(file_path: Path, chunk_size: int = 65536) -> Iterator[bytes]:
    """Yield file chunks without loading entire file into memory.

    Args:
        file_path: Path to the file to read.
        chunk_size: Size of each chunk in bytes. Default 65536 (64KB).

    Yields:
        Chunks of bytes from the file.

    Raises:
        FileNotFoundError: If the file does not exist.
        PermissionError: If the file cannot be read due to permissions.
        IsADirectoryError: If the provided path is a directory.

    Example:
        >>> for chunk in read_chunks(Path("/tmp/large_file.bin")):
        ...     process(chunk)
    """
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            yield chunk
