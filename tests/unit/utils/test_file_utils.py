"""Unit tests for file utilities."""

from pathlib import Path

import pytest

from cerberus.utils import read_chunks


class TestFileUtilsReadChunks:
    """Test read_chunks function."""

    def _create_temp_file(self, tmp_path: Path, content: bytes) -> Path:
        """Create a temporary file with specified byte content.

        Args:
            tmp_path: pytest tmp_path fixture
            content: bytes to write to file

        Returns:
            Path to the created file
        """
        file_path = tmp_path / "test.txt"
        file_path.write_bytes(content)
        return file_path

    def test_read_chunks_yields_correct_chunks(self, tmp_path):
        """Test read_chunks yields correct file chunks."""
        content = b"A" * (10 * 1024 * 1024)
        chunk_size = 1024 * 1024  # 1MB chunk size
        file = self._create_temp_file(tmp_path, content)

        chunks = list(read_chunks(file, chunk_size))
        assert content == b"".join(chunks)
        assert 10 == len(chunks)

    def test_read_chunks_small_file(self, tmp_path):
        """Test read_chunks on a small file smaller than chunk size."""
        content = b"Hello, World!"
        file = self._create_temp_file(tmp_path, content)

        chunks = list(read_chunks(file))
        assert content == b"".join(chunks)

    def test_read_chunks_empty_file(self, tmp_path):
        """Test read_chunks on an empty file."""
        content = b""
        file = self._create_temp_file(tmp_path, content)

        chunks = list(read_chunks(file))
        assert content == b"".join(chunks)

    def test_read_chunks_non_existent_file(self):
        """Test read_chunks on a file that doesn't exist."""
        file = Path("non_existent_file")

        with pytest.raises(FileNotFoundError):
            list(read_chunks(file))
