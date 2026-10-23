"""
Local Filesystem Object Storage Provider
Implements Specification Section: §7 (Tech Stack), §8 (Repo Structure)
Implements Objectives: O1 (Confidentiality)

This module implements the ObjectStore interface using the local host filesystem.
It reads and writes binary files inside a configurable directory, serving as the
primary development and testing storage fallback.
"""

import os
from server.storage.base import ObjectStore


class LocalStore(ObjectStore):
    """
    ObjectStore implementation that saves ciphertext bytes to a local directory.
    """

    def __init__(self, base_dir: str = None):
        """
        Initializes the local storage provider.
        
        Args:
            base_dir (str, optional): Base directory for file storage.
                                      Defaults to environment config or './local_storage'.
        """
        if not base_dir:
            base_dir = os.getenv("LOCAL_STORAGE_DIR", "./local_storage")
        
        self.base_dir = os.path.abspath(base_dir)
        
        # Ensure the storage directory exists
        os.makedirs(self.base_dir, exist_ok=True)

    def _get_path(self, key: str) -> str:
        """Helper to get absolute path for a key and prevent directory traversal."""
        # Sanitize key to prevent path traversal (e.g. "../filename")
        clean_key = os.path.basename(key)
        return os.path.join(self.base_dir, clean_key)

    def put(self, key: str, data: bytes) -> bool:
        """
        Writes ciphertext bytes to disk.
        """
        filepath = self._get_path(key)
        try:
            with open(filepath, "wb") as f:
                f.write(data)
            return True
        except Exception:
            return False

    def get(self, key: str) -> bytes:
        """
        Reads ciphertext bytes from disk.
        """
        filepath = self._get_path(key)
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File with ID '{key}' not found in local storage.")
            
        with open(filepath, "rb") as f:
            return f.read()

    def delete(self, key: str) -> bool:
        """
        Deletes ciphertext file from disk.
        """
        filepath = self._get_path(key)
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
                return True
            except Exception:
                return False
        return False
