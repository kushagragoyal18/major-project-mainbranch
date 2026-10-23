"""
Object Storage Interface Base Class
Implements Specification Section: §7 (Tech Stack), §8 (Repo Structure)
Implements Objectives: O1 (Confidentiality)

This module defines the abstract interface for the pluggable object storage layers.
By defining a common interface, the application can switch transparently between
local disk storage (for offline development/testing) and cloud services (AWS S3 or Azure Blob).
"""

from abc import ABC, abstractmethod


class ObjectStore(ABC):
    """
    Abstract Base Class defining the contract for storage backends.
    All storage classes must implement put, get, and delete.
    """

    @abstractmethod
    def put(self, key: str, data: bytes) -> bool:
        """
        Stores file bytes in the object store.
        
        Args:
            key (str): Unique identifier for the object (usually a UUID or file ID).
            data (bytes): The raw ciphertext bytes to store.
            
        Returns:
            bool: True if storage succeeded, False otherwise.
        """
        pass

    @abstractmethod
    def get(self, key: str) -> bytes:
        """
        Retrieves file bytes from the object store.
        
        Args:
            key (str): Unique identifier for the object.
            
        Returns:
            bytes: The raw ciphertext bytes.
            
        Raises:
            FileNotFoundError: If the object does not exist.
        """
        pass

    @abstractmethod
    def delete(self, key: str) -> bool:
        """
        Deletes the file bytes from the object store.
        
        Args:
            key (str): Unique identifier for the object.
            
        Returns:
            bool: True if deletion succeeded, False otherwise.
        """
        pass
