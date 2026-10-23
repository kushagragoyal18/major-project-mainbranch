"""
Azure Blob Object Storage Provider
Implements Specification Section: §4 (Scope), §7 (Tech Stack), §8 (Repo Structure)
Implements Objectives: O1 (Confidentiality)

This module implements the ObjectStore interface for Azure Blob Storage.
It is imported pluggably.
"""

import os
import logging
from server.storage.base import ObjectStore

logger = logging.getLogger(__name__)


class AzureStore(ObjectStore):
    """
    ObjectStore implementation that saves ciphertext bytes to an Azure Blob Storage Container.
    """

    def __init__(self):
        """
        Initializes Azure connection using connection strings from environment.
        """
        self.conn_str = os.getenv("AZURE_CONNECTION_STRING")
        self.container_name = os.getenv("AZURE_CONTAINER_NAME", "secure-cloud-storage")
        self.blob_service_client = None
        self.container_client = None

        if self.conn_str:
            try:
                from azure.storage.blob import BlobServiceClient
                self.blob_service_client = BlobServiceClient.from_connection_string(self.conn_str)
                self.container_client = self.blob_service_client.get_container_client(self.container_name)
            except ImportError:
                logger.warning("azure-storage-blob library not installed. AzureStore will be non-functional.")
            except Exception as e:
                logger.error(f"Failed to initialize Azure Blob Service Client: {e}")

    def put(self, key: str, data: bytes) -> bool:
        """
        Uploads ciphertext bytes to Azure Blob.
        """
        if not self.container_client:
            logger.error("Azure Blob Store is not initialized.")
            return False
        try:
            blob_client = self.container_client.get_blob_client(key)
            # SECURITY: Uploading ciphertext bytes only.
            blob_client.upload_blob(data, overwrite=True)
            return True
        except Exception as e:
            logger.error(f"Failed to upload {key} to Azure: {e}")
            return False

    def get(self, key: str) -> bytes:
        """
        Downloads ciphertext bytes from Azure Blob.
        """
        if not self.container_client:
            raise IOError("Azure Blob Store is not initialized.")
        try:
            blob_client = self.container_client.get_blob_client(key)
            download_stream = blob_client.download_blob()
            return download_stream.readall()
        except Exception as e:
            logger.error(f"Failed to download {key} from Azure: {e}")
            raise FileNotFoundError(f"File with ID '{key}' not found in Azure Storage.") from e

    def delete(self, key: str) -> bool:
        """
        Deletes blob from Azure container.
        """
        if not self.container_client:
            logger.error("Azure Blob Store is not initialized.")
            return False
        try:
            blob_client = self.container_client.get_blob_client(key)
            blob_client.delete_blob()
            return True
        except Exception as e:
            logger.error(f"Failed to delete {key} from Azure: {e}")
            return False
