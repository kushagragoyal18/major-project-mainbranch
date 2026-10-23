"""
AWS S3 Object Storage Provider
Implements Specification Section: §4 (Scope), §7 (Tech Stack), §8 (Repo Structure)
Implements Objectives: O1 (Confidentiality)

This module implements the ObjectStore interface for AWS S3 using the boto3 library.
It is configured via environment variables.
"""

import os
import logging
import boto3
from botocore.exceptions import ClientError
from server.storage.base import ObjectStore

logger = logging.getLogger(__name__)


class S3Store(ObjectStore):
    """
    ObjectStore implementation that saves ciphertext bytes to an AWS S3 Bucket.
    """

    def __init__(self):
        """
        Initializes S3 client credentials from environment variables.
        """
        self.bucket_name = os.getenv("S3_BUCKET_NAME", "secure-cloud-storage-bucket")
        self.region = os.getenv("AWS_REGION", "us-east-1")
        
        # Initialize boto3 S3 client
        # In production, boto3 will automatically pick up IAM Roles if credentials are blank
        aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
        aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
        
        if aws_access_key and aws_secret_key:
            self.s3_client = boto3.client(
                "s3",
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=self.region
            )
        else:
            self.s3_client = boto3.client("s3", region_name=self.region)

    def put(self, key: str, data: bytes) -> bool:
        """
        Uploads ciphertext bytes to S3.
        """
        try:
            # SECURITY: Uploading encrypted ciphertext to the bucket.
            # Plaintext data is never sent.
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=key,
                Body=data
            )
            return True
        except ClientError as e:
            logger.error(f"Failed to upload {key} to S3: {e}")
            return False

    def get(self, key: str) -> bytes:
        """
        Downloads ciphertext bytes from S3.
        """
        try:
            response = self.s3_client.get_object(Bucket=self.bucket_name, Key=key)
            return response["Body"].read()
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchKey":
                raise FileNotFoundError(f"File with ID '{key}' not found in S3 bucket.") from e
            logger.error(f"Failed to download {key} from S3: {e}")
            raise IOError(f"AWS S3 read error for key {key}") from e

    def delete(self, key: str) -> bool:
        """
        Deletes object from S3.
        """
        try:
            self.s3_client.delete_object(Bucket=self.bucket_name, Key=key)
            return True
        except ClientError as e:
            logger.error(f"Failed to delete {key} from S3: {e}")
            return False
