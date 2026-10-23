"""
Shared pytest configuration.

Points the metadata layer at a throwaway JSON store *before* any server module is
imported, so the test suite never touches a developer's real MongoDB data.
"""

import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="tessera-tests-")
os.environ["METADATA_BACKEND"] = "local"
os.environ["LOCAL_METADATA_PATH"] = os.path.join(_tmp, "metadata.json")
os.environ.setdefault("LOCAL_STORAGE_DIR", os.path.join(_tmp, "blobs"))
os.environ.setdefault("ABE_MODE", "simulated")
