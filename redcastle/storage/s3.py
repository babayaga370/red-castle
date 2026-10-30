"""S3 backend: the realm is a bucket (optionally a prefix), quarantine is another prefix.

Recommended setup: enable bucket versioning, give the castle credentials that
cannot ``s3:DeleteObjectVersion``, and give only the Executioner's profile
that permission. Then hiding an object only ever adds a delete marker, and
the one irreversible call in the system is made with the Executioner's keys.
"""

from __future__ import annotations

import json
from typing import Any

from ..config import ConfigError
from .base import (
    Backend,
    InvalidKey,
    ObjectExists,
    ObjectInfo,
    ObjectNotFound,
    check_case_id,
    normalize_key,
)


def _not_found(exc: Exception) -> bool:
    code = getattr(exc, "response", {}).get("Error", {}).get("Code")
    return code in {"404", "NoSuchKey", "NotFound"}


def _etag(head: dict) -> str:
    return "etag:" + head["ETag"].strip('"')


class S3Backend(Backend):
    def __init__(
        self,
        client: Any,
        bucket: str,
        *,
        prefix: str = "",
        quarantine_prefix: str = ".redcastle-quarantine/",
        can_purge: bool = False,
    ) -> None:
        super().__init__(can_purge=can_purge)
        if not bucket:
            raise ValueError("The S3 backend needs a bucket ([storage] bucket = ...).")
        if not quarantine_prefix.strip("/"):
            raise ValueError("The S3 backend needs a quarantine prefix ([storage] quarantine_prefix = ...).")
        self.client = client
        self.bucket = bucket
        self.prefix = prefix.strip("/") + "/" if prefix.strip("/") else ""
        self.qprefix = quarantine_prefix.strip("/") + "/"
        if self.prefix and self.qprefix.startswith(self.prefix):
            raise ValueError("The quarantine prefix must not be inside the realm prefix.")

    @classmethod
    def from_config(cls, storage: Any, *, executioner: bool = False) -> S3Backend:
        try:
            import boto3  # optional dependency
        except ImportError as exc:
            raise ConfigError("The S3 backend needs boto3: pip install 'redcastle[s3]'") from exc

        profile = storage.profile
        if executioner and storage.executioner_profile:
            profile = storage.executioner_profile
        session = boto3.Session(profile_name=profile or None, region_name=storage.region or None)
        return cls(
            session.client("s3"),
            storage.bucket,
            prefix=storage.prefix,
            quarantine_prefix=storage.quarantine_prefix,
            can_purge=executioner,
        )

    def _full(self, key: str) -> str:
        full = self.prefix + normalize_key(key)
        if full.startswith(self.qprefix):
            raise InvalidKey(f"'{key}' belongs to the castle's quarantine.")
        return full

    def _qkey(self, key: str, case_id: str) -> str:
        return f"{self.qprefix}{check_case_id(case_id)}/{normalize_key(key)}"

    def _head(self, full_key: str) -> dict | None:
        try:
            return self.client.head_object(Bucket=self.bucket, Key=full_key)
        except Exception as exc:
            if _not_found(exc):
                return None
            raise

    def list_objects(self, prefix: str = "") -> list[ObjectInfo]:
        prefix = prefix.replace("\\", "/").lstrip("/")
        found = []
        paginator = self.client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=self.prefix + prefix):
            for obj in page.get("Contents", []):
                full = obj["Key"]
                if full.startswith(self.qprefix) or full.endswith("/"):
                    continue
                found.append(
                    ObjectInfo(full[len(self.prefix):], obj["Size"], obj["LastModified"].timestamp())
                )
        return sorted(found, key=lambda o: o.key)

    def stat(self, key: str) -> ObjectInfo | None:
        head = self._head(self._full(key))
        if head is None:
            return None
        return ObjectInfo(normalize_key(key), head["ContentLength"], head["LastModified"].timestamp())

    def checksum(self, key: str) -> str | None:
        head = self._head(self._full(key))
        return _etag(head) if head else None

    def write(self, key: str, data: bytes) -> None:
        self.client.put_object(Bucket=self.bucket, Key=self._full(key), Body=data)

    def hide(self, key: str, case_id: str) -> str:
        full = self._full(key)
        head = self._head(full)
        if head is None:
            raise ObjectNotFound(key)
        qkey = self._qkey(key, case_id)
        source = {"Bucket": self.bucket, "Key": full}
        version = head.get("VersionId")
        if version and version != "null":
            source["VersionId"] = version
        self.client.copy(source, self.bucket, qkey)
        try:
            deleted = self.client.delete_object(Bucket=self.bucket, Key=full)
        except Exception:
            self.client.delete_object(Bucket=self.bucket, Key=qkey)  # the original stayed: leave no stray copy
            raise
        location: dict[str, str] = {"q": qkey, "orig": full}
        if version and version != "null":
            location["orig_version"] = version
        if deleted.get("DeleteMarker") and deleted.get("VersionId"):
            location["delete_marker"] = deleted["VersionId"]
        return json.dumps(location, sort_keys=True)

    def unhide(self, location: str, key: str) -> None:
        loc = json.loads(location)
        full = self._full(key)
        if self._head(loc["q"]) is None:
            raise ObjectNotFound(loc["q"])
        if self._head(full) is not None:
            raise ObjectExists(key)
        self.client.copy({"Bucket": self.bucket, "Key": loc["q"]}, self.bucket, full)
        self.client.delete_object(Bucket=self.bucket, Key=loc["q"])

    def find_hidden(self, key: str, case_id: str) -> str | None:
        # Which versions the interrupted hide left behind is lost with it, so a later
        # purge removes only the quarantined copy: too much is kept, never too little.
        qkey = self._qkey(key, case_id)
        if self._head(qkey) is None:
            return None
        return json.dumps({"q": qkey, "orig": self._full(key)}, sort_keys=True)

    def quarantined_checksum(self, location: str) -> str | None:
        head = self._head(json.loads(location)["q"])
        return _etag(head) if head else None

    def _purge(self, location: str) -> None:
        loc = json.loads(location)
        targets: list[tuple[str, str | None]] = []
        paginator = self.client.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=loc["q"]):
            for version in page.get("Versions", []) + page.get("DeleteMarkers", []):
                if version["Key"] == loc["q"]:
                    targets.append((version["Key"], version.get("VersionId")))
        if not targets:
            targets.append((loc["q"], None))
        # In a versioned bucket the original data still lives on as an older
        # version of the original key; destroy exactly the versions we hid.
        if loc.get("orig_version"):
            targets.append((loc["orig"], loc["orig_version"]))
        if loc.get("delete_marker"):
            targets.append((loc["orig"], loc["delete_marker"]))
        for key, version_id in targets:
            kwargs = {"Bucket": self.bucket, "Key": key}
            if version_id:
                kwargs["VersionId"] = version_id
            self.client.delete_object(**kwargs)
