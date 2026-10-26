"""The S3 backend, against an in-memory stand-in for the boto3 client."""

from __future__ import annotations

import hashlib
import json
import unittest
from datetime import datetime, timedelta, timezone

from redcastle.castle import Castle
from redcastle.config import load_secrets
from redcastle.registry import Status
from redcastle.storage import InvalidKey, ObjectExists
from redcastle.storage.s3 import S3Backend

from .helpers import CastleTestCase


class FakeClientError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeS3:
    """Just enough of an unversioned bucket for the backend."""

    def __init__(self) -> None:
        self.objects: dict[str, tuple[bytes, datetime]] = {}
        self.deleted: list[tuple[str, str | None]] = []

    def put(self, key: str, data: bytes, age_days: int = 7) -> None:
        self.objects[key] = (data, datetime.now(timezone.utc) - timedelta(days=age_days))

    def _get(self, key: str) -> tuple[bytes, datetime]:
        if key not in self.objects:
            raise FakeClientError("404")
        return self.objects[key]

    def head_object(self, Bucket: str, Key: str) -> dict:
        data, modified = self._get(Key)
        return {"ContentLength": len(data), "LastModified": modified, "ETag": f'"{hashlib.md5(data).hexdigest()}"'}

    def put_object(self, Bucket: str, Key: str, Body: bytes) -> dict:
        self.put(Key, Body, age_days=0)
        return {}

    def copy(self, CopySource: dict, Bucket: str, Key: str) -> None:
        self.objects[Key] = self._get(CopySource["Key"])

    def delete_object(self, Bucket: str, Key: str, VersionId: str | None = None) -> dict:
        self.deleted.append((Key, VersionId))
        self.objects.pop(Key, None)
        return {}

    def get_paginator(self, name: str) -> FakePaginator:
        return FakePaginator(self, name)


class FakePaginator:
    def __init__(self, s3: FakeS3, name: str) -> None:
        self.s3, self.name = s3, name

    def paginate(self, Bucket: str, Prefix: str = ""):
        keys = sorted(k for k in self.s3.objects if k.startswith(Prefix))
        if self.name == "list_objects_v2":
            yield {"Contents": [
                {"Key": k, "Size": len(self.s3.objects[k][0]), "LastModified": self.s3.objects[k][1]} for k in keys
            ]}
        else:
            yield {"Versions": [{"Key": k, "VersionId": "null"} for k in keys]}


class S3BackendTests(unittest.TestCase):
    def setUp(self) -> None:
        self.s3 = FakeS3()
        self.backend = S3Backend(self.s3, "bucket", prefix="realm")
        self.executioner = S3Backend(self.s3, "bucket", prefix="realm", can_purge=True)

    def test_listing_hides_quarantine_and_strips_prefix(self) -> None:
        self.s3.put("realm/a.txt", b"a")
        self.s3.put("elsewhere/b.txt", b"b")
        location = self.backend.hide("a.txt", "rc-1")
        self.assertEqual(self.backend.list_objects(), [])
        self.s3.put("realm/c.txt", b"c")
        self.assertEqual([o.key for o in self.backend.list_objects()], ["c.txt"])
        self.assertIn(json.loads(location)["q"], self.s3.objects)

    def test_hide_unhide_and_purge(self) -> None:
        self.s3.put("realm/a.txt", b"hello")
        location = self.backend.hide("a.txt", "rc-1")
        self.assertIsNone(self.backend.stat("a.txt"))
        self.assertTrue(self.backend.quarantined_checksum(location).startswith("etag:"))
        self.backend.unhide(location, "a.txt")
        self.assertEqual(self.s3.objects["realm/a.txt"][0], b"hello")

        location = self.backend.hide("a.txt", "rc-2")
        with self.assertRaises(PermissionError):
            self.backend.purge(location)
        self.executioner.purge(location)
        self.assertIsNone(self.backend.quarantined_checksum(location))

    def test_unhide_refuses_to_overwrite(self) -> None:
        self.s3.put("realm/a.txt", b"old")
        location = self.backend.hide("a.txt", "rc-1")
        self.s3.put("realm/a.txt", b"new")
        with self.assertRaises(ObjectExists):
            self.backend.unhide(location, "a.txt")

    def test_quarantine_prefix_is_out_of_reach(self) -> None:
        backend = S3Backend(self.s3, "bucket")
        with self.assertRaises(InvalidKey):
            backend.stat(".redcastle-quarantine/rc-1/a.txt")


class S3CastleTests(CastleTestCase):
    def test_full_flow_on_s3(self) -> None:
        s3 = FakeS3()
        s3.put("old/report.tmp", b"stale")
        config = self.castle.config
        castle = Castle(
            config, load_secrets(config.secrets_path),
            backend=S3Backend(s3, "bucket"), executioner_backend=S3Backend(s3, "bucket", can_purge=True),
            notifier=self.castle.notifier,
        )
        try:
            view = castle.gateway.request_deletion(self.token, "old/report.tmp", "Stale build artefact", 5)
            self.assertEqual(view["status"], Status.QUARANTINED)
            self.assertNotIn("old/report.tmp", s3.objects)
            castle.throne.approve(view["request_id"], by="alice")
            self.assertEqual([k for k in s3.objects], [])
        finally:
            castle.close()


if __name__ == "__main__":
    unittest.main()
