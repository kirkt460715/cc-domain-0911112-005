import hashlib
from pathlib import Path
from ..validation import (
    name,
    object_value,
    list_value,
    integer,
    canonical,
    digest,
    parse_json,
    reject,
    VaultError,
)
from ..catalog.registry import CLASSIFICATIONS

MANIFEST = "manifest.ready"
FORMATS = {".csv": "csv", ".jsonl": "jsonl"}


class Unstable(Exception):
    """成员文件在读取期间被替换，本次扫描跳过，下轮重试。"""


def checksum(value):
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(c not in "0123456789abcdef" for c in value)
    ):
        reject("input", "delivery member checksum must be SHA256 hex")
    return value


class DeliveryInbox:
    """按 manifest.ready 认领仪器投递，组内校验后登记到现有目录。

    状态机：claimed（已认领，处理中或崩溃残留）→ registered（整组登记完成）
    或 quarantined（确定性失败，隔离可追踪）。manifest.ready 未出现的目录
    视为尚未传完（pending），不算失败。投递目录只读，任何结果都不删原文件。
    """

    def __init__(self, database, registry, ingestion):
        self.db = database
        self.registry = registry
        self.ingestion = ingestion
        with database.transaction() as con:
            con.execute("""CREATE TABLE IF NOT EXISTS deliveries(
                id TEXT NOT NULL,digest TEXT NOT NULL,state TEXT NOT NULL,
                payload TEXT NOT NULL,PRIMARY KEY(id,digest))""")

    def scan(self, root, classification="internal", scopes=None):
        root = Path(root)
        if root.is_symlink() or not root.is_dir():
            reject("path", "delivery root must be a regular directory")
        if classification not in CLASSIFICATIONS:
            reject("input", "unknown data classification")
        if scopes is None:
            scopes = ["research"]
        scopes = sorted({name(scope) for scope in list_value(scopes, 1, 100)})
        if (root / MANIFEST).is_file() or (root / MANIFEST).is_symlink():
            targets = [root]
        else:
            targets = [
                child
                for child in sorted(root.iterdir())
                if child.is_dir() and not child.is_symlink()
            ] or [root]
        groups, pending = [], []
        for target in targets:
            manifest = target / MANIFEST
            if manifest.is_symlink() or not manifest.is_file():
                pending.append(target.name)
                continue
            groups.append(self._scan_group(target, classification, scopes))
        return {"root": str(root), "pending": pending, "groups": groups}

    def list(self):
        return [
            self._record(row)
            for row in self.db.rows("SELECT * FROM deliveries ORDER BY id,digest")
        ]

    def get(self, delivery):
        name(delivery)
        rows = self.db.rows(
            "SELECT * FROM deliveries WHERE id=? ORDER BY digest", (delivery,)
        )
        if not rows:
            reject("missing", "delivery not found")
        return [self._record(row) for row in rows]

    @staticmethod
    def _record(row):
        return {
            "id": row["id"],
            "digest": row["digest"],
            "state": row["state"],
            "payload": parse_json(row["payload"]),
        }

    def _scan_group(self, directory, classification, scopes):
        try:
            manifest = self._read_manifest(directory / MANIFEST)
            if not isinstance(manifest, dict) or "delivery_id" not in manifest:
                reject("input", "delivery manifest requires delivery_id")
            delivery = name(manifest["delivery_id"])
        except VaultError as exc:
            with self.db.transaction():
                self.db.audit(
                    "delivery_invalid", directory.name, {"error": exc.as_dict()}
                )
            return {
                "directory": directory.name,
                "state": "invalid",
                "error": exc.as_dict(),
            }
        fingerprint = digest(manifest)
        record = self.db.one(
            "SELECT * FROM deliveries WHERE id=? AND digest=?",
            (delivery, fingerprint),
        )
        if record is not None:
            payload = parse_json(record["payload"])
            if record["state"] == "registered":
                return {
                    "delivery": delivery,
                    "state": "registered",
                    "reused": True,
                    **payload,
                }
            if record["state"] == "quarantined":
                return {
                    "delivery": delivery,
                    "state": "quarantined",
                    "reused": True,
                    **payload,
                }
        else:
            sibling = self.db.one(
                "SELECT state FROM deliveries WHERE id=?", (delivery,)
            )
            if sibling is not None:
                return self._quarantine(
                    delivery,
                    fingerprint,
                    {
                        "code": "conflict",
                        "message": "delivery id republished with different content",
                    },
                )
            with self.db.transaction() as con:
                con.execute(
                    "INSERT INTO deliveries VALUES(?,?,'claimed',?)",
                    (delivery, fingerprint, canonical({})),
                )
                self.db.audit("delivery_claimed", delivery, {"digest": fingerprint})
        try:
            members = self._register(
                directory, delivery, manifest, classification, scopes
            )
        except Unstable:
            return {"delivery": delivery, "state": "unstable"}
        except VaultError as exc:
            return self._quarantine(delivery, fingerprint, exc.as_dict())
        payload = {"members": members}
        with self.db.transaction() as con:
            con.execute(
                "UPDATE deliveries SET state='registered',payload=? WHERE id=? AND digest=?",
                (canonical(payload), delivery, fingerprint),
            )
            self.db.audit("delivery_registered", delivery, payload)
        return {
            "delivery": delivery,
            "state": "registered",
            "reused": False,
            "members": members,
        }

    def _quarantine(self, delivery, fingerprint, reason):
        payload = {"reason": reason}
        with self.db.transaction() as con:
            con.execute(
                """INSERT INTO deliveries(id,digest,state,payload) VALUES(?,?,'quarantined',?)
                   ON CONFLICT(id,digest) DO UPDATE SET state='quarantined',payload=excluded.payload""",
                (delivery, fingerprint, canonical(payload)),
            )
            self.db.audit(
                "delivery_quarantined",
                delivery,
                {"digest": fingerprint, "reason": reason},
            )
        return {"delivery": delivery, "state": "quarantined", "reason": reason}

    def _read_manifest(self, path):
        if (
            path.is_symlink()
            or not path.is_file()
            or path.stat().st_size > 16000000
        ):
            reject("integrity", "delivery manifest is not a bounded regular file")
        return parse_json(path.read_bytes())

    def _members(self, manifest):
        object_value(
            manifest,
            {"delivery_id", "classification", "scopes", "members"},
            {"delivery_id", "members"},
        )
        items = list_value(manifest["members"], 1, 100)
        members, datasets, paths = [], set(), set()
        for item in items:
            object_value(
                item,
                {
                    "path",
                    "dataset",
                    "schema_version",
                    "expected_version",
                    "bytes",
                    "sha256",
                    "rows",
                    "depends_on",
                },
                {
                    "path",
                    "dataset",
                    "schema_version",
                    "expected_version",
                    "bytes",
                    "sha256",
                    "rows",
                },
            )
            dataset = name(item["dataset"])
            if dataset in datasets:
                reject("input", "duplicate dataset in delivery", dataset=dataset)
            datasets.add(dataset)
            relative = item["path"]
            if (
                not isinstance(relative, str)
                or not relative
                or len(relative) > 512
                or "\x00" in relative
            ):
                reject("input", "delivery member path must be bounded text")
            if relative in paths:
                reject("input", "duplicate path in delivery", path=relative)
            paths.add(relative)
            depends_on = [
                name(entry)
                for entry in list_value(item.get("depends_on", []), 0, 16)
            ]
            if len(set(depends_on)) != len(depends_on):
                reject("input", "duplicate dependency in delivery member")
            members.append(
                {
                    "path": relative,
                    "dataset": dataset,
                    "schema_version": integer(item["schema_version"], 1, 100000),
                    "expected_version": integer(item["expected_version"], 0),
                    "bytes": integer(item["bytes"], 0, 32000000),
                    "sha256": checksum(item["sha256"]),
                    "rows": integer(item["rows"], 0, 100000),
                    "depends_on": depends_on,
                }
            )
        known = {member["dataset"] for member in members}
        for member in members:
            for dependency in member["depends_on"]:
                if dependency not in known:
                    reject(
                        "input",
                        "delivery dependency not in group",
                        dataset=member["dataset"],
                        dependency=dependency,
                    )
                if dependency == member["dataset"]:
                    reject("input", "delivery member cannot depend on itself")
        ordered, done, remaining = [], set(), list(members)
        while remaining:
            ready = [
                member
                for member in remaining
                if all(dependency in done for dependency in member["depends_on"])
            ]
            if not ready:
                reject("input", "delivery dependencies form a cycle")
            for member in ready:
                ordered.append(member)
                done.add(member["dataset"])
            remaining = [
                member for member in remaining if member["dataset"] not in done
            ]
        return ordered

    def _member_path(self, root, relative):
        candidate = Path(relative)
        if candidate.is_absolute() or ".." in candidate.parts:
            reject(
                "path", "delivery member path escapes delivery root", path=relative
            )
        full = root / candidate
        if full.is_symlink():
            reject(
                "path", "delivery member cannot be a symbolic link", path=relative
            )
        if not full.is_file():
            reject("missing", "delivery member file unavailable", path=relative)
        if not full.resolve().is_relative_to(root):
            reject(
                "path", "delivery member path escapes delivery root", path=relative
            )
        return full

    def _signature(self, path):
        info = path.stat()
        return (info.st_ino, info.st_size, info.st_mtime_ns)

    def _read_stable(self, path, attempts=3):
        for _ in range(attempts):
            try:
                before = self._signature(path)
                content = path.read_bytes()
                after = self._signature(path)
            except OSError:
                continue
            if before == after:
                if len(content) > 32000000:
                    reject("input", "delivery member exceeds size limit")
                return content
        raise Unstable(path)

    def _register(self, directory, delivery, manifest, classification, scopes):
        members = self._members(manifest)
        if "classification" in manifest:
            classification = manifest["classification"]
            if classification not in CLASSIFICATIONS:
                reject("input", "unknown data classification")
        if "scopes" in manifest:
            scopes = sorted(
                {name(scope) for scope in list_value(manifest["scopes"], 1, 100)}
            )
        root = directory.resolve()
        loaded = []
        for member in members:
            path = self._member_path(root, member["path"])
            content = self._read_stable(path)
            if len(content) != member["bytes"]:
                reject(
                    "integrity",
                    "delivery member length differs",
                    path=member["path"],
                )
            if hashlib.sha256(content).hexdigest() != member["sha256"]:
                reject(
                    "integrity",
                    "delivery member digest differs",
                    path=member["path"],
                )
            format_name = FORMATS.get(Path(member["path"]).suffix.lower())
            if format_name is None:
                reject(
                    "input",
                    "delivery member format unsupported",
                    path=member["path"],
                )
            loaded.append((member, content, format_name))
        results = {}
        with self.db.transaction():
            for member, content, format_name in loaded:
                parents = [
                    {"dataset": parent, "version": results[parent]["version"]}
                    for parent in member["depends_on"]
                ]
                request_id = delivery + "." + member["dataset"]
                if len(request_id) > 100:
                    request_id = (
                        "delivery-" + digest([delivery, member["dataset"]])[:48]
                    )
                result = self.ingestion.ingest(
                    request_id,
                    member["dataset"],
                    member["schema_version"],
                    content,
                    format_name,
                    classification,
                    scopes,
                    parents=parents,
                    metadata={"delivery": delivery},
                    expected_version=member["expected_version"],
                )
                if result["rows"] != member["rows"]:
                    reject(
                        "integrity",
                        "delivery member row count differs",
                        path=member["path"],
                    )
                results[member["dataset"]] = result
        return [
            {"dataset": member["dataset"], **results[member["dataset"]]}
            for member in members
        ]
