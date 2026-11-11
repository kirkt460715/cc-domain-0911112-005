import hashlib
import tempfile
from pathlib import Path
from .service import Vault
from .validation import canonical
from .releases.exporter import verify_directory


def demonstrate():
    with tempfile.TemporaryDirectory() as directory:
        with Vault(Path(directory) / "vault") as vault:
            schema = {
                "id": "measurements",
                "version": 1,
                "fields": [
                    {"name": "id", "type": "text"},
                    {"name": "pressure", "type": "decimal", "minimum": "0"},
                ],
                "primary_key": ["id"],
            }
            vault.registry.add_schema(schema)
            vault.registry.register(
                "trial", "Synthetic trial measurements", "measurements", "operator"
            )
            content = (
                canonical({"id": "sample-A", "pressure": "12.5"})
                + "\n"
                + canonical({"id": "sample-B", "pressure": "13"})
                + "\n"
            ).encode()
            ingested = vault.ingestion.ingest(
                "request", "trial", 1, content, "jsonl", "internal", ["research"]
            )
            vault.releases.plan(
                "release", [{"dataset": "trial", "version": 1}], "research", "internal"
            )
            vault.releases.approve(
                "release", 1, "independent-reviewer", "Synthetic dataset verified"
            )
            exported = vault.exporter.export(
                "export", "release", Path(directory) / "release"
            )
            verified = verify_directory(Path(directory) / "release")
            inbox = Path(directory) / "inbox"
            inbox.mkdir()
            member = b"id,pressure\nsample-C,14\n"
            (inbox / "trial.csv").write_bytes(member[:10])
            pending = vault.deliveries.scan(inbox)
            (inbox / "trial.csv").write_bytes(member)
            manifest = {
                "delivery_id": "demo-delivery",
                "members": [
                    {
                        "path": "trial.csv",
                        "dataset": "trial",
                        "schema_version": 1,
                        "expected_version": 1,
                        "bytes": len(member),
                        "sha256": hashlib.sha256(member).hexdigest(),
                        "rows": 1,
                        "depends_on": [],
                    }
                ],
            }
            (inbox / "manifest.ready").write_bytes(canonical(manifest).encode())
            delivered = vault.deliveries.scan(inbox)
            rescanned = vault.deliveries.scan(inbox)
            conflicting = dict(manifest, members=[dict(manifest["members"][0], rows=9)])
            (inbox / "manifest.ready").write_bytes(canonical(conflicting).encode())
            isolated = vault.deliveries.scan(inbox)
            assert pending["pending"] == ["inbox"] and not pending["groups"]
            assert delivered["groups"][0]["state"] == "registered"
            assert delivered["groups"][0]["members"][0]["version"] == 2
            assert rescanned["groups"][0]["reused"]
            assert isolated["groups"][0]["state"] == "quarantined"
            assert (inbox / "trial.csv").read_bytes() == member
            assert ingested["rows"] == 2
            assert verified["rows"] == 2
            assert exported["state"] == "complete"
            return {
                "ingestion": ingested,
                "export": exported,
                "verification": verified,
                "delivery": delivered["groups"][0],
                "integrity": vault.checks.inspect(),
            }
