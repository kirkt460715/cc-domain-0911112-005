import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from trialvault.service import Vault
from support import register

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "dropbox"


def fixture_manifest(**changes):
    manifest = json.loads((FIXTURE / "manifest.ready").read_text())
    manifest.update(changes)
    return manifest


class DeliveryInboxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.vault = Vault(self.base / "vault")
        self.addCleanup(self.vault.close)
        register(self.vault, "measurements")
        register(self.vault, "calibration")
        self.inbox = self.base / "inbox"
        self.inbox.mkdir()

    def copy_fixture(self, *names, target=None):
        target = target or self.inbox
        for item in names:
            shutil.copy2(FIXTURE / item, target / item)

    def scan(self, root=None):
        return self.vault.deliveries.scan(root or self.inbox)

    def test_partial_upload_is_pending_then_registers(self):
        self.copy_fixture("measurements.csv")
        half = (FIXTURE / "measurements.csv").read_bytes()[:10]
        (self.inbox / "measurements.csv").write_bytes(half)
        result = self.scan()
        self.assertEqual(result["pending"], ["inbox"])
        self.assertEqual(result["groups"], [])
        self.copy_fixture("measurements.csv", "calibration.jsonl", "readme.md")
        result = self.scan()
        self.assertEqual(result["pending"], ["inbox"])
        self.assertEqual(self.vault.deliveries.list(), [])
        self.copy_fixture("manifest.ready")
        result = self.scan()
        self.assertEqual(result["pending"], [])
        group = result["groups"][0]
        self.assertEqual(group["state"], "registered")
        self.assertEqual(group["delivery"], "lab-delivery-01")
        self.assertFalse(group["reused"])
        self.assertEqual(
            [member["dataset"] for member in group["members"]],
            ["calibration", "measurements"],
        )
        parents = self.vault.registry.version("measurements", 1)["payload"]["parents"]
        self.assertEqual(parents, [{"dataset": "calibration", "version": 1}])
        self.assertEqual(
            self.vault.ingestion.rows("measurements", 1),
            [
                {"group": "A", "id": "a", "value": "10"},
                {"group": "B", "id": "b", "value": "20"},
            ],
        )
        self.assertEqual(
            self.vault.ingestion.rows("calibration", 1),
            [{"group": "A", "id": "c", "value": "2"}],
        )
        metadata = self.vault.registry.version("calibration", 1)["payload"]["metadata"]
        self.assertEqual(metadata, {"delivery": "lab-delivery-01"})
        self.assertEqual(self.vault.checks.inspect()["versions"], 2)
        for name in ("measurements.csv", "calibration.jsonl", "manifest.ready"):
            self.assertTrue((self.inbox / name).is_file())

    def test_rescan_is_idempotent(self):
        self.copy_fixture(
            "measurements.csv", "calibration.jsonl", "manifest.ready"
        )
        first = self.scan()["groups"][0]
        self.assertEqual(first["state"], "registered")
        audits = self.vault.database.rows("SELECT kind FROM audit")
        second = self.scan()["groups"][0]
        self.assertEqual(second["state"], "registered")
        self.assertTrue(second["reused"])
        self.assertEqual(
            self.vault.database.rows("SELECT kind FROM audit"), audits
        )
        self.assertEqual(len(self.vault.registry.list_versions("measurements")), 1)
        self.assertEqual(len(self.vault.registry.list_versions("calibration")), 1)
        self.assertEqual(self.vault.checks.inspect()["versions"], 2)

    def test_conflicting_redelivery_is_quarantined(self):
        self.copy_fixture(
            "measurements.csv", "calibration.jsonl", "manifest.ready"
        )
        self.assertEqual(self.scan()["groups"][0]["state"], "registered")
        changed = fixture_manifest()
        changed["members"][0]["rows"] = 99
        (self.inbox / "manifest.ready").write_text(json.dumps(changed))
        group = self.scan()["groups"][0]
        self.assertEqual(group["state"], "quarantined")
        self.assertEqual(group["reason"]["code"], "conflict")
        records = self.vault.deliveries.list()
        self.assertEqual(
            [record["state"] for record in records], ["quarantined", "registered"]
        )
        again = self.scan()["groups"][0]
        self.assertEqual(again["state"], "quarantined")
        self.assertTrue(again["reused"])
        self.assertEqual(len(self.vault.registry.list_versions("measurements")), 1)
        self.assertEqual(self.vault.registry.list_versions("calibration")[0]["version"], 1)
        self.assertTrue((self.inbox / "manifest.ready").is_file())
        self.assertTrue((self.inbox / "measurements.csv").is_file())

    def test_corrupted_group_quarantined_while_others_register(self):
        group_a = self.inbox / "group-a"
        group_b = self.inbox / "group-b"
        group_a.mkdir()
        group_b.mkdir()
        self.copy_fixture("measurements.csv", "calibration.jsonl", target=group_a)
        broken = fixture_manifest()
        broken["members"][0]["sha256"] = "0" * 64
        (group_a / "manifest.ready").write_text(json.dumps(broken))
        self.copy_fixture("measurements.csv", "calibration.jsonl", target=group_b)
        (group_b / "manifest.ready").write_text(
            json.dumps(fixture_manifest(delivery_id="lab-delivery-02"))
        )
        result = self.scan()
        self.assertEqual(result["pending"], [])
        self.assertEqual([group["state"] for group in result["groups"]], ["quarantined", "registered"])
        failed, registered = result["groups"]
        self.assertEqual(failed["delivery"], "lab-delivery-01")
        self.assertEqual(failed["reason"]["code"], "integrity")
        self.assertEqual(registered["delivery"], "lab-delivery-02")
        self.assertEqual(len(self.vault.registry.list_versions("measurements")), 1)
        tracked = self.vault.deliveries.get("lab-delivery-01")
        self.assertEqual(tracked[0]["state"], "quarantined")
        self.assertEqual(tracked[0]["payload"]["reason"]["code"], "integrity")
        self.assertTrue((group_a / "measurements.csv").is_file())
        self.assertTrue((group_a / "manifest.ready").is_file())

    def test_member_path_cannot_escape_root(self):
        outside = self.base / "escape.csv"
        outside.write_bytes(b"id,value,group\nx,1,A\n")
        self.copy_fixture("calibration.jsonl")
        escaped = fixture_manifest()
        escaped["members"][0]["path"] = "../escape.csv"
        (self.inbox / "manifest.ready").write_text(json.dumps(escaped))
        group = self.scan()["groups"][0]
        self.assertEqual(group["state"], "quarantined")
        self.assertEqual(group["reason"]["code"], "path")
        absolute = fixture_manifest(delivery_id="lab-delivery-02")
        absolute["members"][0]["path"] = str(outside)
        (self.inbox / "manifest.ready").write_text(json.dumps(absolute))
        group = self.scan()["groups"][0]
        self.assertEqual(group["state"], "quarantined")
        self.assertEqual(group["reason"]["code"], "path")
        self.assertEqual(self.vault.registry.list_versions("measurements"), [])
        self.assertEqual(outside.read_bytes(), b"id,value,group\nx,1,A\n")

    def test_unstable_member_is_retried_not_quarantined(self):
        self.copy_fixture(
            "measurements.csv", "calibration.jsonl", "manifest.ready"
        )
        counter = {"n": 0}

        def changing(path):
            counter["n"] += 1
            return (0, 0, counter["n"])

        self.vault.deliveries._signature = changing
        group = self.scan()["groups"][0]
        self.assertEqual(group["state"], "unstable")
        self.assertEqual(self.vault.registry.list_versions("measurements"), [])
        records = self.vault.deliveries.list()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["state"], "claimed")
        del self.vault.deliveries._signature
        group = self.scan()["groups"][0]
        self.assertEqual(group["state"], "registered")
        self.assertEqual(len(self.vault.registry.list_versions("measurements")), 1)

    def test_restart_before_finalize_recovers_without_duplicates(self):
        self.copy_fixture(
            "measurements.csv", "calibration.jsonl", "manifest.ready"
        )
        self.assertEqual(self.scan()["groups"][0]["state"], "registered")
        with self.vault.database.transaction() as con:
            con.execute("UPDATE deliveries SET state='claimed'")
        self.vault.close()
        self.vault = Vault(self.base / "vault")
        self.addCleanup(self.vault.close)
        group = self.scan()["groups"][0]
        self.assertEqual(group["state"], "registered")
        self.assertTrue(all(member["reused"] for member in group["members"]))
        self.assertEqual(len(self.vault.registry.list_versions("measurements")), 1)
        self.assertEqual(len(self.vault.registry.list_versions("calibration")), 1)
        self.assertEqual(self.vault.checks.inspect()["versions"], 2)
        self.assertEqual(self.vault.deliveries.list()[0]["state"], "registered")

    def test_row_count_mismatch_rolls_back_whole_group(self):
        self.copy_fixture(
            "measurements.csv", "calibration.jsonl", "manifest.ready"
        )
        changed = fixture_manifest()
        changed["members"][0]["rows"] = 5
        (self.inbox / "manifest.ready").write_text(json.dumps(changed))
        group = self.scan()["groups"][0]
        self.assertEqual(group["state"], "quarantined")
        self.assertEqual(group["reason"]["code"], "integrity")
        self.assertEqual(self.vault.registry.list_versions("measurements"), [])
        self.assertEqual(self.vault.registry.list_versions("calibration"), [])
        preview = self.vault.checks.unused_artifacts()
        self.assertEqual(len(preview["candidates"]), 2)
        self.vault.checks.unused_artifacts(False)
        self.assertEqual(self.vault.artifacts.inventory(), [])
        self.assertTrue((self.inbox / "calibration.jsonl").is_file())

    def test_schema_incompatible_delivery_keeps_old_head(self):
        self.copy_fixture(
            "measurements.csv", "calibration.jsonl", "manifest.ready"
        )
        self.assertEqual(self.scan()["groups"][0]["state"], "registered")
        bad = b"id,value,group\nc,30,C\n"
        followup = fixture_manifest(
            delivery_id="lab-delivery-02",
            members=[
                {
                    "path": "measurements.csv",
                    "dataset": "measurements",
                    "schema_version": 1,
                    "expected_version": 1,
                    "bytes": len(bad),
                    "sha256": hashlib.sha256(bad).hexdigest(),
                    "rows": 1,
                    "depends_on": [],
                }
            ],
        )
        (self.inbox / "measurements.csv").write_bytes(bad)
        (self.inbox / "manifest.ready").write_text(json.dumps(followup))
        group = self.scan()["groups"][0]
        self.assertEqual(group["state"], "quarantined")
        self.assertEqual(group["reason"]["code"], "row")
        head = self.vault.registry.version("measurements", 1)
        self.assertEqual(head["state"], "active")
        self.assertEqual(len(self.vault.registry.list_versions("measurements")), 1)
        self.assertEqual(self.vault.ingestion.rows("measurements", 1)[0]["id"], "a")

    def test_invalid_manifest_is_audited(self):
        self.copy_fixture("measurements.csv", "calibration.jsonl")
        (self.inbox / "manifest.ready").write_bytes(b"{not json")
        group = self.scan()["groups"][0]
        self.assertEqual(group["state"], "invalid")
        self.assertEqual(group["error"]["code"], "input")
        kinds = [
            row["kind"]
            for row in self.vault.database.rows("SELECT kind FROM audit")
        ]
        self.assertIn("delivery_invalid", kinds)
        self.assertEqual(self.vault.registry.list_versions("measurements"), [])

    def test_dependency_outside_group_is_quarantined(self):
        self.copy_fixture(
            "measurements.csv", "calibration.jsonl", "manifest.ready"
        )
        changed = fixture_manifest()
        changed["members"][0]["depends_on"] = ["absent"]
        (self.inbox / "manifest.ready").write_text(json.dumps(changed))
        group = self.scan()["groups"][0]
        self.assertEqual(group["state"], "quarantined")
        self.assertEqual(group["reason"]["code"], "input")
        self.assertEqual(self.vault.registry.list_versions("calibration"), [])


if __name__ == "__main__":
    unittest.main()
