import hashlib,json,unittest
from pathlib import Path

class DeliveryFixture(unittest.TestCase):
    def test_manifest_matches_published_bytes(self):
        root=Path(__file__).resolve().parents[1]/"fixtures/dropbox"
        manifest=json.loads((root/"manifest.ready").read_text())
        for member in manifest["members"]:
            data=(root/member["path"]).read_bytes()
            self.assertEqual(len(data),member["bytes"])
            self.assertEqual(hashlib.sha256(data).hexdigest(),member["sha256"])
