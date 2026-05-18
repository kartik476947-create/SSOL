import unittest
import os
import json
from ssol_supply_chain_guard import SupplyChainGuard

class TestSSOLSupplyChainGuard(unittest.TestCase):
    def setUp(self):
        self.test_manifest = "test_sbom_manifest.json"
        if os.path.exists(self.test_manifest):
            try:
                os.remove(self.test_manifest)
            except Exception:
                pass
        self.guard = SupplyChainGuard(config_path="nonexistent_config.yaml")
        # Override target manifest file
        self.guard.manifest_path = self.test_manifest

    def tearDown(self):
        # Guarantee cleanup
        if os.path.exists(self.test_manifest):
            try:
                os.remove(self.test_manifest)
            except Exception:
                pass

    def test_sha256_binary_hashing(self):
        """Test 1: Verify SHA-256 critical system utility hashing."""
        print("[-] Running Test: SHA-256 Binary Integrity Hashing...")
        hashes = self.guard.get_binary_hashes()
        self.assertIsInstance(hashes, dict)
        self.assertGreater(len(hashes), 0)
        # Verify hash values look like hexadecimal SHA-256 keys
        for key, val in hashes.items():
            self.assertEqual(len(val), 64, f"Hash value for {key} is not SHA-256 hex format!")
            
        print("\033[92m[v] Test Passed: SHA-256 system utility hashing is correct.\033[0m")

    def test_sbom_manifest_generation(self):
        """Test 2: Verify CycloneDX SBoM manifest compilation and signing."""
        print("[-] Running Test: SBoM Compilation & Signing...")
        manifest = self.guard.generate_sbom()
        
        # Verify file creation
        self.assertTrue(os.path.exists(self.test_manifest))
        
        # Verify manifest structure
        self.assertIn("sbom", manifest)
        self.assertIn("signature", manifest)
        self.assertTrue(manifest["signature"].startswith("FIPS-TDX-HSM-SIG::"))
        
        sbom = manifest["sbom"]
        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertEqual(sbom["specVersion"], "1.4")
        self.assertIn("components", sbom)
        self.assertGreater(len(sbom["components"]), 0)
        
        print("\033[92m[v] Test Passed: CycloneDX SBoM manifest structure and FIPS signature validated.\033[0m")

    def test_integrity_audit_alerts(self):
        """Test 3: Verify scheduled boot checks alert correctly on file hash alterations."""
        print("[-] Running Test: SBoM Tamper & Breach Audits...")
        
        # Generate pristine state
        self.guard.generate_sbom()
        
        # Clean check should pass
        success, violations = self.guard.audit_integrity()
        self.assertTrue(success)
        self.assertEqual(len(violations), 0)
        
        # Tamper 1: Alter signature validation key
        with open(self.test_manifest, "r") as f:
            mdata = json.load(f)
        mdata["signature"] = "FIPS-TDX-HSM-SIG::tampered_signature_hex_value"
        with open(self.test_manifest, "w") as f:
            json.dump(mdata, f, indent=2)
            
        success_t1, violations_t1 = self.guard.audit_integrity()
        self.assertFalse(success_t1)
        self.assertIn("manifest_signature_breach", violations_t1)

        # Re-generate SBoM to fix signature
        self.guard.generate_sbom()
        
        # Tamper 2: Simulate file modification by altering hash of core utility
        with open(self.test_manifest, "r") as f:
            mdata = json.load(f)
        # Select first binary entry and inject rogue hash
        bin_name = list(mdata["sbom"]["binary_integrity"].keys())[0]
        mdata["sbom"]["binary_integrity"][bin_name] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        # Skip updating HSM signature to keep it signed as original
        with open(self.test_manifest, "w") as f:
            json.dump(mdata, f, indent=2)
            
        success_t2, violations_t2 = self.guard.audit_integrity()
        # Should breach since we altered the manifest values, failing signature validation or binary checks
        self.assertFalse(success_t2)
        
        print("\033[92m[v] Test Passed: Breach alerts successfully generated on system state mutation.\033[0m")

if __name__ == "__main__":
    unittest.main()
