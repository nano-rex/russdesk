"""Tests for the RustDesk client config baker (client/configure_client.py).

The baker is a pure string transform, so these run without a Rust toolchain and
also sanity-check that it matches the actual vendored client source.
"""

import importlib.util
import os
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_MODULE_PATH = os.path.join(_HERE, "..", "client", "configure_client.py")
_spec = importlib.util.spec_from_file_location("configure_client", _MODULE_PATH)
cc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cc)

# A minimal stand-in with the three lines the baker touches, laid out like the
# real config.rs (DEFAULT_SETTINGS is indented inside a lazy_static! block).
SAMPLE = '''\
lazy_static::lazy_static! {
    pub static ref DEFAULT_SETTINGS: RwLock<HashMap<String, String>> = Default::default();
}

pub const RENDEZVOUS_SERVERS: &[&str] = &["rs-ny.rustdesk.com"];
pub const RS_PUB_KEY: &str = "OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw=";
'''


class PatchConfigTest(unittest.TestCase):
    def test_bakes_id_and_key(self):
        out = cc.patch_config_rs(SAMPLE, id_server="rd.example.com:21116", key="ABC123=")
        self.assertIn('pub const RENDEZVOUS_SERVERS: &[&str] = &["rd.example.com:21116"];', out)
        self.assertIn('pub const RS_PUB_KEY: &str = "ABC123=";', out)
        # Default rendezvous and key are gone.
        self.assertNotIn("rs-ny.rustdesk.com", out)
        self.assertNotIn("OeVuKk5nlHiXp", out)

    def test_idempotent(self):
        once = cc.patch_config_rs(SAMPLE, id_server="rd.example.com", key="K=")
        twice = cc.patch_config_rs(once, id_server="rd.example.com", key="K=")
        self.assertEqual(once, twice)

    def test_rebake_overwrites_previous(self):
        once = cc.patch_config_rs(SAMPLE, id_server="first.example.com", key="K1=")
        twice = cc.patch_config_rs(once, id_server="second.example.com", key="K2=")
        self.assertIn('&["second.example.com"]', twice)
        self.assertNotIn("first.example.com", twice)
        self.assertIn('"K2="', twice)
        self.assertNotIn("K1=", twice)

    def test_relay_and_api_seed_default_settings(self):
        out = cc.patch_config_rs(SAMPLE, id_server="rd.example.com", key="K=",
                                 relay="rd.example.com:21117", api="https://rd.example.com")
        self.assertIn('("relay-server".to_string(), "rd.example.com:21117".to_string())', out)
        self.assertIn('("api-server".to_string(), "https://rd.example.com".to_string())', out)
        self.assertIn("RwLock::new(std::collections::HashMap::from([", out)
        self.assertNotIn("= Default::default();", out)

    def test_no_relay_keeps_default_settings_default(self):
        out = cc.patch_config_rs(SAMPLE, id_server="rd.example.com", key="K=")
        self.assertIn(
            "pub static ref DEFAULT_SETTINGS: RwLock<HashMap<String, String>> = Default::default();",
            out)

    def test_relay_only_omits_api_entry(self):
        out = cc.patch_config_rs(SAMPLE, id_server="rd.example.com", key="K=", relay="r:21117")
        self.assertIn('("relay-server".to_string(), "r:21117".to_string())', out)
        self.assertNotIn("api-server", out)

    def test_rejects_unsafe_values(self):
        for bad in ['evil"]; fn hack(){}//', "back\\slash", "has space", "new\nline"]:
            with self.assertRaises(ValueError):
                cc.patch_config_rs(SAMPLE, id_server=bad, key="K=")
            with self.assertRaises(ValueError):
                cc.patch_config_rs(SAMPLE, id_server="ok.example.com", key=bad)

    def test_requires_id_and_key(self):
        with self.assertRaises(ValueError):
            cc.patch_config_rs(SAMPLE, id_server="", key="K=")
        with self.assertRaises(ValueError):
            cc.patch_config_rs(SAMPLE, id_server="rd.example.com", key="")

    def test_missing_constant_raises(self):
        with self.assertRaises(ValueError):
            cc.patch_config_rs("// nothing to patch here\n", id_server="rd.example.com", key="K=")

    def test_against_vendored_config_rs(self):
        """The real vendored client source must patch cleanly (exactly one of each)."""
        if not os.path.exists(cc.DEFAULT_CONFIG_RS):
            self.skipTest("vendored client source not present")
        with open(cc.DEFAULT_CONFIG_RS, encoding="utf-8") as f:
            real = f.read()
        out = cc.patch_config_rs(real, id_server="rd.example.com:21116", key="REALKEY=",
                                 relay="rd.example.com:21117")
        self.assertIn('pub const RENDEZVOUS_SERVERS: &[&str] = &["rd.example.com:21116"];', out)
        self.assertIn('pub const RS_PUB_KEY: &str = "REALKEY=";', out)
        self.assertIn('("relay-server".to_string(), "rd.example.com:21117".to_string())', out)


if __name__ == "__main__":
    unittest.main()
