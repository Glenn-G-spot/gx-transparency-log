"""Run the complete local verifier against isolated signature fixtures.

Run with: python3 -m unittest discover -s tests -v
"""

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "gx_verify_local.sh"
PROOF_ID = "20260211T192351Z"
TAG = f"gx-proof-{PROOF_ID}-r2"
KEY_ID = "0123456789ABCDEF"
SIGNER = "Review No public key <review@example.invalid>"
SIGNED_FILES = (
    f"GX_MERKLE_ROOT_{PROOF_ID}.txt",
    f"GX_DNS_TXT_ANCHOR_{PROOF_ID}.txt",
    f"snapshots/{PROOF_ID}.json",
)


def isolated_environment(root):
    """Exclude inherited Git settings and keep all GPG state in the fixture."""
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("GIT_") and key not in ("GPG_AGENT_INFO", "GPG_TTY")
    }
    home = root / "home"
    home.mkdir(exist_ok=True)
    env.update(
        HOME=str(home),
        XDG_CONFIG_HOME=str(home / ".config"),
        GNUPGHOME=str(root / "gnupg"),
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_SYSTEM=os.devnull,
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_TERMINAL_PROMPT="0",
        LC_ALL="C",
    )
    return env


def run_process(args, *, env, cwd, input=None, timeout=30):
    return subprocess.run(
        args,
        input=input,
        capture_output=True,
        text=True,
        env=env,
        cwd=cwd,
        timeout=timeout,
        check=False,
    )


class VerifierFixture:
    def __init__(self, root):
        self.root = root
        self.repo = root / "repo"
        self.script = self.repo / "tools" / "gx_verify_local.sh"
        self.script.parent.mkdir(parents=True)
        shutil.copy2(SCRIPT, self.script)
        self.env = isolated_environment(root)

        for relative in SIGNED_FILES:
            material = self.repo / relative
            material.parent.mkdir(parents=True, exist_ok=True)
            material.write_text(f"isolated fixture: {relative}\n", encoding="utf-8")
            material.with_name(material.name + ".asc").write_text(
                "signature fixture\n", encoding="utf-8"
            )
        for relative in (
            f"GX_MERKLE_ROOT_{PROOF_ID}.txt.ots",
            f"GX_MERKLE_SUPER_COMBINED_{PROOF_ID}.txt.digicert.tsr",
            f"GX_MERKLE_SUPER_COMBINED_{PROOF_ID}.txt.globalsign.tsr",
        ):
            (self.repo / relative).write_text("proof fixture\n", encoding="utf-8")

        index = b"isolated proof index\n"
        (self.repo / "GX_PROOF_INDEX.txt").write_bytes(index)
        (self.repo / "GX_PROOF_INDEX.txt.sha256").write_text(
            f"{hashlib.sha256(index).hexdigest()}  GX_PROOF_INDEX.txt\n",
            encoding="utf-8",
        )

    def verify(self, env=None):
        # The unrelated working directory also checks script-relative resolution.
        return run_process(
            ["/bin/bash", str(self.script)],
            env=self.env if env is None else env,
            cwd=self.root,
        )


class VerifierAssertions:
    def assert_verifier_result(self, result, status, *, detached_valid=True):
        output = result.stdout + result.stderr
        suffix = {
            "PASS": "",
            "FAIL": ":signature_check_failed",
            "NOT_VERIFIED": ":verification_capability_unavailable",
        }[status]
        tag_lines = [
            line
            for line in output.splitlines()
            if line.startswith(tuple(f"{state}=git_tag:{TAG}" for state in (
                "PASS", "FAIL", "NOT_VERIFIED"
            )))
        ]
        self.assertEqual(tag_lines, [f"{status}=git_tag:{TAG}{suffix}"], output)
        self.assertEqual(result.returncode, 1 if status == "FAIL" else 2, output)
        overall = "FAIL" if status == "FAIL" else "PARTIAL_NOT_VERIFIED"
        self.assertIn(f"OVERALL={overall}\n", result.stdout)
        self.assertIn(
            "NOT_VERIFIED=opentimestamps:proof_present_but_network_verification_not_performed\n",
            result.stdout,
        )
        self.assertIn(
            "NOT_VERIFIED=rfc3161:responses_present_but_certificate_chain_verification_not_performed\n",
            result.stdout,
        )
        if detached_valid:
            for label in ("merkle_root", "dns_anchor", "snapshot"):
                self.assertIn(f"PASS=gpg:{label}\n", result.stdout)


class MockedTagVerificationTests(VerifierAssertions, unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="gx-tag-mock-")
        self.addCleanup(temporary.cleanup)
        self.fixture = VerifierFixture(Path(temporary.name))
        binary_dir = self.fixture.root / "bin"
        binary_dir.mkdir()
        programs = {
            "git": """import os, sys
if 'verify-tag' in sys.argv:
    sys.stderr.write(os.environ['GX_TEST_TAG_OUTPUT'])
    sys.exit(int(os.environ['GX_TEST_TAG_RC']))
if 'rev-parse' in sys.argv:
    sys.exit(0)
sys.exit(99)
""",
            "gpg": """import sys
sys.stdout.write('[GNUPG:] GOODSIG 0123456789ABCDEF Fixture signer\\n')
sys.exit(0)
""",
        }
        for name, body in programs.items():
            executable = binary_dir / name
            executable.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
            executable.chmod(0o755)
        self.fixture.env["PATH"] = str(binary_dir) + os.pathsep + os.defpath

    def verify_tag(self, output, rc=1):
        self.fixture.env.update(GX_TEST_TAG_OUTPUT=output, GX_TEST_TAG_RC=str(rc))
        return self.fixture.verify()

    def test_badsig_with_capability_words_in_signer_uid_is_failure(self):
        for phrase in ("No public key", "waiting for lock", "Operation timed out"):
            with self.subTest(phrase=phrase):
                output = f"[GNUPG:] BADSIG {KEY_ID} Review {phrase} <review@example.invalid>\n"
                self.assert_verifier_result(self.verify_tag(output), "FAIL")

    def test_explicit_invalid_status_takes_precedence_over_missing_key(self):
        for status in ("BADSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG"):
            bad = f"[GNUPG:] {status} {KEY_ID} {SIGNER}\n"
            missing = f"[GNUPG:] NO_PUBKEY {KEY_ID}\n"
            for output in (bad + missing, missing + bad):
                with self.subTest(status=status, missing_first=output == missing + bad):
                    self.assert_verifier_result(self.verify_tag(output), "FAIL")

    def test_missing_public_key_status_is_not_verified(self):
        output = (
            f"[GNUPG:] ERRSIG {KEY_ID} 1 10 00 1760000000 9\n"
            f"[GNUPG:] NO_PUBKEY {KEY_ID}\n"
        )
        self.assert_verifier_result(self.verify_tag(output), "NOT_VERIFIED")

    def test_valid_signature_is_pass_even_with_capability_words_in_uid(self):
        output = (
            f"[GNUPG:] GOODSIG {KEY_ID} {SIGNER}\n"
            "[GNUPG:] VALIDSIG 0123456789ABCDEF0123456789ABCDEF01234567 "
            "2026-10-10 1760000000 0 4 0 1 10 00\n"
        )
        self.assert_verifier_result(self.verify_tag(output, rc=0), "PASS")

    def test_unknown_error_is_failure(self):
        self.assert_verifier_result(
            self.verify_tag("error: signature verification failed for an unknown reason\n"),
            "FAIL",
        )

    def test_actual_gpg_lock_and_timeout_diagnostics_are_not_verified(self):
        for diagnostic in (
            "gpg: waiting for lock (held by 4242) ...\n",
            "gpg: keydb_search failed: Operation timed out\n",
            "gpg: Note: database_open 134217901 waiting for lock (held by 4242) ...\n",
        ):
            with self.subTest(diagnostic=diagnostic):
                self.assert_verifier_result(self.verify_tag(diagnostic), "NOT_VERIFIED")

    def test_capability_words_outside_status_or_diagnostic_are_failure(self):
        for output in (
            f'gpg: BAD signature from "{SIGNER}"\n',
            f"[GNUPG:] USERID_HINT {KEY_ID} Review waiting for lock\n",
            f"[GNUPG:] USERID_HINT {KEY_ID} Review Operation timed out\n",
            "other: gpg: keydb_search failed: Operation timed out\n",
            f"[GNUPG:] USERID_HINT {KEY_ID} Review [GNUPG:] NO_PUBKEY {KEY_ID}\n",
        ):
            with self.subTest(output=output):
                self.assert_verifier_result(self.verify_tag(output), "FAIL")


class RealGitGpgTagTests(VerifierAssertions, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.git = shutil.which("git")
        cls.gpg = shutil.which("gpg")
        if not cls.git or not cls.gpg:
            raise unittest.SkipTest("real signature tests require git and gpg")

        # A short path also avoids platform limits on GPG agent socket paths.
        temporary = tempfile.TemporaryDirectory(prefix="gx-tag-real-", dir="/tmp")
        cls.addClassCleanup(temporary.cleanup)
        cls.fixture = VerifierFixture(Path(temporary.name))
        cls.keyring = cls.fixture.root / "gnupg"
        cls.keyring.mkdir(mode=0o700)
        (cls.keyring / "gpg.conf").write_text(
            "no-auto-key-retrieve\nauto-key-locate clear\nno-auto-key-import\n",
            encoding="utf-8",
        )
        cls.gpgconf = shutil.which("gpgconf")
        cls.addClassCleanup(cls.stop_fixture_agent)

        cls.checked(
            [cls.gpg, "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
             "--quick-generate-key", SIGNER, "rsa2048", "sign", "0"],
            timeout=60,
        )
        for relative in SIGNED_FILES:
            material = cls.fixture.repo / relative
            cls.checked(
                [cls.gpg, "--batch", "--yes", "--pinentry-mode", "loopback",
                 "--passphrase", "", "--armor", "--detach-sign", str(material)]
            )

        cls.fixture.env.update(
            GIT_CONFIG_COUNT="4",
            GIT_CONFIG_KEY_0="user.name",
            GIT_CONFIG_VALUE_0="Isolated verifier test",
            GIT_CONFIG_KEY_1="user.email",
            GIT_CONFIG_VALUE_1="review@example.invalid",
            GIT_CONFIG_KEY_2="gpg.program",
            GIT_CONFIG_VALUE_2=cls.gpg,
            GIT_CONFIG_KEY_3="user.signingkey",
            GIT_CONFIG_VALUE_3=SIGNER,
        )
        cls.checked([cls.git, "init", "--quiet", str(cls.fixture.repo)])
        cls.checked([cls.git, "-C", str(cls.fixture.repo), "add", "."])
        cls.checked([cls.git, "-C", str(cls.fixture.repo), "commit", "--quiet",
                     "--no-gpg-sign", "-m", "isolated fixture"])
        cls.checked([cls.git, "-C", str(cls.fixture.repo), "tag", "-s", TAG,
                     "-m", "isolated signed proof"])
        cls.original_tag = cls.checked(
            [cls.git, "-C", str(cls.fixture.repo), "rev-parse", f"refs/tags/{TAG}"]
        ).stdout.strip()

    @classmethod
    def checked(cls, args, *, input=None, timeout=30):
        result = run_process(
            args, env=cls.fixture.env, cwd=cls.fixture.root, input=input, timeout=timeout
        )
        if result.returncode:
            raise AssertionError(
                f"Fixture command failed ({result.returncode}): {args!r}\n"
                f"{result.stdout}{result.stderr}"
            )
        return result

    @classmethod
    def stop_fixture_agent(cls):
        if cls.gpgconf:
            run_process(
                [cls.gpgconf, "--homedir", str(cls.keyring), "--kill", "gpg-agent"],
                env=cls.fixture.env,
                cwd=cls.fixture.root,
                timeout=10,
            )

    def setUp(self):
        self.checked([self.git, "-C", str(self.fixture.repo), "update-ref",
                      f"refs/tags/{TAG}", self.original_tag])

    def test_real_valid_signature_with_no_public_key_in_uid_is_pass(self):
        self.assert_verifier_result(self.fixture.verify(), "PASS")

    def test_real_tampered_tag_message_with_no_public_key_in_uid_is_failure(self):
        original = self.checked(
            [self.git, "-C", str(self.fixture.repo), "cat-file", "tag", self.original_tag]
        ).stdout
        self.assertIn("\nisolated signed proof\n", original)
        tampered = original.replace(
            "\nisolated signed proof\n", "\ntampered signed proof\n", 1
        )
        tampered_oid = self.checked(
            [self.git, "-C", str(self.fixture.repo), "hash-object", "-t", "tag", "-w", "--stdin"],
            input=tampered,
        ).stdout.strip()
        self.checked([self.git, "-C", str(self.fixture.repo), "update-ref",
                      f"refs/tags/{TAG}", tampered_oid])
        raw = run_process(
            [self.git, "-C", str(self.fixture.repo), "verify-tag", "--raw", TAG],
            env=self.fixture.env,
            cwd=self.fixture.root,
        )
        raw_output = raw.stdout + raw.stderr
        self.assertNotEqual(raw.returncode, 0, raw_output)
        self.assertRegex(raw_output, r"(?m)^\[GNUPG:\] BADSIG [^\n]*Review No public key")
        self.assertNotRegex(raw_output, r"(?m)^\[GNUPG:\] NO_PUBKEY(?: |$)")
        self.assert_verifier_result(self.fixture.verify(), "FAIL")

    def test_real_empty_public_keyring_is_not_verified(self):
        empty_keyring = self.fixture.root / "empty-keyring"
        empty_keyring.mkdir(mode=0o700, exist_ok=True)
        (empty_keyring / "gpg.conf").write_text(
            "no-auto-key-retrieve\nauto-key-locate clear\nno-auto-key-import\n",
            encoding="utf-8",
        )
        env = dict(self.fixture.env, GNUPGHOME=str(empty_keyring))
        result = self.fixture.verify(env)
        self.assert_verifier_result(result, "NOT_VERIFIED", detached_valid=False)
        for label in ("merkle_root", "dns_anchor", "snapshot"):
            self.assertIn(
                f"NOT_VERIFIED=gpg:{label}:public_key_unavailable\n", result.stdout
            )


if __name__ == "__main__":
    unittest.main()
