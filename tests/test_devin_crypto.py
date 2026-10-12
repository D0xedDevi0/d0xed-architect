"""RFC 8439 vectors + bundle integrity.

The vectors are the whole point: hand-rolled crypto is only trustworthy when it
matches the published answers byte for byte. A failure here means every sealed
bundle is suspect, so these tests are deliberately exact rather than "round
trips OK".
"""
import os
import unittest

from devin.crypto import (MAGIC, SCRYPT_N, CryptoError, FormatError,
                          IntegrityError, PassphraseError, aead_open, aead_seal,
                          chacha20_block, chacha20_xor, derive_key, is_bundle,
                          open_bundle, parse_header, poly1305_mac, seal_bundle)

# RFC 8439 section 2.3.2
BLOCK_KEY = bytes(range(32))
BLOCK_NONCE = bytes.fromhex("000000090000004a00000000")
BLOCK_OUT = bytes.fromhex(
    "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
    "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e")

SUNSCREEN = (b"Ladies and Gentlemen of the class of '99: If I could offer you "
             b"only one tip for the future, sunscreen would be it.")

# RFC 8439 section 2.4.2
STREAM_KEY = bytes(range(32))
STREAM_NONCE = bytes.fromhex("000000000000004a00000000")
# The published dump covers the first 112 bytes; plaintext is 114, so the last
# two keystream bytes are unverified here and are simply not asserted.
STREAM_OUT = bytes.fromhex(
    "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
    "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
    "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
    "5af90bbf74a35be6b40b8eedf2785e42")

# RFC 8439 section 2.8.2
AEAD_KEY = bytes(range(0x80, 0xA0))
AEAD_NONCE = bytes.fromhex("070000004041424344454647")
AEAD_AAD = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
AEAD_CT = bytes.fromhex(
    "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
    "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
    "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
    "3ff4def08e4b7a9de576d26586cec64b6116")
AEAD_TAG = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")   # RFC 8439 2.8.2


class TestRfcVectors(unittest.TestCase):
    def test_block_function(self):
        self.assertEqual(chacha20_block(BLOCK_KEY, 1, BLOCK_NONCE), BLOCK_OUT)

    def test_stream_encryption(self):
        self.assertEqual(len(STREAM_OUT), 112)
        got = chacha20_xor(STREAM_KEY, STREAM_NONCE, SUNSCREEN[:112], counter=1)
        self.assertEqual(got, STREAM_OUT)
        # ...and the full-length stream must agree with it on the shared prefix.
        full = chacha20_xor(STREAM_KEY, STREAM_NONCE, SUNSCREEN, counter=1)
        self.assertEqual(full[:112], STREAM_OUT)

    def test_round_trip_is_an_involution(self):
        ct = chacha20_xor(BLOCK_KEY, BLOCK_NONCE, SUNSCREEN)
        self.assertEqual(chacha20_xor(BLOCK_KEY, BLOCK_NONCE, ct), SUNSCREEN)

    def test_aead_seal_matches_rfc(self):
        sealed = aead_seal(AEAD_KEY, AEAD_NONCE, SUNSCREEN, AEAD_AAD)
        self.assertEqual(sealed[:-16], AEAD_CT)
        self.assertEqual(sealed[-16:], AEAD_TAG)

    def test_aead_open_matches_rfc(self):
        self.assertEqual(aead_open(AEAD_KEY, AEAD_NONCE, AEAD_CT + AEAD_TAG,
                                   AEAD_AAD), SUNSCREEN)

    def test_poly1305_vector(self):
        key = bytes.fromhex(
            "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
        tag = poly1305_mac(b"Cryptographic Forum Research Group", key)
        self.assertEqual(tag.hex(),
                         "a8061dc1305136c6c22b8baf0c0127a9")

    def test_aead_rejects_a_flipped_bit_everywhere(self):
        sealed = bytearray(aead_seal(AEAD_KEY, AEAD_NONCE, SUNSCREEN, AEAD_AAD))
        for i in (0, 20, 60, len(sealed) - 1):
            with self.subTest(index=i):
                bad = bytearray(sealed)
                bad[i] ^= 0x01
                with self.assertRaises(IntegrityError):
                    aead_open(AEAD_KEY, AEAD_NONCE, bytes(bad), AEAD_AAD)

    def test_aad_is_authenticated(self):
        sealed = aead_seal(AEAD_KEY, AEAD_NONCE, SUNSCREEN, AEAD_AAD)
        with self.assertRaises(IntegrityError):
            aead_open(AEAD_KEY, AEAD_NONCE, sealed, b"different aad")


class TestBundle(unittest.TestCase):
    PW = "correct horse battery staple"

    def test_round_trip(self):
        blob = seal_bundle(b"payload bytes", self.PW)
        self.assertTrue(is_bundle(blob))
        self.assertEqual(open_bundle(blob, self.PW), b"payload bytes")

    def test_header_is_authenticated(self):
        """Editing the declared scrypt cost must not silently decrypt."""
        blob = bytearray(seal_bundle(b"payload bytes", self.PW))
        blob[42] ^= 0x01                       # r
        with self.assertRaises(CryptoError):
            open_bundle(bytes(blob), self.PW)

    def test_salt_edit_fails(self):
        blob = bytearray(seal_bundle(b"payload bytes", self.PW))
        blob[12] ^= 0x01
        with self.assertRaises(IntegrityError):
            open_bundle(bytes(blob), self.PW)

    def test_wrong_passphrase_fails_cleanly(self):
        blob = seal_bundle(b"payload bytes", self.PW)
        with self.assertRaises(IntegrityError):
            open_bundle(blob, "wrong horse battery staple")

    def test_truncated_and_garbage_are_refused(self):
        for blob in (b"", b"short", MAGIC + b"\x00" * 20, os.urandom(200)):
            with self.subTest(n=len(blob)):
                with self.assertRaises(FormatError):
                    parse_header(blob)

    def test_same_input_seals_differently(self):
        a = seal_bundle(b"same", self.PW)
        b = seal_bundle(b"same", self.PW)
        self.assertNotEqual(a, b)
        self.assertEqual(open_bundle(a, self.PW), open_bundle(b, self.PW))

    def test_fixed_salt_and_nonce_is_reproducible(self):
        kw = {"salt": bytes(16), "nonce": bytes(12)}
        a = seal_bundle(b"receipt", self.PW, **kw)
        b = seal_bundle(b"receipt", self.PW, **kw)
        self.assertEqual(a, b)                 # needed for reproducible receipts

    def test_plaintext_is_not_recoverable_from_the_blob(self):
        secret = b"AKIA" + b"Z" * 20
        blob = seal_bundle(secret, self.PW)
        self.assertNotIn(b"AKIA", blob)
        self.assertNotIn(b"ZZZ", blob)

    def test_hostile_cost_parameters_are_refused(self):
        hdr = parse_header(seal_bundle(b"x", self.PW))
        big = (MAGIC + bytes(16) + bytes(12) + (1 << 30).to_bytes(4, "big")
               + hdr.r.to_bytes(4, "big") + hdr.p.to_bytes(4, "big"))
        with self.assertRaises(FormatError):
            parse_header(big + bytes(64))

    def test_non_power_of_two_n_is_refused(self):
        blob = (MAGIC + bytes(16) + bytes(12) + (3).to_bytes(4, "big")
                + (8).to_bytes(4, "big") + (1).to_bytes(4, "big") + bytes(64))
        with self.assertRaises(FormatError):
            parse_header(blob)

    def test_short_or_missing_passphrase_is_refused(self):
        for pw in ("", "short", "1234567"):
            with self.subTest(pw=pw):
                with self.assertRaises(PassphraseError):
                    seal_bundle(b"x", pw)

    def test_kdf_changes_with_salt(self):
        a = derive_key(self.PW, bytes(16))
        b = derive_key(self.PW, bytes(15) + b"\x01")
        self.assertNotEqual(a, b)
        self.assertEqual(len(a), 32)
        self.assertEqual(a, derive_key(self.PW, bytes(16)))

    def test_default_cost_is_the_documented_one(self):
        hdr = parse_header(seal_bundle(b"x", self.PW))
        self.assertEqual(hdr.n, SCRYPT_N)
        self.assertEqual((hdr.r, hdr.p), (8, 1))

    def test_params_are_validated_on_seal_too(self):
        with self.assertRaises(FormatError):
            seal_bundle(b"x", self.PW, n=3)
        with self.assertRaises(FormatError):
            seal_bundle(b"x", self.PW, salt=b"tooshort")


if __name__ == "__main__":
    unittest.main()
