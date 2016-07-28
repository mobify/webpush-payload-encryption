# -*- coding: utf-8 -*-
import base64
from unittest import TestCase

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
import mock

from .. import (
    encrypt_payload,
    DEFAULT_BACKEND,
    HEADER_CRYPTO_KEY,
    HEADER_ENCRYPTION_KEY,
    HEADER_ENCRYPTION,
    HKDF_256
)


class TestEncryption(TestCase):

    PUBLIC_KEY = None
    PRIVATE_KEY = None
    KEY_B64 = None

    AUTH_B64 = 'Or79lW+u11VPfLG83mxBfQ=='

    SALT = '\xbaa\x1c\xd00w\xb6\xb3\xb6\xbdh~\x8e8\x10|'

    PLAINTEXT = {
        'abc': 123,
        'def': 456
    }

    @classmethod
    def setUpClass(cls):
        # See https://tools.ietf.org/html/draft-ietf-webpush-encryption#section-5
        # for the specification of the key.
        cls.PRIVATE_KEY = ec.generate_private_key(
            ec.SECP256R1,
            DEFAULT_BACKEND
        )

        cls.PUBLIC_KEY = (
            cls.PRIVATE_KEY
            .public_key()
            .public_numbers()
            .encode_point()
        )

        cls.KEY_B64 = base64.b64encode(cls.PUBLIC_KEY)

    def test_payload_encryption(self):

        with mock.patch(
            'OpenSSL.rand.bytes',
            new=lambda x: self.SALT
        ):
            ciphertext, headers = encrypt_payload(
                key=self.KEY_B64,
                auth=self.AUTH_B64,
                payload=self.PLAINTEXT
            )

            # This is a pretty limited test of the encryption, since we don't
            # implement *decryption*. We're just verifying that there is an
            # encoded text and that the headers look right.
            self.assertIsNotNone(ciphertext)
            self.assertIn(HEADER_CRYPTO_KEY, headers)
            self.assertEqual(
                headers.get(HEADER_ENCRYPTION),
                'keyid=p256dh;salt=umEc0DB3trO2vWh-jjgQfA'
            )

            # Verify that omitting the auth returns the alternate
            # headers
            ciphertext, headers = encrypt_payload(
                key=self.KEY_B64,
                auth=None,
                payload=self.PLAINTEXT
            )

            self.assertIsNotNone(ciphertext)
            self.assertIn(HEADER_ENCRYPTION_KEY, headers)
            self.assertEqual(
                headers.get(HEADER_ENCRYPTION),
                'keyid=p256dh;salt=umEc0DB3trO2vWh-jjgQfA'
            )
