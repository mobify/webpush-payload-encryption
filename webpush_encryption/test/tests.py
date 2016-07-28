# -*- coding: utf-8 -*-
import mock
from unittest import TestCase

from .. import *


class TestEncryption(TestCase):

    KEY = 'BBlN5VUVJAx3fIRwhSdCxXgJF2egGZkDJAAqZ1Ao20chG' \
          '/O0uaM91twU8a8aPWP7fMAePomPY6icfuzocGGNR3g='

    AUTH = 'Or79lW+u11VPfLG83mxBfQ=='

    PLAINTEXT = {
        'abc': 123,
        'def': 456
    }

    def test_payload_encryption(self):

        with mock.patch(
            'OpenSSL.rand.bytes',
            new=lambda x: '\xbaa\x1c\xd00w\xb6\xb3\xb6\xbdh~\x8e8\x10|'
        ):
            ciphertext, headers = encrypt_payload(
                key=self.KEY,
                auth=self.AUTH,
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
                key=self.KEY,
                auth=None,
                payload=self.PLAINTEXT
            )

            self.assertIsNotNone(ciphertext)
            self.assertIn(HEADER_ENCRYPTION_KEY, headers)
            self.assertEqual(
                headers.get(HEADER_ENCRYPTION),
                'keyid=p256dh;salt=umEc0DB3trO2vWh-jjgQfA'
            )
