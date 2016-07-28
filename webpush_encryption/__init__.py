import base64
import json
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import OpenSSL


CONTENT_APPLICATION_OCTET_STREAM = 'application/octet-stream'
HEADER_CONTENT_ENCODING = 'Content-Encoding'
HEADER_CONTENT_LENGTH = 'Content-Length'
HEADER_CONTENT_TYPE = 'Content-Type'
HEADER_COOKIE = 'Cookie'
HEADER_CRYPTO_KEY = 'Crypto-Key'
HEADER_DATE = 'Date'
HEADER_ENCRYPTION = 'Encryption'
HEADER_ENCRYPTION_KEY = 'Encryption-Key'


def encrypt_gcm(key, nonce, plaintext):
    """
    Encrypts the given plaintext with the given AES key in GCM mode.
    Uses the provided nonce to initialize the encryption.
    :returns: the output ciphertext as a string
    """

    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update('\x00\x00' + plaintext) + encryptor.finalize()
    ciphertext += encryptor.tag

    return ciphertext


# pylint: disable=invalid-name
def HKDF_256(**kwargs):
    return HKDF(algorithm=hashes.SHA256(), backend=default_backend(), **kwargs)


def chrome_auth_info(info_type, client_key, server_key):
    return '\0'.join((
        'Content-Encoding: %s' % info_type,
        'P-256',
        (
            struct.pack('>H', len(client_key)) + client_key +
            struct.pack('>H', len(server_key)) + server_key
        )
    ))


def header_encode(value):
    """
    Encodes a binary value in a way that is acceptable for webpush
    encryption headers.

    Firefox 48 and up require no '=' padding on the
    end of the string, so we strip trailing equal signs out.
    """
    return base64.urlsafe_b64encode(value).rstrip('=')


# pylint: disable=too-many-locals
def encrypt_encoded_payload(key, payload, auth=None):
    """
    Perform the encryption on the given JSON payload,
    returning the encrypted text and a set of HTTP headers
    that carry the encryption information.

    The returned headers are suitable for use in a POST
    to the Mozilla autopush server. To use them for
    GCM, the "keyid=p256dh;" preamble should be removed from
    the Crypto-Key and Encryption headers.

    :param key: The public key as raw bytes
    :param payload: The payload, encoded as a JSON string
    :type payload: basestring
    :param auth: The auth secret as raw bytes
    :returns ciphertext string, header dict
    """
    # KEY EXCHANGE
    server_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    server_public_key = server_private_key.public_key().public_numbers().encode_point()

    # This will throw ValueError if the key is invalid. We will handle
    # this in the caller.
    client_public_key = ec.EllipticCurvePublicNumbers.from_encoded_point(
        ec.SECP256R1(), key,
    ).public_key(default_backend())

    shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)

    # KEY DERIVATION
    salt = OpenSSL.rand.bytes(16)

    # If the auth secret is present, we need an additional HKDF stage
    # combining it with the secret key before we derive the actual AES
    # key and nonce.
    if auth is not None:
        prk = HKDF_256(
            length=32,
            salt=auth,
            info='Content-Encoding: auth\0'
        ).derive(shared_secret)
    else:
        prk = shared_secret

    key_info = 'Content-Encoding: aesgcm128'
    if auth is not None:
        key_info = chrome_auth_info(
            info_type='aesgcm',
            client_key=key,
            server_key=server_public_key
        )
    aes_key = HKDF_256(
        length=16,
        salt=salt,
        info=key_info
    ).derive(prk)

    nonce_info = 'Content-Encoding: nonce'
    if auth is not None:
        nonce_info = chrome_auth_info(
            info_type='nonce',
            client_key=key,
            server_key=server_public_key
        )
    nonce = HKDF_256(
        length=12,
        salt=salt,
        info=nonce_info
    ).derive(prk)

    # ENCRYPTION

    ciphertext = encrypt_gcm(aes_key, nonce, payload)

    # JR Conlin's example page (https://jrconlin.github.io/WebPushDataTestPage/)
    # shows the following headers:
    # "crypto-key: keyid=p256dh;dh=BH0bFMn9HBbTY4iS_UJKx3qvzERpn4d0..."
    # "encryption: keyid=p256dh;salt=Wf4pd_Zs_6s0IjBCBN81Rw"
    # "content-encoding: aesgcm"

    # Old FF subscriptions contained no `auth`, in which case we use
    # a different header set.
    if auth is not None:
        crypto_key_header = HEADER_CRYPTO_KEY
        content_encoding = 'aesgcm'
    else:
        crypto_key_header = HEADER_ENCRYPTION_KEY
        content_encoding = 'aesgcm128'

    headers = {
        # See https://tools.ietf.org/html/draft-ietf-webpush-encryption
        HEADER_CONTENT_LENGTH: len(ciphertext),
        HEADER_CONTENT_TYPE: CONTENT_APPLICATION_OCTET_STREAM,

        # https://developers.google.com/web/updates/2016/03/web-push-encryption
        # suggests we use Crypto-Key with 'aesgcm' (not 'aesgcm128'). The
        # Mozilla servers return a 400 stating that we're using an obsolete
        # protocol if we use Crypto-Key with 'aesgcm128'. So we changed to
        # use 'aesgcm'.
        HEADER_CONTENT_ENCODING: content_encoding,
        crypto_key_header: 'keyid=p256dh;dh=%s' % header_encode(server_public_key),
        HEADER_ENCRYPTION: 'keyid=p256dh;salt=%s' % header_encode(salt)
    }

    return ciphertext, headers


def encrypt_payload(key, payload, auth=None):
    """
    Encrypts a push payload using the given ECDH public key.

    :returns: the ciphertext as a string, and the resulting Web Push headers, as a dict.
    """
    return encrypt_encoded_payload(
        base64.b64decode(key),
        json.dumps(payload),
        None if auth is None else base64.b64decode(auth)
    )
