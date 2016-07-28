# webpush-payload-encryption

Python package to handle the encryption of push notifications for Firefox
and Chrome.

Intended to support Firefox v46 and later, Chrome v44 and later.

# Installation

`pip install webpush_encryption`

This package requires the `cryptography` python package, which has
some installation dependencies. See https://cryptography.io/en/latest/installation/ 

# Usage

The subscription information for web push contains either one or two
encryption keys:

* the _public key_
* the _auth_ secret, which is not present in some older Firefox
  subscriptions

We generally assume these are stored as base64-encoded strings. They're
returned from [`PushSubscription.getKey`](https://developer.mozilla.org/en-US/docs/Web/API/PushSubscription/getKey) as
`ArrayBuffers`. In Javascript, an `ArrayBuffer` can be base-64 encoded with:

```javascript
/**
 * Converts an ArrayBuffer of bytes to a Base64 encoded string, ready
 * for inclusion in a JSON payload. Useful for working with encryption keys.
 */
/* istanbul ignore next */
var encodeByteArray = function(bytes) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(bytes)));
};
```

Given the _public key_, a payload `dict` and optionally an `auth`
key, you can call `encrypt_payload` to get the encrypted data (the
_ciphertext_) and the HTTP _headers_ needed when POSTing to either
Google Cloud Messaging or the `endpoint` URL of a Firefox web
push subscription:

```python
    import webpush_encryption
    
    ciphertext, headers = webpush_encryption.encrypt_payload(
        key=public_key_base64,
        auth=auth_key_base64,
        payload=the_payload_dict
    )

```


If you store the key and auth un-encoded (or your code already
decodes them from base64), you can call `encrypt_encoded_payload`
directly:

```python
    import json
    import webpush_encryption
    
    ciphertext, headers = webpush_encryption.encrypt_encoded_payload(
        key=public_key,
        auth=auth_key,
        payload=json.dumps(the_payload)
    )

```

# References

https://tools.ietf.org/html/draft-ietf-webpush-encryption, specifically
https://tools.ietf.org/html/draft-ietf-webpush-encryption#section-3

# Releases

1. Setup the `venv` and `pip install setuptools twine`
2. Run the tests: `python setup.py test`
3. Update the version in `setup.py`

