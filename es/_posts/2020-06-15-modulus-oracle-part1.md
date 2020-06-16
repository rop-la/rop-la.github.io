---
layout: post
title: "Modulus Oracle: Rompiendo un mal uso de RSA"
author: "RoP Team"
description: "Un mal uso de RSA nos permite romper el sistema de cifrado"
keywords: "RSA, crypto, oracle, modulus"
date: 2020-06-15 00:00:00 -0500
categories: pentesting
lang: es
lang-ref: modulus-oracle-part1
---

El año pasado, mientras realizábamos un *Ethical Hacking*, encontramos una curiosa vulnerabilidad en la implementación de un sistema de cifrado basado en RSA.

Nuestro cliente centralizó la autenticación de sus aplicaciones internas en un login web. Este login, luego de verificar el nombre de usuario y la contraseña, redirige a la aplicación interna seleccionada y le pasa un misterioso parámetro codificado en Base64. Obviamente lo decodificamos para revelar su contenido, pero solo obtuvimos datos binarios aleatorios. El contenido estaba cifrado.

<!--more-->

Así que realizamos, sin éxito, algunas pruebas de criptografía para buscar vulnerabilidades como *Padding Oracle* y con una de ellas obtuvimos un *modulus error*. Y así descubrimos que el cifrado era RSA.

### Comprendiendo la prueba

RSA usa la operación aritmética **módulo**. Esta operación obtiene el resto de una división. El divisor se conoce como el **módulo** y generalmente se representa como $$N$$. Los valores que RSA puede cifrar o descifrar deben estar teóricamente en el rango $$[0, N-1]$$ pero en la práctica este rango es menor por motivos de seguridad. Si intentamos cifrar un mensaje mayor que $$N$$ parte del mensaje se perderá. Por esta razón muchas implementaciones de RSA revisan el valor del mensaje y lanzan una excepción cuando es mayor que el módulo. De forma similar para las operaciones de descifrado.

En nuestra prueba, enviamos una entrada demasiado grande a la aplicación interna. La aplicación la decodificó de Base64 y obtuvo un número mayor que su módulo RSA. Entonces, al descifrarlo, lanzó una excepción no controlada: *modulus error*.

```
http://internal-app/verify?secret=AAAAAAAAAAAA[...]AAAA
```

### El sistema de cifrado

Después de que el login centralizado valida las credenciales del usuario, este necesita enviar un mensaje a la aplicación interna con la información del usuario. Pero este mensaje contiene información sensible así que es necesario protegerlo. Para ello, las aplicaciones tienen preconfigurado un par de llaves RSA pública/privada. Así la primer aplicación usa la llave pública para cifrar el mensaje y lo envía a la segunda mediante una redirección a través del navegador. Entonces la aplicación interna usa la llave privada para descifrar el mensaje, recuperar la información del usuario e iniciar su sesión.

![img01](/assets/img/202006/diagram01.svg){: class="image fit" style="max-width: 800px;"}

### La vulnerabilidad

Si queremos enviar un mensaje falso a la aplicación interna necesitamos la capacidad de cifrar mensajes arbitrarios. Para ello necesitamos la *llave pública*. Pero en este caso la llave pública no es realmente "pública". Quiero decir, está almacenada en el servidor y no podemos acceder a ella. Sin embargo, encontramos un modo de obtenerla.

Una llave pública RSA se compone de dos números: el módulo $$N$$ y el exponente público $$e$$. El exponente público más común es $$65537$$. Este valor es una convención para optimizar el cálculo. Por otro lado, el módulo es el resultado de multiplicar dos primos grandes $$p$$ y $$q$$ generados aleatoriamente. Si logramos descubrir el módulo, obtendremos la llave pública.

#### Modulus Oracle

¿Recuerdas el *modulus error* del principio? Podemos usar este error como un oráculo. Cuando enviamos un mensaje cifrado que resulta en un número mayor que el módulo RSA, obtenemos un *modulus error* y cuando es menor, obtenemos otro tipo de error. Así podemos usar un algoritmo de búsqueda binaria para recuperar el valor del módulo. Puesto que la búsqueda binaria obtiene un bit de información con cada solicitud, necesitamos tantas solicitudes como bits tenga el módulo. Por ejemplo, para una llave RSA 1024 necesitaremos aproximadamente 1024 solicitudes.

### Demo

Hemos programado una aplicación en Flask que simula esta vulnerabilidad. Para efectos dramáticos, en este caso el mensaje es un comando y si obtienes la llave pública lograrás RCE. También hemos incluido un script `modulus-oracle.py` que implementa el *Modulus Oracle Attack*. Puedes descargar esta demo desde nuestro [repositorio de Github](https://github.com/rop-la/modulus-oracle).

Y ahora, veámoslo en acción:

<iframe width="560" height="315" src="https://www.youtube.com/embed/C91ej0HSFPA" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

<br>

Estamos investigando otros escenarios útiles donde aplicar este *Modulus Oracle Attack* pero te contaremos más en el siguiente post.

¡Hasta entonces!

> Escrito por **RoP Team**