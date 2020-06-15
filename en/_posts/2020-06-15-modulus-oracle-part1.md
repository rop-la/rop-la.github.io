---
layout: post
title: "Modulus Oracle: Breaking a RSA misuse"
author: "RoP Team"
description: "A misuse of RSA allow us to break the cryptosystem"
keywords: "RSA, crypto, oracle, modulus"
date: 2020-06-15 00:00:00 -0500
categories: pentesting
lang: en
lang-ref: modulus-oracle-part1
---

The last year, while we are performed an ethical hacking assessment, we found a curious vulnerability in a cryptosystem implementation based on RSA.

Our client centralized the authentication of their internal applications in a web login. This login, after to verify the username and password, redirects to the selected internal application and pass a misterious Base64 encoded parameter to such application. Obviously, we decoded it to reveal its content, but we got just a random binary stream. The content was encrypted.

<!--more-->

So we unsuccessfully perform some crypto tests to looking for vulnerabilities like *Padding Oracle* and with one of them we got a *modulus error*. And so we discovered that the encryption was RSA.

### Understanding the test

RSA use the aritmethic operation **modulo**. This operation finds the remainder in a division. The divisor is known as the **modulus** and usually is represented as $$N$$. The values that RSA can encrypt or decrypt must be theorically in the range $$[0, N-1]$$ but in practice this range is lower for security reasons. If we try to encrypt a message greater than $$N$$, part of the message will be lost. For this reason many RSA implementations check for the message value and throws an exception if it is greater than the modulus. Similarly for decryption operations.

In our test, we sent a too long input to the internal application. The application decoded it from Base64 and got a number greater than its RSA modulus. Then, when tries to decrypt it, throws an unhandled exception: *modulus error*.

```
http://internal-app/verify?secret=AAAAAAAAAAAA[...]AAAA
```

### The cryptosystem

After the centralized login validate the user credentials, it needs send to the internal application a message with the user information. But this message contains sensitive information so it is necessary to protect it. For that the applications hat a preconfigured RSA public/private keys pair. So the first application uses the public key to encrypt the message and send it to the second one by a redirect through the browser. Then the internal application uses the private key to decrypt the message, recover the user information and starts his session.

![img01](/assets/img/202006/diagram01.svg){: class="image fit" style="max-width: 800px;"}

### The vulnerability

If we want to send a fake message to the internal application we need the ability to encrypt arbitrary messages. That is, we need the *public key*. But in this case the *public key* is not really public. I means, it is stored in the server and we can't access to it. However, we found a way to obtain it.

A RSA public key is composed by two numbers: the modulus $$N$$ and the public exponent $$e$$. The most common public exponent is $$65537$$. This value is a convention to optimize the calculus. In other hand, the modulus is the result from multiplying two large prime numbers $$p$$ and $$q$$ that are generated randomly. If we discover the modulus we will obtain the public key.

#### Modulus Oracle

Do you remember the *modulus error* from the beginning? We can use this error as an oracle. When we send a encrypted message that results in a number greater than the RSA modulus, we get a *modulus error* and when is lower, we obtain another type of error. So we can use a binary search algorithm to recover the modulus value. Since the binary search get one bit of information with each request, we need as many requests as bits the modulus has. In example, for a RSA 1024 key we need arround 1024 requests.

### Demo

We hat coded a Flask application that simulates this vulnerability. For dramatic effects, in this case the message is a command line and if you get the public key you will achieve RCE. Also we hat included the script `modulus-oracle.py` that implements the *Modulus Oracle Attack*. You can download this demo from our [github repository](https://github.com/rop-la/modulus-oracle).

And now, view it in action:

<iframe width="560" height="315" src="https://www.youtube.com/embed/gQRgRELH6Zw" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

<br>

We are investigating another useful scenarios where to apply this *Modulus Oracle Attack* but we tell you more in the next post.

See you then!


> Writen by **RoP Team**