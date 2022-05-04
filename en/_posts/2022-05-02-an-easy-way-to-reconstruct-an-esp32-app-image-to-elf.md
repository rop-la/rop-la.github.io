---
layout: post
title: "An easy way to reconstruct an ESP32 app image to ELF"
author: "Nox"
description: "Reconstructing an ESP 32 app image to ELF format binary"
date: 2022-05-02 00:00:00 -0500
categories: reversing
keywords: "esp32, reversing"
lang: en
lang-ref: an-easy-way-to-reconstruct-an-esp32-app-image-to-elf
---

Three years ago, in a CTF I found a challenge using ESP32 architecture. In that context the time is key, and this blogpost are my notes about how to quickly reconstrut the ESP32 app image challange to an ELF binary.

<!--more-->

A reconstruction from an ESP32 app image to ELF could be trivial with the @lynerc and @_nickmiles_ research. 
They [made a tool][1] for dumping a firmware of an IoT device ESP32 architecture based, where is necessary to specify from the dump the segment
to reconstruct to an ELF. Of course, whole technical explanation in [their talk][2].

The tool doesn't reconstruct an app image by default because the dump of an ESP32 firmware has more segments 
and it only handle that dump format. Anyways, with only a few lines we can use that tool to reconstruct an app image to ELF.

```python
import sys
from esp32_image parser import *

print ("{} {}".format(sys.argv[1], sys.argv[2]))

input_file = sys.argv[1]
output_file = sys.argv[2]

image2elf(input_file, output_file, True)
```

After that, we can use ghidra to decompile it using an external ghidra processor

```
$ sudo apt-get install openjdk-11-jdk
$ git clone https://github.com/Ebiroll/ghidra-xtensa xtensa
$ cd xtensa/
$ make
```

And that's it! 

> Written by [**Nox**][5]

Follow us on our twitter account [@rop-la][rop-twitter], our public Github repositories [RoP-LA][rop-github] and [Youtube Channel][rop-youtube].

[rop-web]: https://www.rop.la
[rop-twitter]: https://twitter.com/rop_la
[rop-github]: https://github.com/rop-la/
[rop-youtube]: https://www.youtube.com/channel/UCg01TfhxLro71ppULtIBAjw

[1]:https://github.com/tenable/esp32_image_parser
[2]:https://www.youtube.com/watch?v=swIvvuSBOkw
[5]:https://twitter.com/MrNox_
