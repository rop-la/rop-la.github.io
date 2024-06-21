---
layout: post-linenums
title: "Dos métodos para volcar el firmware del routers ZTE ZXHN parte 1"
author: "Nox"
description: "Volcar firmware de routers ZTE ZXHN parte 1"
keywords: "reversing, hardware"
date: 2024-06-21 00:00:00 -0500
categories: reversing 
lang: es
lang-ref: two-ways-dump-firmware-zte-zxhn-routers-part1
---
He estado usando durante varios años un router ZTE del modelo ZXHN ya que es el router que brinda el ISP IPlan en Argentina y como por lo general en el tiempo libre me gusta analizar las cosas que uso y romperlas -literalmente -. Este ISP brinda para los hogares al menos las siguientes versiones de este modelo F670, F680 y F6600, de las cuales las dos últimas las he usado para desarrollar esta investigación. De todas maneras, esto método probablemente funcione para muchas más versiones del modelo ZTE ZXHN, o incluso otros dispositivos que cumplan las condiciones que serán desarrolladas en este post. 

De todas maneras, hay muchas maneras de poder obtener el firmware. En este post voy a documentar dos métodos que yo no leído - aunque seguramente habrá información al respecto - , para la extracción firmware en caliente a través de una debilidad en la configuración del servicio SAMBA, y a través de UART, pero con un toque tinto distinto.

<!--more-->

### Extracción del firmware a través de UART

Una vez más, el protocolo más usado y sencillo usado por IoT y dispositivos embebidos. En esta ocación relataré mis aventuras con el router F680, pero como mencionó anteriormente, esto se puede extrapolar para los otros modelos del router ZTE, u otros dispositivos dadas las condiciones.

Para iniciar este proceso de extracción se tiene que abrir el router con mucho cuidado porque al soportar fibra óptica, podemos dañar la conexión que existe hacia el router y quedarnos sin internet por algunos días - cómo me pasó a mí :( -. Al observar el PCB para buscar las cuatro conexiones no las encontré, pero al voltearla estaban allí, así que comencé a soldarle unos pines para poder conectarme, y usando un _USB to TTL adapter_ se puede interactuar con la interfaz que nos brinda el router.

En este punto intenté varias cosas [que están documentadas][1] pero no me funcionaron. Faltaba un día para que vengan a cambiarme el router porque había un roto un cable al abrirlo D: - así que comencé a barajear dos opciones, comprarme un programador - pues la memoria NAND es un Winbond W25N - y podría extraer el firmware rápidamente aunque iba a estar al límite porque el pedido me llegaría el día que me cambiaron el router, o usar las herramientas que brindaba el propio router y extraerlo por línea de comandos, sería lento pero tal vez funcionaría. Sino me tocaría romper otro router para seguir con la extracción del firmware y que se vuelvan a molestar conmigo en casa.

```
SF▒▒▒H▒
Boot SPI NAND
1
Boot SPI NAND
1

U-Boot 2013.04 (Apr 30 2021 - 11:17:06)

CPU  : ZX279128@A9,800MHZ
Board: ZTE zx279128evb
DRAM:  128 MiB
com1
product_vid = 75
vid=75-F680
output gpio:49, value=1, 0
output gpio:50, value=1, 0
output gpio:51, value=1, 0
output gpio:52, value=1, 0
8000000,48000000
NAND:  manuid=ef,aa

Manu ID: 0xef, Chip ID: 0xaa (Winbond SPI NAND W25N01GVZEIR+WINBOND 128MiB 3,3V)
128 MiB
<nand_read_skip_bad_,1241>!mtdpart=0x1,offset=0x0,mtdpartoffset=0x180000,mtdPartsize=0x80000,length=0x20000

...

Hit 1 to upgrade software version
Hit any key to stop autoboot:  0
```

Al iniciar el router aparecía la opción de parar el _booteo_, cuando esto se hace nos da un menú con diversas herramientas.

```
Hit 1 to upgrade software version
Hit any key to stop autoboot:  0
=> help
?       - alias for 'help'
boot    - boot default, i.e., run 'bootcmd'
bootd   - boot default, i.e., run 'bootcmd'
bootk   - boot kernel
coninfo - print console devices and information
cp      - memory copy
dhcp    - boot image via network using DHCP/TFTP protocol
downver - upgrade software downloaded from TFTP server
go      - start application at address 'addr'
ls      - list files in a directory (default /)
md      - memory display
mii     - MII utility commands
mtddebug- mtddebug operate
mtest   - simple RAM read/write test
mw      - memory write (fill)
nand    - NAND sub-system
printenv- print environment variables
reset   - Perform RESET of the CPU
saveenv - save environment variables to persistent storage
setenv  - set environment variables
...
```

Esto ya nos diversas opciones que podemos hacer, por ejemplo la línea 11 lista `\`

```
--- jffs2_part_info: partition number 0 for device nand0 (single part)
jffs2_part_info:rootfs0,1a20000
rootfs0,1a20000
 -rw-r--r--  3672273 Wed Oct 28 12:51:20 2020 0uImage
 drwxr-xr-x        0 Wed Oct 28 12:51:17 2020 bin
 drwxr-xr-x        0 Wed Oct 28 12:23:44 2020 dev
 drwxr-xr-x        0 Wed Oct 28 12:51:18 2020 etc
 drwxr-xr-x        0 Wed Oct 28 12:51:16 2020 home
 -rwxr-xr-x       66 Wed Oct 28 12:23:29 2020 init
 drwxr-xr-x        0 Wed Oct 28 12:51:20 2020 kmodule
 drwxr-xr-x        0 Wed Oct 28 12:51:15 2020 lib
 lrwxrwxrwx       12 Wed Oct 28 12:41:44 2020 linuxrc -> /bin/busybox
 drwxr-xr-x        0 Wed Oct 28 12:23:29 2020 mnt
 drwxr-xr-x        0 Wed Oct 28 12:23:29 2020 proc
 drwxr-xr-x        0 Wed Oct 28 12:23:29 2020 root
 drwxr-xr-x        0 Wed Oct 28 12:51:20 2020 sbin
 drwxr-xr-x        0 Wed Oct 28 12:23:29 2020 sys
 drwxr-xr-x        0 Wed Oct 28 12:23:29 2020 tagparam
 lrwxrwxrwx        7 Wed Oct 28 12:23:29 2020 temp -> var/tmp
 lrwxrwxrwx        7 Wed Oct 28 12:23:29 2020 tmp -> var/tmp
 drwxr-xr-x        0 Wed Oct 28 12:23:29 2020 userconfig
 drwxr-xr-x        0 Wed Oct 28 12:23:29 2020 usr
 drwxr-xr-x        0 Wed Oct 28 12:23:29 2020 var
 drwxr-xr-x        0 Wed Oct 28 12:23:29 2020 wlan
```

Uno de los tantos métodos es sobreescribir las variables de _booteo_, para ello veamos cuáles están establecidos con el comando `printenv`

```
=> printenv
baudrate=115200
bootcmd=setenv bootargs console=$(console) root=/dev/mtdblock9 ro rootfstype=jffs2  mem=$(memsize);bootm 0x44000000;
bootdelay=2
bootfile=uboot.bin
console=ttyAMA0,115200n8
ethact=eth0
ethaddr=00:41:71:00:00:50
filesize=382421
fullfile=upgrade.bin
gatewayip=192.168.1.1
hostname=unknown
ipaddr=192.168.1.1
linuzfile=vmlinuz.bin
loadaddr=0x44000000
memsize=128M
nand_erasesize=20000
nand_oobsize=40
nand_writesize=800
netmask=255.255.255.0
netretry=5
serverip=192.168.1.100
stderr=serial
stdin=serial
stdout=serial
versioninfo=U-Boot V6.0.20P3N14B 20210430114200 0x3a00000 0x1 0x83 0x8f
```

Entonces se sobreescribe la variable `bootargs` con el comando `setenv` para agregar la variable `init=/bin/sh` y continuar el _booteo_

```
=> setenv bootargs console=ttyAMA0,115200n8 root=/dev/mtdblock9 ro rootfstype=jffs2 mem=128M init=/bin/sh
=> saveenv
=> bootm 0x44000000
```

El resultado es

```
Kernel panic - not syncing: Requested init /bin/sh; failed (error -2).
CPU: 1 PID: 1 Comm: swapper/0 Not tainted 4.1.25 #56
Hardware name: ZTE ZX279128 (Device Tree)
[<c000fe68>] (unwind_backtrace) from [<c000ccdc>] (show_stack+0x10/0x14)
[<c000ccdc>] (show_stack) from [<c04ad5f8>] (dump_stack+0x94/0xa8)
[<c04ad5f8>] (dump_stack) from [<c04ab600>] (panic+0xc4/0x22c)
[<c04ab600>] (panic) from [<c04a9bf8>] (kernel_init+0x98/0xf4)
[<c04a9bf8>] (kernel_init) from [<c000a428>] (ret_from_fork+0x14/0x2c)
```

No funciona, y posiblemente ese error -2 corresponda a [ENOENT][2], es decir que nuestro tan preciado `sh` no se encuentra en el _filesystem_ en el momento de la ejecución del comando.

Volvamos a ver otros comandos que nos interesan.

```
=> help
md      - memory display
nand    - NAND sub-system

=> nand
nand device
nand info
nand read addr ofs|partition size
nand read.oob addr ofs|partition size
nand write addr ofs|partition size
nand read.raw addr ofs|partition [count]
nand write.raw addr ofs|partition [count]
nand dump
...
```
Aquí podemos conjeturar que estando en la configuración del _booteo_, podemos ejecutar `bootm 0x44000000`, quiere decir que en la memoria flash (memoria volátil) ya está cargado el Linux Kernel Image.

```
=> md.b 0x44000000 3679265
44000000: 27 05 19 56 ef af 97 d7 60 8b 77 51 00 38 23 e1    '..V....`.wQ.8#.
44000010: 40 00 80 00 40 00 80 00 0c 5b 51 e6 05 02 02 00    @...@....[Q.....
44000020: 4c 69 6e 75 78 20 4b 65 72 6e 65 6c 20 49 6d 61    Linux Kernel Ima
44000030: 67 65 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ge..............
44000040: 00 00 a0 e1 00 00 a0 e1 00 00 a0 e1 00 00 a0 e1    ................
44000050: 00 00 a0 e1 00 00 a0 e1 00 00 a0 e1 00 00 a0 e1    ................
44000060: 03 00 00 ea 18 28 6f 01 00 00 00 00 70 0d 38 00    .....(o.....p.8.
44000070: 01 02 03 04 00 90 0f e1 88 0d 00 eb 01 70 a0 e1    .............p..
44000080: 02 80 a0 e1 00 20 0f e1 03 00 12 e3 01 00 00 1a    ..... ..........
44000090: 17 00 a0 e3 56 34 12 ef 00 00 0f e1 1a 00 20 e2    ....V4........ .
440000a0: 1f 00 10 e3 1f 00 c0 e3 d3 00 80 e3 04 00 00 1a    ................
440000b0: 01 0c 80 e3 0c e0 8f e2 00 f0 6f e1 0e f3 2e e1    ..........o.....
...
```

Y simplemente para volcarlo debemos guardar el log y convertirlo a un _binary file_ con `xxd -r -p <input.txt> <output.bin>`. Mi idea es - y por favor corríganme si me equivoco- usar la combinación de `nand read` para poder escribir desde la memoria NAND hacia la memoria flash el firmware, entonces con `md.b` - que ya vimos su funcionamiento -, volcar lo que se encuentra en memoria flash y obtener el firmware. ¿Cómo hacemos eso?, ¿y por qué tiene que ser así? Veámoslo.

Después de que se nos brinde la opción de entrar a la configuración del _booteo_, la lectura del firmware y su escritura a memoria continua, esto lo podemos ver en el log de la interfaz UART donde estamos conectados.


```
Hit 1 to upgrade software version
Hit any key to stop autoboot:  0
addr=1a00000
addr=3a00000
select=0x0
search=0x2
<nand_read_skip_bad_,1241>!mtdpart=0x4,offset=0x0,mtdpartoffset=0x200000,mtdPartsize=0x400000,length=0x1000
BootImageNum=0x00000001,1
select=0x1
search=0x2
search->result[1].entry=3a00140
mtd_length=1660000
<nand_read_skip_bad_,1241>!mtdpart=0x3,offset=0x0,mtdpartoffset=0x3a00000,mtdPartsize=0x2000000,length=0x1660000

---mtdparts_init--current_mtd_partnum=1-
part  : name = rootfs0, size = 0x01700000, offset = 0x01a20000
part  : name = rootfs1, size = 0x01640000, offset = 0x03a20000

--- jffs2_part_info: partition number 1 for device nand0 (single part)
jffs2_part_info:rootfs1,3a20000
### JFFS2 loading '0uImage' to 0x44000000
Scanning JFFS2 FS: .................... done.
### JFFS2 load complete: 3679265 bytes loaded to 0x44000000
<nand_read_skip_bad_,1241>!mtdpart=0x0,offset=0x0,mtdpartoffset=0x0,mtdPartsize=0x200000,length=0x80000
```

Además, la línea 15 en adelante nos indica en qué parte de la memoria NAND se encuentra el _filesytem_ y todo esto sucedes **después** de la opción de entrar a la configuración de _booteo_. El lector hábil se habrá dado cuenta de que existen dos _filesystem_, el primero denominado `rootfs0` en la dirección de la memoria NAND `0x01a20000` y el segundo `rootfs1` localizado en `0x03a20000`. Tal vez se pregunte, ¿por qué hay dos filesystem?, déjame decirte que esto es usual en este tipo de dispositivos que requieren cierta independencia, ya que se agrega a la memoria NAND un _filesystem_ de respaldo, entonces si el que se intenta cargar está dañado, se podrá usar el de respaldo, en este caso, como vemos en la línea 20, el _filesystem_ usado por defecto es `rootfs1`.

Con toda esta información, nos toca pelearnos con el comando `nand`. 

```
=> nand dump 0x1a00000
Page 01a00000 dump:
        99 99 99 99 44 44 44 44  55 55 55 55 aa aa aa aa
        28 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00  00 00 00 00 56 36 2e 30
...
```

`nand dump` funciona! Ahora con `nand read`, el formato de uso es `nand read <memory addr> <nand offset> <size>`

```
=> nand read 0x400000 0x1a00000 0x100

NAND read: device 0 offset 0x1a00000, size 0x100
 256 bytes read: OK
```

Al parecer funciona también! Así que el ruedo. Pero antes [como debería funcionar de un ejemplo tomado por internet][3]

```
LF1000 # nand read 1800000 0 800

NAND read: device 0 offset 0x0, size 0x800
 2048 bytes read: OK
LF1000 # md 1800000 10
01800000: e59fd004 eb000001 ea000b6c 00228000    ........l.....".
01800010: e59fc034 e3a03001 e58c3000 e59c3008    4....0...0...0..
01800020: e3a00b02 e52de004 e3833080 e3a0e000    ......-..0......
01800030: e1a01000 e3a02b7e e58c3008 e58ce008    ....~+...0......
```

Ahora, como funciona

```
=> nand read 400000 1a00000 100

NAND read: device 0 offset 0x1a00000, size 0x100
 256 bytes read: OK
=> md.b 0x00400000 100
00400000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
00400010: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
00400020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
00400030: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
00400040: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
```

:(

Pero no hay que desesperarnos, podemos usar la última opción `nand dump`, que ya vimos que funciona. Lamentablemente solo nos dumpea 0x800 bytes. Además, al estar en una comunicación asíncrona es casi segura que haya un desfase en nuestro volcado. Pero qué más da, al día siguiente ya me iban a cambiar el router y tendría que abrir el nuevo - sin romperlo - volver a soldar los pines y empezar nuevamente, así que nada que perder. 

```
import sys
import time
import serial

class MySerial:
    def __init__(self, tty, baudrate = 115200, timeout = 1):
        self.ser = serial.Serial(tty, baudrate, timeout=timeout)
        self.ser.flush()
        self.ser.flushInput()
        self.ser.flushOutput()

    def read(self):
        data = self.ser.read().decode('latin-1')
        time.sleep(0.05)

        data += self.ser.read(self.ser.inWaiting()).decode('latin-1')
        return data

    def readuntil(self, msg):
        data = self.read()
        while msg not in data:
            data += self.read()
        return data
    
    def write(self, data):
        self.ser.write(data.encode('latin-1'))
        time.sleep(0.5)

    def writeline(self, data):
        self.write(data + '\n')
    
    def read_from_nand(self, offset, size, offset_end):
        data = ''
        off = 0
        idx = 0
        while offset + off < offset + size and offset + off < offset_end:
            cmd = 'nand dump 0x{:08x}'.format(offset + off)

            self.ser.flush()
            self.ser.flushInput()
            self.ser.flushOutput()

            self.writeline(cmd)
            self.writeline('\n'*5)
            tmp = self.readuntil('=>')

            start = tmp.find('dump:')
            end = tmp.find('OOB:')

            print('{}: {} ## {},{}'.format(idx, cmd, start, end))

            chunk = tmp[start+7:end-1].rstrip()

            if start != 36 or end != 6571:
                continue

            off += 0x800
            idx += 1

            with open('rootfs1.txt', 'a') as f:
                f.write(chunk+'\n')


if __name__ == '__main__':
    serial = MySerial('/dev/ttyCH341USB0', 115200, 2)
    
    offset = 0x01a00000
    size = 0x01700000
    end = offset + size

    offset = 0x3a00000
    size = 0x1660000
    end = offset + size

    data = serial.read_from_nand(offset, size, end)
    print('Done')

```

Después de unas horas de ejecución, !tengo el firmware volcado en frío! Claro, había luego que montar los directorios si quisiera tenerlo lo más parecido posible a cuando el router está ya inicializado y funcionando, algo que no me apatecía. Así que comencé a buscar otra manera de obtener una shell en router, ¡y de eso se tratará la segunda parte!, como obtener shell a través de SAMBA para finalmente volcar el _filesystem_ en caliente.

Para esta parte debo agradecer a mi colega [Octa][50], que me brindó su tiempo, ayuda, consejos y links. ¡Gracias!

> Escrito por **Nox**

[1]: https://www.synacktiv.com/publications/i-hack-u-boot.html
[2]: https://man7.org/linux/man-pages/man3/errno.3.html
[3]: https://elinux.org/Didj_U_Boot_Flashing_Primer
[50]: https://x.com/ogianatiempo
