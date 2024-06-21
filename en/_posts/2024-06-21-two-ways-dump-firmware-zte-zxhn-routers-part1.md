---
layout: post-linenums
title: "Two ways to dump the firmware of the ZTE ZXHN routers part 1"
author: "Nox"
description: "Dump firmware of the ZTE ZXHN routers part 1"
keywords: "reversing, hardware"
date: 2024-06-21 00:00:00 -0500
categories: reversing 
lang: en
lang-ref: two-ways-dump-firmware-zte-zxhn-routers-part1
---

I have been using a ZTE ZXHN router for several years because it is the router provided by the ISP IPlan in Argentina. Since I generally like to analyze and pwn the things I use in my free time —literally breaking them— I started investigating. This ISP provides at least the following versions of this model for households: F670, F680, and F6600, of which I have used the latter two to develop this research. Nevertheless, this method will likely work for many other versions of the ZTE ZXHN model, or even other devices that meet the conditions that will be outlined in this post.

There are many ways to obtain the firmware. In this post, I will document two methods that I have not read about —although there is surely information available— for hot firmware extraction through a vulnerability in the SAMBA service configuration and via UART, but with a slightly different twist.

<!--more-->

### Firmware dumping via UART

The most commonly used and simplest protocol for IoT and embedded devices. This time, I will recount my adventures with the F680 router, but as I mentioned earlier, this can be extrapolated to other models of the ZTE router or other devices given the conditions.

To start this extraction process, you have to open the router very carefully because, as it supports fiber optics, you might damage the connection to the router and be left without the internet for a few days —like what happened to me. When examining the PCB to look for the four pin connections, I couldn't find them, but when I turned it over, there they were. So, I began soldering some pins to connect to it, and using a USB to TTL adapter, you can interact with the interface provided by the router.

At this point, I tried [several documented methods][1], but they didn't work for me. One day was left before the ISP technician came to replace my router because I had broken a cable while opening it. So, I started considering two options: buying a programmer —since the NAND memory is a Winbond W25N— and extracting the firmware quickly, although I would be cutting it close as the order would arrive the same day they were replacing my router, or using the tools provided by the router itself and extracting it via command line. It would be slow, but it might work. Otherwise, I would have to break another router to continue the firmware extraction, which would certainly annoy everyone at home again.


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

In the boot process an option is showed to enter in the boot setup.

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

There are some options, for example the line 11 list `\`.

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

One method is to try to overwrite the boot variables. To do this, I need to know what they are by using the `printenv` command

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

Then, overwrite the variable `bootargs` using the `setenv` command to add `init=/bin/sh` and continue the boot process

```
=> setenv bootargs console=ttyAMA0,115200n8 root=/dev/mtdblock9 ro rootfstype=jffs2 mem=128M init=/bin/sh
=> saveenv
=> bootm 0x44000000
```

The result is

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
It does not work. It's possible that error -2 corresponds to [`ENOENT`][2], meaning that our precious `sh` is not present in the filesystem at the time the command is executed.

Let's see some interesting commands again.

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

Here we can hypothesize that while in the boot configuration, executing bootm 0x44000000 means that the Linux Kernel Image is already loaded in the flash memory (volatile memory).

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
And simply to dump it, we need to save the log and convert it to a binary file using `xxd -r -p <input.txt> <output.bin>`. My idea is —and please correct me if I'm wrong— to use the combination of `nand read` to write the firmware from the NAND memory to the flash memory. Then, using `md.b` —whose functionality we've already seen— we can dump what is in the flash memory and obtain the firmware. How do we do this, and why does it need to be done this way? Let's take a look.

After being given the option to enter the boot configuration, the reading of the firmware and its writing in memory continue and it can be save it in the log of the UART interface to which we are connected.

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

Furthermore, line 15 onward indicates which part of the NAND memory contains the filesystem, and all this happens after the option to enter the boot configuration. The astute reader will notice that there are two filesystems, the first named `rootfs0` at the NAND memory address `0x01a20000` and the second `rootfs1` located at `0x03a20000`. You might wonder, why are there two filesystems? Let me tell you, this is common in such devices that require a certain level of redundancy. A backup filesystem is added to the NAND memory so that if the one being loaded is corrupted, the backup can be used. In this case, as we see on line 20, the default filesystem used is `rootfs1`.

With all this information, it’s time to wrestle with the `nand` command.

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

`nand dump` works! Now with `nand read`, the use format is `nand read <memory addr> <nand offset> <size>`

```
=> nand read 0x400000 0x1a00000 0x100

NAND read: device 0 offset 0x1a00000, size 0x100
 256 bytes read: OK
```

It seems to work as well! So let's get started. But before diving in, [let's see an example taken from the internet][3] on how it should work.

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

Now, how it works in my case

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


But there's no need to panic, we can use the last option, `nand dump`, which we already know works. Unfortunately, it only dumps 0x800 bytes. Additionally, given that we're in an asynchronous communication setup, there's almost certainly going to be some discrepancy in our dump. But it doesn't matter, the next day they were going to replace my router anyway, and I'd have to open the new one—without breaking it—resolder the pins, and start over, so I had nothing to lose.

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

After a few hours of execution, I have the firmware dumped in cold! Of course, I would then need to mount the directories if I wanted to have it as close as possible to when the router is initialized and running, which I wasn't keen on doing. So, I began looking for another way to get a shell on the router, and that's what the second part will be about: how to obtain a shell through SAMBA to finally dump the filesystem in hot.

For this part, I must thank my colleague [Octa][50], who provided his time, help, advice, and links. Thank you!

> Written by **Nox**

[1]: https://www.synacktiv.com/publications/i-hack-u-boot.html
[2]: https://man7.org/linux/man-pages/man3/errno.3.html
[3]: https://elinux.org/Didj_U_Boot_Flashing_Primer
[50]: https://x.com/ogianatiempo
