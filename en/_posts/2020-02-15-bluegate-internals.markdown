---
layout: post
title:  "BlueGate Internals"
date:   2020-02-25 00:00:00 -0500
categories: vulnerabilities
author: RoP Team
lang: en
lang-ref: bluegate-internals
---

## BlueGate internals
While I was on vacations, there was a patch on RD Gateway CVE-2020-0609 and CVE-2020-0610, I never listen about a Gateway on Remote Desktop so I found it interesting to analyze.

I stopped sunbathing on the beach, turned on the laptop and started. After doing a PoC that worked correctly triggering a DoS, some post began to apper about that. Then, I was in doubt if I should write about t, and here we are.

<!-- more -->
### RD Gateway
RD Gateway, previously [Terminal Services Gateway (TS Gateway)][2], has a business focus, allows routing for a Remote Desktop out side of the enterprise. RD Gateway allows use several policies to users can authenticate, then the gateway will forward RDP traffic to the windows machine specified by the user, allowing only the gateway to be exposed to the internet and not access to RDP directly.

You can access to  RD Gateway using two protocols, DTLS over UDP, and HTTP over TLS. Both make a socket, binding on the respective port, set the socket mode calling to `WSAIoctl`, and finally calls `CreateThreadpoolIo` to create i/o thread pool, setting `CAAUdpServerTransport::IoCompletionCallback` function as callback for UDP,  and `CAAHttpServerTransport::IoCompletionCallback` for HTTP, .

RD Gateway HTTP protocol allows websocket and [processing requests][3] scheme (see the link for more information). For the last one, the API supplies a request `HTTP_REQUEST_V2` structure to parse in `CAAHttpServerTransport::ParseRequest`, after that follows his path  hentication based on the arguments passed.

RD Gateway UDP protocol allows large message, but when a  large message is processed it will be split in multiple separate fragments which will be rebuilt later. To interact with the client for receiving and sending data only two main functions are used: `CAAUdpServerTransport::HandleRecvComplete` and `CAAUdpServerTransport::HandleSendComplete`.

### BlueGate
Both vulnerabilities CVE-2020-0609 and CVE-2020-0610 exist in `CAAUdpConnection::HandleReceiveDataWhenConxStateIsSecured`. But, how do I get there?  

The server change its status according to the operation being processed, for example when it is starting the DTLS handshake (state 2), authentication (state 3), finishing (state 5), calling `CAAUdpConnection::ChangeServerState` function. After DTLS handshake I can reach the `CAAUdpConnection::HandleReceiveDataWhenConxStateIsSecured` function (state 3). 

    0:024> k
     # Child-SP          RetAddr           Call Site
    00 0000001e`1cb7e320 00007ffc`991c4daa aaedge!CAAUdpConnection::HandleReceiveDataWhenConxStateIsSecured+0x241
    01 0000001e`1cb7f0f0 00007ffc`991cb490 aaedge!CAAUdpConnection::OnReceiveDataComplete+0x366
    02 0000001e`1cb7f3c0 00007ffc`991cb0c8 aaedge!CAAUdpServerTransport::HandleRecvComplete+0x3a0
    03 0000001e`1cb7f480 00007ffc`be5c6760 aaedge!CAAUdpServerTransport::IoCompletionCallback+0x108
    04 0000001e`1cb7f4b0 00007ffc`c134ee19 KERNEL32!BasepTpIoCallback+0x50
    05 0000001e`1cb7f500 00007ffc`c1350348 ntdll!TppIopExecuteCallback+0x129
    06 0000001e`1cb7f580 00007ffc`be5c7974 ntdll!TppWorkerThread+0x3c8
    07 0000001e`1cb7f870 00007ffc`c136a271 KERNEL32!BaseThreadInitThunk+0x14
    08 0000001e`1cb7f8a0 00000000`00000000 ntdll!RtlUserThreadStart+0x21

&nbsp;

To build a valid packet we can check the  `CAAUdpConnection::ValidatePacket(CAAUdpConnection *this, struct UDP_FRAGMENT *pkt, unsigned int pkt_len)` function, then set a bp there and send data.
```python
conn.send("A"*0xFF)
```
    0:024> r rdx, r8, r13
    rdx=0000020e74be206d r8=00000000000000ff r13=0000020e74be206d
    0:024> dq rdx l6
    0000020e`74be206d  41414141`41414141 41414141`41414141
    0000020e`74be207d  41414141`41414141 41414141`41414141
    0000020e`74be208d  41414141`41414141 41414141`41414141

For this function register `rdx`  is the packet address, `r13` for the caller, and `r8` is the packet length.

```nasm
.text:00000001800685D3                 movzx   ecx, word ptr [rdx]
.text:00000001800685D6                 sub     ecx, 1
.text:00000001800685D9                 jz      short loc_18006860A
.text:00000001800685DB                 sub     ecx, 2
.text:00000001800685DE                 jz      short loc_180068600
.text:00000001800685E0                 sub     ecx, 1
.text:00000001800685E3                 jz      short loc_1800685FA
.text:00000001800685E5                 cmp     ecx, 1
.text:00000001800685E8                 jnz     short loc_180068602
.text:00000001800685EA                 cmp     r8d, 0Ah
.text:00000001800685EE                 jb      short loc_180068602
.text:00000001800685F0                 movzx   ecx, word ptr [rdx+8]
.text:00000001800685F4                 lea     eax, [r8-0Ah]
...
.text:0000000180068618                 cmp     eax, ecx
.text:000000018006861A                 jnb     short loc_180068600
```
The first word is compared with the type of the fragment and if it is 5 then  `[rdx+8]` is the length of the fragment. We reach that conclusion  because it is compared directly with `r8` that is length of the packet minus a constant `0x0A` (this assembly is used to subtract the header length of the full length), if this value is lower than the header length then it  returns an error code, else it returns 0. Knowing all of that, I can add that information to show the decompiled C code.

```c
v3 = 0x8000FFFF;
/* ... */
if ( packet->type != 1 )
{
  if ( packet->type != 3 )
  {
    if ( packet->type != 4 )
    {
      if ( packet->type != 5 || packet_length < 0xA )
        return v3;
      v5 = (unsigned __int16)packet->fragment_length;
      v6 = packet_length - HDR_FRGMNT_LEN; //10
      goto LABEL_19;
    }
/* ... */
 LABEL_19:
    if ( v6 < v5 )
      return 0x80070005;
    return 0;
```
&nbsp;

Now going back to the caller, to the vulnerable function. `r13` is the packet address and `r14` is the *this* object reference.
```nasm
.text:0000000180065308 movzx   ecx, word ptr [r13+6]
.text:000000018006530D mov     [r14+668h], ecx
...
.text:0000000180065322 mov     edx, ecx
...
.text:0000000180065388 movzx   ecx, word ptr [r13+4]
.text:000000018006538D cmp     ecx, edx
.text:000000018006538F jbe     loc_180065426
```
That assembly construction is used to check an out of bounds of index, at the end of that snippet you can see how it is used as index `cmp     [r14+rdx*4+568h], ecx`. Then, `[r13+4]` is an index or ID, remember that a large message is split in multiple fragments that must carry an ID to be reconstructed, and `[r13+6]` is the total number of fragments that will be processed, for that reason the comparison is made, to know if all the fragments were received,  ` jbe     loc_180065426`. 

#### Another bug
Following with the same idea, when a fragment is received it will check if any previous fragment has already been received.

```nasm
.text:0000000180065426 mov     rdx, rcx
.text:0000000180065429 xor     ecx, ecx
.text:000000018006542B cmp     [r14+rdx*4+568h], ecx
.text:0000000180065433 jz      short loc_180065461
```
If the fragment was received, the result will be true and the execution flow jump to the function epilogue. But if it is fales execution flow will continue. Now, `rdx` is `packet->fragment_id`, and I control it. So if I set `packet->number_of_fragments = 0xFFFF` and `packet->fragment_id = 0xFFFE`, a crash will be triggered.

    (a24.bcc): Access violation - code c0000005 (first chance)
    First chance exceptions are reported before any exception handling.
    This exception may be expected and handled.
    aaedge!CAAUdpConnection::HandleReceiveDataWhenConxStateIsSecured+0x587:
    00007ff9`6e05542b 41398c9668050000 cmp     dword ptr [r14+rdx*4+568h],ecx ds:000001a5`0a44c3d0=????????
    0:023> r rdx
    rdx=000000000000fffe

This Windbg  output show how setting the fields previously mentioned triggering a DoS.

#### CVE-2020-0609/0610
I know that `[r13+8]` is `packet->fragment_length`, and is comparison directly with `[r14+564h]`. What idea comes to your mind? Maybe be the maximum size of the buffer? Yeah that's what it is.
```nasm
.text:0000000180065461 movzx   eax, word ptr [r13+8]
.text:0000000180065466 add     eax, [r14+560h]
.text:000000018006546D cmp     eax, [r14+564h]
.text:0000000180065474 jbe     short loc_1800654C1
```
Remember that the fragments will be rebuilt and put in a buffer, `[r14+564h]` or `this->buffer_maximum_size` is the maximum size of the buffer and if I look at a debugger I'll see the value `0x1000`. Next, `[r14+560h]` is adding with `packet->fragment_length`, which makes us think that it saves the count of bytes that have been written. In summary, `packet->fragment_length + this->bytes_written` can determine if it is exceeding the maximum buffer size `jbe     short loc_1800654C1`:  `if ((packet->fragment_length + this->bytes_written) <= this->buffer_maximun_size){/*continue*/}else{return err;}`. Is easy to pass the check? Yes, only send the field `fragment_length` with a lower value than `0x1000`, because the **key for trigger the vulnerabilities** is `fragment_id`. Let's see what follows after this:

&nbsp;
Here I found the CVE-2020-0609 vulnerability.
```nasm
.text:00000001800654C1 loc_1800654C1:
.text:00000001800654C1 mov     [r14+rdx*4+568h], r8d
```

This bugs has no mistery, `rdx` is `fragment_id`, and setting it with a calculated value you can overwrite  inside the object :D but only with `(uint32_t) 1` value, only with high addresses and relative to the position where it starts :(. Another hazard is that `fragment_id` should not be a high value, e.g. `0xFFFE` because the memory address `[r14+rdx*4+568h]` that will be accessed will result in unmapped memory (see "Another bug").

    aaedge!CAAUdpConnection::HandleReceiveDataWhenConxStateIsSecured+0x61d:
    00007ff9`713354c1 4589849668050000 mov     dword ptr [r14+rdx*4+568h],r8d ds:0000026c`700dbf18=00000000
    0:024> r rdx
    rdx=0000000000000200
    0:024> dq 0000026c`700dbf18 l1
    0000026c`700dbf18  00000000`00000001



&nbsp;
After that, it's found the CVE-2020-0610 vulnerability.

```nasm
.text:00000001800654C9 lea     r8, [r13+UDP_FRAGMENT.fragment] ; Src
.text:00000001800654CD movzx   eax, [r13+UDP_FRAGMENT.fragment_id]
.text:00000001800654D2 mov     edx, 1000       ; DstSize
.text:00000001800654D7 movzx   r9d, [r13+UDP_FRAGMENT.fragment_length] ; MaxCount
.text:00000001800654DC imul    rcx, rax, 1000
.text:00000001800654E3 add     rcx, [r14+558h] ; Dst
.text:00000001800654EA call    cs:__imp_memcpy_s
```
How I said, the key is `fragment_id` because it is used as an index without a correct check to avoid out of bounds. 

    memcpy_s(&this->buffer[packet->fragment_id * 1000], 1000, &packet->fragment, packet->fragment_len);
    this->bytes_written += packet->fragment_len;
In this vulnerability multiply `packet->fragment_id * 1000`, and if I set the same value in it, 0x200 and considering that the buffer maximum size is 0x1000  I'll write out of the buffer.

    0:024> 
    rcx=0000026c702ddde0 rdx=00000000000003e8 
    aaedge!CAAUdpConnection::HandleReceiveDataWhenConxStateIsSecured+0x646:
    00007ff9`713354ea 48ff1597900300  call    qword ptr [aaedge!_imp_memcpy_s (00007ff9`7136e588)] ds:00007ff9`7136e588={msvcrt!memcpy_s (00007ff9`943ed300)}
    0:024> dq r14+558 l1
    0000026c`700db708  0000026c`70260de0
    0:024> ? 026c`70260de0 + (0x200*0n1000)
    Evaluate expression: 2664761777632 = 0000026c`702ddde0
The buffer is allocated by `kernel32!LocalAlloc`, that means that the buffer is in another "heap" allocated on top addresses than `CAAUdpConnection` objects :(.

On the patch of those vulnerabilities added checks for fragment_id and number_of_fragments :P. if they are greater than 64 it will return an error code of `0x8000FFFF`, with that information is possible does a scanner sending `fragment_id = 65` and if not is vulnerable it will return the error code previously mentioned.

Finally, the UDP_FRAGMENT packet could be rebuilt as seen in the image. 
![UDP Fragment Layout](/assets/img/202002/udp-packet.png){: width=auto height=auto style="margin-left: auto; margin-right: auto"}

[1]:https://www.kryptoslogic.com/blog/2020/01/rdp-to-rce-when-fragmentation-goes-wrong/
[2]: https://docs.microsoft.com/en-us/windows/win32/termserv/terminal-services-is-now-remote-desktop-services](https://docs.microsoft.com/en-us/windows/win32/termserv/terminal-services-is-now-remote-desktop-services)
[3]: https://docs.microsoft.com/en-us/windows/win32/http/processing-requests](https://docs.microsoft.com/en-us/windows/win32/http/processing-requests)