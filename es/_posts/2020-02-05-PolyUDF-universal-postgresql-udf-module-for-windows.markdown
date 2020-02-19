---
layout: post
title:  "PolyUDF: Módulo UDF universal de PostgreSQL para Windows"
date:   2020-02-05 00:00:00 -0500
categories: tools
author: RoP Team
lang: es
lang-ref: polyudf-universal-postgresql-udf-module-for-windows
---

La herramienta que estamos liberando el día de hoy tiene como finalidad acabar con los problemas a los que se enfretan los pentesters cuando desean conseguir ejecución de comandos en un servidor de base de datos con PostgreSQL. En este caso específicos sobre plataforma Windows.

Usualmente, para poder aprovechar el acceso con privilegios dba (como el usuario *postgres*) en una instancia PostgreSQL sobre Windows, se tie que compilar el Modulo UDF (DLL) usando las librerías y cabeceras de la versión específica de PostgreSQL, implicando un mayor trabajo instalar la versión de PostgreSQL, además de Visual Studio (o el compilador de su preferencia), y hacerlo cada vez que la versión de PostgreSQL sea distinta. El objetivo de este proyecto es eliminar todos esos requerimientos, teniendo una sola DLL (por arquitectura x86/x64) que sea **compatible con cualquier versión de PostgreSQL** desde la versión 9.4 en adelante. Para lograrlo, se emplearon algunas técnicas y métodos que pueden servir en situaciones similares a las encontradas en este caso. Asimismo, se han incorporado funcionalidades no encontradas en ningún otro proyecto o módulo desarrollado para este fin. <br/>
Las principales características de esta herramienta son:
- Soporte multiversión (9.4+, version 1 de la convención de llamada de PostgreSQL)
- Soporte para x86 y x64.
- Una función que regitra todas las demás funciones en un solo paso.
- Eliminación limpia del módulo de memoria, permitendoe eliminar el DLL del disco sin tener que reiniciar el servicio de PostgreSQL.

Demo:

<div align="center"><iframe width="560" height="315" src="https://www.youtube.com/embed/-89qvnDvFek" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe></div>

## Liberando a Poly!
Para poder acceder al código fuente del proyecto pueden visitar el repositorio en nuestra cuenta de [Github][1].

## Detalles técnicos
Si desean conocer toda la historia y el detalle técnico detras de PolyUDF, pueden leer nuestro [post en ingles]({{ site.baseurl }}{% link en/_posts/2020-02-05-PolyUDF-universal-postgresql-udf-module-for-windows.markdown%})

Siganos en nuestras cuentas de Twitter [@rop-la][rop-twitter] en nuestro repositorio público de Github [RoP-LA][rop-github] y en nuestro canal de [Youtube][rop-youtube]

[rop-web]: https://www.rop.la
[rop-twitter]:   https://twitter.com/rop_la
[rop-github]:   https://github.com/rop-la/
[rop-youtube]: https://www.youtube.com/channel/UCg01TfhxLro71ppULtIBAjw
[1]:https://github.com/rop-la/PolyUDF