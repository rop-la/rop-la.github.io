---
layout: post
title:  "PolyUDF: Módulo UDF universal de PostgreSQL para Windows"
date:   2020-02-05 00:00:00 -0500
categories: tools
author: RoP Team
lang: es
lang-ref: polyudf-universal-postgresql-udf-module-for-windows
---

La herramienta que estamos liberando el día de hoy tiene como finalidad el acabar con los problemas a los que se enfretan los pentesters cuando desean conseguir ejecución de comandos del OSen un servidor de base de datos con PostgreSQL. En este caso específicos sobre plataforma Windows.

Normalmente para poder aprovechar el acceso con privilegios dba (como el usuario *postgres* por ejemplo) en una instancia PostgreSQL sobre Windows, uno tendría que compilar el Modulo UDF (DLL) usando las librerias y cabeceras de la versión específica de PostgreSQL, lo cual implica tener instalado el PostgreSQL y el Visual Studio en la versión que podamos conseguir. El objetivo de este proyecto es eliminar todos eso requerimientos, teniendo una sola DLL (por arquitectura x86/x64) que sea compatible con cualquier versión de PostgreSQL desde la versión 9.4 en adelante.

Para lograr este objetivo se emplearon algunas técnicas y métodos que pueden servir para situaciones similares a las encontradas en este caso. Asimismo, se han incorporado funcionalidades no vistas en ningún otro proyecto o módulo desarrollado para este fin. Las principales características de esta herramienta son:<br/><br/>
<em>- Soporte multiversión (9.4+ - Version 1 de la convención de llamada de PostgreSQL) y multiarquitectura (x86/x64).</em><br/>
<em>- Una sola función que regitra todas las demás funciones en un solo paso!</em><br/>
<em>- Eliminación limpia del módulo de memoria. Permite eliminar el DLL del disco sin tener que reiniciar el servicio de PostgreSQL.</em><br/>

Ahora sin más palabras, es hora de un video:

{:refdef: style="text-align: center;"}
[![PolyUDF on action!](http://img.youtube.com/vi/-89qvnDvFek/0.jpg)](http://www.youtube.com/watch?v=-89qvnDvFek "PolyUDF - PostgreSQL universal UDF module for Windows"){:target="_blank"}
{: refdef}

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