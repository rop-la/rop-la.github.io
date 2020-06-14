---
layout: post
title: "Hackeando una botnet de minería"
author: RoP Team
description: "Vulnerabilidad en XMRigCC permite tomar control del cluster de minería"
keywords: "mineria, monero, xmrigcc, botnet"
date: 2020-02-17 00:00:00 -0500
categories: vulnerability
lang: es
lang-ref: pwning-a-miners-cc
---

La vulnerabilidad que exponemos aquí ha sido corregida algunos meses antes de esta publicación. No pudimos reportarla oportunamente, sin embargo nos alegra poder compartir finalmente esta historia.

Hace mucho tiempo, mientras realizaba un análisis de *malware* en la computadora de un cliente, encontré un extraño *miner* de Monero. Este *miner* tenía su configuración en un archivo JSON en texto plano, sin ningún tipo  de ofuscación. Esto es bastante inusual en un *malware*, así que decidí investigar un poco más.

<!--more-->

El archivo de configuración contenía algunas líneas como las siguientes:

```json
"cc-client": {
    "enabled" : true,
    "url": "localhost:3344",
    "use-tls" : false,
    "access-token": "mySecret",
    "worker-id": null,
    "update-interval-s": 10,
    "use-remote-logging" : true,
    "upload-config-on-start" : true
}
```

Después de buscar en Google algunas palabras clave del archivo JSON, encontré en Github el repositorio de [XMRigCC][1]. Este es un *fork* de XMRig que incluye una aplicación web para control remoto y monitorización de los *miners*. XMRigCC no ha sido diseñado como *malware* pero el atacante lo ha usado así. Y cuando alguien usa un software para algo para lo cual no ha sido diseñado, es momento de buscar vulnerabilidades.

## Vista general

XMRigCC es una aplicación cliente/servidor y se compone de dos binarios: xmrigServer y xmrigDaemon. xmrigDaemon es el software de minería en sí, se ejecuta en la máquina víctima y conecta al servidor para recibir instrucciones y enviar su estado. Por otra parte, xmrigServer es un servidor HTTP para comando y control. Este servidor tiene dos *endpoints*: el primero es es un panel de administración web con la funcionalidad para gestionar y monitorizar los *bots* y el segundo es una API JSON para la comunicación con los *bots*. Estos *endpoints* tienen diferentes métodos de autenticación. El panel de administración usa *Basic Authentication* y requiere conocer un nombre de usuario y contraseña preconfigurados. El API JSON usa *Bearer Authentication* y requiere conocer un *token* secreto. Obviamente el *token* secreto debe ser el mismo en los archivos de configuración del cliente y el servidor.

## Análisis de código

Como se dijo antes, hoy la vulnerabilidad está corregida pero puedes encontrar el código vulnerable [aquí][2].

En el archivo `src/cc/Service.cpp` podemos encontrar los métodos `Service::handleGET` y `Service::handlePOST`. Básicamente, estos métodos comparan la ruta solicitada con rutas específicas usando el método `rfind`. Si la ruta solicitada inicia con una ruta específica, cierto método es llamado para manejar la solicitud. Observe que las rutas no necesitan ser iguales. La ruta específica solo debe estar incluida al inicio de la ruta solicitada. Entonces, podemos añadir cualquier cosa al final de la ruta solicitada y el método manejador será llamado igualmente.

```csharp
unsigned Service::handleGET(const Options* options, const std::string& url, const std::string& clientIp, const std::string& clientId, std::string& resp)
{

// [...]

	if (url == "/") {
		resultCode = getAdminPage(options, resp);
	} else if (url.rfind("/admin/getClientStatusList", 0) == 0) {
		resultCode = getClientStatusList(resp);
	} else if (url.rfind("/admin/getClientConfigTemplates", 0) == 0) {
		resultCode = getClientConfigTemplates(options, resp);
	} else {

// [...]
```

Ahora echemos un vistazo al archivo `src/cc/Httpd.cpp`. Podemos encontrar los métodos `Httpd::tokenAuth` y `Httpd::basicAuth` los cuales implementan los mecanismos de autenticación para el API y el panel de administración respectivamente. Pero, el código más interesante está en el método  `Httpd::handler`. Este método es el responsable de aplicar el mecanismo de autenticación apropiado. Cuando la cadena `/client/` se encuentra en la URL, significa que el API está siendo accedida, entonces se llama al método `tokenAuth`. En cualquier otro caso se llama al método `basicAuth`.

Observe que, dado que `strstr` devuelve un puntero a la primera ocurrencia de la cadena buscada, la cadena `/client/` podría estar en cualquier posición de la URL. Solo cuando la cadena `/client/` no está presente, `strstr` retornará NULL y la condición será falsa.

```csharp
int Httpd::handler(void* httpd, MHD_Connection* connection, const char* url, const char* method, const char* version, const char* upload_data, size_t* upload_data_size, void** con_cls)
{

// [...]

    if (strstr(url, "/client/")) {
        unsigned status = static_cast<Httpd*>(httpd)->tokenAuth(connection, clientIp);
        if (status != MHD_HTTP_OK) {
            return sendResponse(connection, status, nullptr, CONTENT_TYPE_JSON);
        }
    } else {
        std::string resp;
        unsigned status = static_cast<Httpd*>(httpd)->basicAuth(connection, clientIp, resp);
        if (status != MHD_HTTP_OK) {
            MHD_Response* rsp = nullptr;
            if (!resp.empty()) {
                rsp = MHD_create_response_from_buffer(resp.length(), (void*)resp.c_str(), MHD_RESPMEM_MUST_COPY);
            }
            return sendResponse(connection, status, rsp, CONTENT_TYPE_HTML);
        }
    }

// [...]
```

## La vulnerabilidad

En este punto, quizá ya has notado cual es el problema. Podemos evitar el método *Basic Auth* (basado en usuario y contraseña) para acceder a la funcionalidad del panel de administración incluyendo la cadena `/client/` al final de la URL. De esta forma, el método de autenticación aplicado será *Bearer Auth* (basado en *token*) y el *token* secreto es conocido cuando eres un cliente (víctima) en la *botnet* de minería.

En resumen, tenemos una vulnerabilidad para escalar privilegios de máquina víctima a maestro de la *botnet* y mucha sed de venganza }:D

## Prueba de concepto

El siguiente comando permite listar los clientes (víctimas) conectados a XMRigCC. Debes reemplazar el *token* secreto y el nombre de *host* con los apropiados.

```shell
curl -H 'Authorization: Bearer SECRET' 'http://BOTNET:3344/admin/getClientStatusList/client/'
```

Finalmente, este vídeo muestra como podemos explotar la vulnerabilidad para reemplazar la dirección del *wallet* de Monero en la configuración de los clientes.

<div align="center"><iframe width="560" height="315" src="https://www.youtube.com/embed/Ol3s-5svYbM" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe></div>

Lo siento Naruto*, tu kung fu no es bueno ;)

Gracias por leer!

(*) Uso este alias para el atacante debido a que él lo usaba como contraseña.

[1]: https://github.com/Bendr0id/xmrigCC
[2]: https://github.com/Bendr0id/xmrigCC/tree/2.0.0
