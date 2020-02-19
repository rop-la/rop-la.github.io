---
layout: post
title: "Pwning a miner's C&C"
author: "RoP Team"
description: "A vulnerability in XMRigCC allows to takeover the mining cluster"
keywords: "mineria, monero, xmrigcc, botnet"
date: 2020-02-17 00:00:00 -0500
categories: vulnerability
lang: en
lang-ref: pwning-a-miners-cc
---

The vulnerability that we are disclosing here has been fixed some months before this post. We could not report it timely, but we are happy to finally share this story.

Long time ago, while I was doing a malware analysis on a customer computer, I found a weird Monero miner. This miner had its configuration on a JSON file in plain text without any obfuscation. That is very unusual on a malware, so I decided to investigate a little more.

<!--more-->

The configuration file contains some lines like the following:

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

After googling a couple of keywords from the JSON file, I found the Github repository of [XMRigCC][1]. It's a XMRig fork that includes a web application for remote control and monitoring the miners. XMRigCC was not designed as malware but the attacker has used it as such. And when someone uses software for something that has not been designed for, it's time for vulnerability hunting.

## General overview

XMRigCC is a client-server application and is composed by two binaries: xmrigServer and xmrigDaemon. xmrigDaemon is the mining software itself, it runs on the miner machine and connects to the server to receive instructions and send its status. In other hand, xmrigServer is a HTTP server for command and control. This server have two endpoints: the first one is a web admin panel with the functionality for bots management and monitoring and the second one is a JSON API for bots communication. These endpoints have distinct authentication methods. The admin panel uses Basic Authentication and requires to known a preconfigured username and password. The JSON API uses Bearer Authentication and requires to known a secret token. Obviously the secret token must be the same in client and server configuration files.

## Code analysis

As stated above, today the vulnerability is fixed but you can find the vulnerable source code [here][2].

At the file `src/cc/Service.cpp` we can find the methods `Service::handleGET` and `Service::handlePOST`. Basically these methods compare the requested path with specific paths by using the method `rfind`. If the requested path starts with a specific path, certain method is called to handle the request. Note that the paths don't need to be equal. The specific path only must be included at the beginning of requested path. Then we could append anything to the end of requested path and the handler method will be called anyway.

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

Now, let's take a look the file `src/cc/Httpd.cpp`. We can find the methods `Httpd::tokenAuth` and `Httpd::basicAuth` which implement the authentication mechanisms for the API and admin panel respectively. But, the most interesting code is at `Httpd::handler` method. This method is the responsible to apply the appropriate authentication mechanism. When the string `/client/` is found into the URL, it means the API is being accessed, then the method `tokenAuth` is called. In any other case the called method is `basicAuth`.

Note that, since the `strstr` function returns a pointer to the first occurrence of the searched string, the string `/client/` could be in any position of the URL. Only when the `/client/` string is not present, `strstr` will return NULL and the condition will be false.

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

## The vulnerability

At this point, maybe you've already noticed what is the problem. We can avoid the Basic Auth method (user/password based) to access the admin panel functionality by including the string `/client/` at the end of the URL. In this way, the applied authentication method will be Bearer Auth (token based) and the secret token is known if you are a client (victim) in the mining botnet.

In short, we have a privilege escalation vulnerability to pass from victim machine to botnet master and are very thirsty for revenge }:D

## Proof of Concept

The following command allows to list the clients (victims) connected to XMRigCC. You must replace the secret token and the hostname with the proper ones.

```shell
curl -H 'Authorization: Bearer SECRET' 'http://BOTNET:3344/admin/getClientStatusList/client/'
```

Finally, this video shows how we can exploit the vulnerability to replace the monero wallet address in the clients configuration.

<div align="center"><iframe width="560" height="315" src="https://www.youtube.com/embed/Ol3s-5svYbM" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe></div>

Sorry Naruto*, your kung fu is weak ;)

Thanks for reading!

(*) I use this alias for the attacker because he has used it as password.

[1]: https://github.com/Bendr0id/xmrigCC
[2]: https://github.com/Bendr0id/xmrigCC/tree/2.0.0
