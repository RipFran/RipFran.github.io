---
title: "HTB: Starting point Tier 0"
date: 2022-09-10 19:00:00 +/-TTTT
categories: [HTB, Starting Point]
tags: [redis,ftp,telnet,rdp,mongo]     ## TAG names should always be lowercase
image: /photos/2022-09-10-Starting_point-Tier-0/htb.jpg
---

> Actualizado 4-10-2022
{: .prompt-info }

En este post vamos a estar resolviendo las máquinas ***Tier 0* del *Starting Point* de *Hack the Box***. Son las máquinas **mas fáciles** de la plataforma y nos ayudarán a familiarizarnos con las técnicas básicas de **reconocimiento** y **penetración**. También haré una pequeña introducción de como funciona la plataforma y de como conectarse a la VPN de *HTB*.

## Funcionamiento de HTB

El objetivo de las máquinas de *HTB* es conseguir dos banderas: la **user flag** y la **root flag**, que son básicamente un archivo que contiene un *hash*.

*   La user flag se obtiene normalmente consiguiendo adentrarse en la máquina víctima (esto no es siempre así, a lo mejor se tiene que pivotar entre usuarios para poder tener acceso a ella). 

*   La root flag, en cambio, atiende a una escalada de privilegios. Una vez estas dentro, deberás efectuar una escalada de privilegios para convertirte en el usuario root y poder tener asi el control total de la máquina víctima.

En este punto ya habrás *pwneado* la máquina. Este es el reto que te pone *HTB* pero el principal objetivo siempre es aprender y probar diferentes formas de vulnerar los sistemas.

La plataforma ofrece un **nivel 0 para aquellos usuarios mas principiantes**. Este nivel 0 que ellos llama ***Starting Point*** se divide en 3 partes: *Tier 0, Tier 1 y Tier 2*. La metodología en estas secciones varia un poco a la del resto de máquinas que no pertenecen al *Starting Point*. Con la finalidad de hacer una intrusion mas guiada, en vez de conseguir las típicas dos flags, la plataforma te hará una serie de preguntas sobre la máquina y las tendrás que contestar. No obstante, yo **solo me centraré en la forma de conseguir las flags de *root***.

## Poniendo en marcha la VPN de HTB 

Para conectarte y a la plataforma *tendrás* que utilizar una VPN. La VPN es diferente dependiendo si estás comprometiendo máquinas de HTB, si estás resolviendo el *Starting Point* o si resuelves fortresses. 

*   Simplemente se debe de bajar un archivo (el nombre del archivo VPN de las máquinas del *starting point* suele ser *starting_point_tuUsuario.ovpn* ) y ejecutarlo con la herramienta *openvpn* (por ejemplo, en mi caso sería **sudo openvpn starting_point_R1pFr4n.ovpn**).

*   El proceso se debe dejar corriendo todo el tiempo. Una vez aquí, se te asignará una ip (la puedes ver haciendo *ifconfig* y suele trabajar en la **interfaz tun0**) y ya podrás resolver las máquinas. 

**Nota**: Te recomiendo que para comprobar si tienes conexión enciendas una máquina y pruebes a enviarle un *ping*. Si el *ping* no llega es que hay algo mal configurado. Si tienes algún problema: [https://help.hackthebox.com/en/articles/5185536-connection-troubleshooting](https://help.hackthebox.com/en/articles/5185536-connection-troubleshooting).

## Tier 0 

Como he comentado anteriormente, estas son las mas fáciles de la plataforma y recomiendo que empiecen por aquí todas aquellas personas que se adentran por primera vez en el mundo del *hacking*. Ahora bien, es bastante recomendable que se tengan nociones básicas de *Linux* (saber utilizar una terminal, comandos principales...).  

Resolveré tanto las máquinas gratis como las VIP. En cuanto al VIP de HTB lo recomiendo al 100%, ya que esta suscripción te proporciona el acceso a todas las máquinas retiradas de la plataforma y están todas solucionadas.


## Meow 

*   *Meow* es una máquina que únicamente tiene abierto el **puerto 23** , *Telnet*. *Telnet* sirve para establecer una conexión remota con otro equipo por la línea de comandos y controlarlo.  No es un protocolo seguro ya que la autenticación y todo el tráfico de datos se envía sin cifrar.

### Fase de reconocimiento
El primer paso es saber si nos estamos enfrentando a una máquina **Windows o Linux**. Para ello enviaremos un *ping* a la máquina victima. Debemos tener en cuenta que el **Time To Live (TTL)** de los paquetes que envía una máquina **Linux es de 64** mientras que el de las **Windows es de 128**. Por lo tanto, si en el paquete recibido tiene un TTL **menor o igual a 64 la maquina será Linux**. Por el contrario, si el TTL es **menor o igual a 128 será una máquina Windows**. Como curiosidad, el TTL disminuye a medida que el paquete pasa por nodos intermediarios.

![](/photos/2022-09-10-Starting_point-Tier-0/meow/ping.jpg)

De la captura anterior vemos que es una máquina **Linux ya que su TTL es menor o igual a 64**.

Ahora que ya sabemos a que tipo de máquina nos estamos enfrentando, **escanearemos todos los puertos** del *host* victima en busca de aquellos que estén **abiertos** (estos son los que ofrecen algún tipo servicio de cara al exterior y que podremos intentar vulnerar para adentrarnos en la máquina). El volcado del escaneo es el siguiente:

![](/photos/2022-09-10-Starting_point-Tier-0/meow/allports.jpg)

**nmap** será la herramienta principal de la fase de reconocimiento.  

**-sS** efectúa un *TCP SYN Scan*, iniciando rápidamente una conexión sin finalizarla.  
**-min-rate 5000** sirve para enviar paquetes no mas lentos que 5000 paquetes por segundo.  
**-n** sirve para evitar resolución DNS.  
**-Pn** para evitar host discovery.  
**-vvv** triple verbose para que nos vuelque la información que vaya encontrando el escaneo.  
**-p-** para escanear todo el rango de puertos.  
**--open** para escanear solo aquellos puertos que tengan un *status open*.  
**-oG** exportará la evidencia en formato *grepeable* al fichero **allPorts**. Este formato nos permitirá extraer la información mas relevante de la captura a través de un *script* que tengo configurado en mi *zshrc* llamado **extractPorts**. El *script* es el siguiente:

![](/photos/2022-09-10-Starting_point-Tier-0/meow/extractports.jpg)

Simplemente se tiene que **pegar este *script* en la *.zshrc*** (si utilizáis *bash* en vez de *zsh* será en el archivo .*bashrc*) y al ejecutarlo nos copiará todos los puertos abiertos de la máquina víctima en la **clipboard**.

![](/photos/2022-09-10-Starting_point-Tier-0/meow/extract.jpg)

En este caso pasándole al *script* como parámetro el fichero *allPorts*, nos copiará en la *clipboard* el puerto 23. 

El sentido de este proceso es que ahora vamos a ejecutar un análisis de las versiones de cada puerto abierto. En este caso solo hay un puerto, pero en ocasiones, cuando hay bastantes, nos ahorrará tiempo el no tener que escribirlos todos de forma manual. El escaneo del que hablo es el siguiente:

![](/photos/2022-09-10-Starting_point-Tier-0/meow/targeted.jpg)

**-sCV** es el conjunto de **-sC** que lanza un conjunto de scripts de reconocimiento y **-sV** que extrae la versión y el servicio que corre para cada puerto.  
**-oN** guarda la evidencia en formato *nmap*. En este caso guardaremos el volcado con el nombre *targeted*.  
**-p** sirve para indicar los puertos que quieres escanear. En este caso solo el 23. Como lo tenemos copiado en la *clipboard*, lo pegamos.

**Este proceso es el mismo para todas las máquinas: descubrir si es una máquina Windows o Linux, ver que puertos están abiertos y ver qué versión y qué servicio corren para cada uno de ellos.**

### Puerto 23 abierto (Telnet)

Aunque ya lo sabíamos de antes, la captura **targeted** nos muestra que bajo el puerto 23 está corriendo el servicio de *telnet*.  
Ahora nos podemos conectar a este servicio a través de la herramienta *telnet*.

![](/photos/2022-09-10-Starting_point-Tier-0/meow/telnet0.jpg)

Vemos que nos está pidiendo un usuario de *login*. Como en este punto no sabemos de ningún usuario válido, podríamos probar con credenciales básicas como *root/root, admin/admin o administrator/administrator*. 

![](/photos/2022-09-10-Starting_point-Tier-0/meow/failtelnet.jpg)

Si probamos con *admin/admin o con administrator/administrator* nos pondrá *login incorrect*. En cambio, si nos *logueamos* como *root* obtendremos una *shell* como este usuario:

![](/photos/2022-09-10-Starting_point-Tier-0/meow/telnet.jpg)

A partir de aquí, ya seremos *root*, teniendo privilegios máximos sobre la máquina y ya pudiendo visualizar la *flag (flag.txt)*.  

**Nota**: Si la *shell* no funciona de manera correcta, recomiendo hacer *export TERM=xterm* y *export SHELL=bash*

![](/photos/2022-09-10-Starting_point-Tier-0/meow/flag.jpg)

## Fawn 
*   *Fawn* es una máquina que tiene el **puerto 21**  abierto (FTP). Gracias a los *scripts* básicos de reconocimiento que lanza *nmap* podremos ver que tendremos acceso al servidor como el usuario *anonymous*. Este usuario no requiere de contraseña para *loguearse*. Una vez *logueados*, podremos visualizar la *flag*.

### Fase de reconocimiento 

Como la fase de reconocimiento inicial siempre es la misma y la he explicado detalladamente en la máquina anterior, ahora iré al grano. Primeramente enviamos un *ping* para saber si la máquina esta activa y para saber a qué sistema operativo nos estamos enfrentando:

![](/photos/2022-09-10-Starting_point-Tier-0/fawn/ping.jpg)

La máquina está activa y es *Linux*. 

Ahora escanearemos todo el rango de puertos con la misma combinación de parámetros que antes:

![](/photos/2022-09-10-Starting_point-Tier-0/fawn/allports.jpg)

Nos descubre el puerto 21 (FTP). Básicamente el protocolo de transferencia de archivos o FTP es un software para enviar archivos entre ordenadores con cualquier sistema operativo.  

El siguiente paso será lanzar una serie de scripts básicos de enumeración contra el puerto 21. Siguiendo los mismos pasos que antes haríamos un *extractports allPorts*, nos copiaría en la *clipboard* el puerto 21 y procederíamos de la siguiente manera:

![](/photos/2022-09-10-Starting_point-Tier-0/fawn/targeted.jpg)

### Puerto 21 abierto (FTP)

**-sCV** prueba con un conjunto de scripts de reconocimiento para cada puerto. Para el 21, lanza un script llamado ***ftp_anon***. Este script es un *checker* que nos dice si la sesión de anonymous esta habilitada o no. En este caso nos esta diciendo que si que está habilitada. Este usuario no requiere de contraseña para *loguearse*. Por lo tanto, accederemos al servidor a través del comando *ftp*, de la siguiente forma:

![](/photos/2022-09-10-Starting_point-Tier-0/fawn/ftp.jpg)

Como *Name* pondremos *anonymous* y como contraseña simplemente pulsaremos *enter*. Una vez dentro podremos hacer un *dir* para visualizar el contenido del directorio y veremos la *flag*. Para visualizar el contenido de esta, se puede jugar con el comando *get* para descargarla y verla en nuestro equipo local.    

Por lo tanto haremos un *get flag.txt* y saldremos del FTP haciendo un *exit*. Finalmente ya podremos visualizarla en nuestro equipo.

![](/photos/2022-09-10-Starting_point-Tier-0/fawn/flag.jpg)

## Dancing 
*   Dancing es una máquina *Windows* que tiene varios puertos abiertos, entre ellos el **puerto 445**, que ofrece el servicio *SMB*. *SMB* proporciona acceso compartido a archivos e impresoras entre nodos de una red de sistemas. Dentro del directorio compartido *WorkSpaces* nos encontraremos dos carpetas: *Amy.J* y *James.P*. Al visualizar el contenido de la carpeta *James.P* veremos que se encuentra la *flag*.

### Fase de reconocimiento

Una vez mas enviamos un ping a la máquina víctima para saber si tenemos conexión con ella y para saber su sistema operativo:

**Nota** : El parámetro *-c 1* indica que solo quiero enviar un paquete ICMP.

![](/photos/2022-09-10-Starting_point-Tier-0/dancing/ping.jpg)

Como el *TTL* es menos o igual a 128, quiere decir que nos estamos enfrentando a una máquina *Windows*.

Ahora descubrimos que puertos tiene abiertos la máquina:

![](/photos/2022-09-10-Starting_point-Tier-0/dancing/portscan.jpg)

Estamos viendo que nuestro *target* tiene varios puertos abiertos, vamos a describir cada uno de ellos:  

**135** ofrece el servicio *Microsoft RPC*. Nos podremos conectar a este servicio con herramientas como *rpcclient* incluso con una sesión de invitado (sin credenciales). Información relevante que podríamos encontrar aquí son los usuarios pertenecientes al dominio y los grupos del mismo.  

**139,445** ofrecen el servicio SMB. Como he mencionado antes, *SMB* proporciona acceso compartido a archivos e impresoras entre nodos de una red de sistemas. Hay varias herramientas para auditar este servicio. Luego veremos algunas.  

**5985** ofrece el servicio WinRM (Windows Remote Management). Te permite administrar una máquina *Windows* de forma remota, pero necesitarás credenciales para hacerlo. Digamos que es como un SSH en *Linux*. Herramientas como *evil-winrm* te permiten conectarte si es que tienes credenciales de un usuario del sistema víctima que pertenezca al grupo *Remote Management Users*.  

Los puertos mas altos también pertenecen a *microsoft RPC*.

Ahora que ya sabemos mas o menos a lo que nos estamos enfrentando, vamos a probar una serie de *scripts* básicos de reconocimiento para cada puerto abierto. Después de hacer *nmap -sCV -p135,139,445,5985,47001,49664,49666,49667,49668,49669 10.129.1.12 -oN targeted*, obtenemos el siguiente volcado:

**Nota**: Si tenéis *batcat* instalado, recomiendo meterle el parámetro *-l python* al *cat targeted* para verlo mas bonito.

![](/photos/2022-09-10-Starting_point-Tier-0/dancing/targeted.jpg)

### Puerto 445 abierto (SMB)

Ahora que ya lo tenemos claro todo, yo recomiendo siempre empezar por enumerar el servicio SMB. Primeramente tiraremos de la herramienta *crackmapexec* que nos enumerará de forma general el servicio. Entre otras cosas, podremos ver la arquitectura de la máquina y también el nombre del dominio.

En este caso nos enfrentamos a un Windows de 64 bits (x64) con nombre de dominio *Dancing* (*domain:Dancing)*

![](/photos/2022-09-10-Starting_point-Tier-0/dancing/cme.jpg)

Luego con *smbmap* y *smbclient* podremos listar los ficheros compartidos. Siempre me gusta utilizar las dos por si alguna falla tener la otra a mano. 

Empezaremos con la herramienta *smbmap*. Con el parámetro *-H* indicaremos la IP del host mientras que con *-u* indicaremos el usuario con el que nos queremos conectar. En este caso, como no sabemos de ningún usuario válido, pondremos cualquier cosa en este parámetro para entrar con la sesión de invitado.

![](/photos/2022-09-10-Starting_point-Tier-0/dancing/smb.jpg)

Podemos ver que tenemos permisos de lectura y escritura sobre el directorio *WorkShares* *(Permissions: READ,WRITE)*. Vamos a ver que hay dentro de este directorio. Con el parámetro -r podemos listarlo. De la siguiente forma:

![](/photos/2022-09-10-Starting_point-Tier-0/dancing/smbWorkShares.jpg)

Vemos que hay dos directorios mas: *Amy.J* y *James.P*. Como puede haber mucha mas información dentro de estos directorios y puede resultar muy tedioso mirarlo todo con el parámetro *-r*, *smbclient* ofrece una sesión interactiva, que es básicamente una consola donde podremos maniobrar mucho mejor.

Los dos parámetros que necesitaremos será el parámetro *-N* que indica que queremos un Null Session (es el equivalente a la Guest Session de *smbmap* ya que no tenemos credenciales) y luego la IP del servidor y el recurso compartido al que nos queremos conectar. De la siguiente manera:

![](/photos/2022-09-10-Starting_point-Tier-0/dancing/smbcontent.jpg)

En este punto recomiendo hacer un ***prompt off*** para que cuando descarguemos archivos no nos haga preguntas durante la descarga, ***recurse on*** para que descargue archivos de forma recursiva (archivos dentro de otros) y luego hacer un **mget \*** para descargarlo todo.  

![](/photos/2022-09-10-Starting_point-Tier-0/dancing/james.jpg)

Finalmente, ya con las dos carpetas y su contenido en nuestro ordenador personal, podemos ver que hay dentro y podremos encontrar la *flag* dentro del directorio *James.P*.

![](/photos/2022-09-10-Starting_point-Tier-0/dancing/flag.jpg)

## Redeemer 

*   *Redeemer* es una máquina que únicamente tiene el **puerto 6379** abierto. En este puerto corre el servicio de ***Redis***. Redis es un almacén de estructura de datos en memoria de código abierto, que se utiliza como base de datos, caché...  

Para visualizar la flag básicamente nos conectaremos al servicio como usuario de invitado y en la base de datos disponible podremos encontrarla.  

Como **extra** veremos una forma de ganar ejecución remota de comandos (RCE) en la máquina victima y podernos enviar una *reverse shell*.

### Fase de reconocimiento

Como siempre empezaremos enviándole un *ping* a la máquina víctima. Podemos ver que tenemos conexión a ella y que nos estamos enfrentando a un *Linux*.

![](/photos/2022-09-10-Starting_point-Tier-0/redeemer/ping.jpg)

Procedemos a escanear todo el rango de puertos:

![](/photos/2022-09-10-Starting_point-Tier-0/redeemer/allports.jpg)

 Vemos que solo tiene un ***status open* el puerto 6379, *Redis***. Ahora probando un conjunto de *scripts* de reconocimiento contra el puerto a ver que nos encuentra de interesante:

![](/photos/2022-09-10-Starting_point-Tier-0/redeemer/targeted.jpg)

Solamente nos descubre la versión. Estamos ante un *Redis key-value store 5.0.7*. 

### Puerto 6379 abierto (Redis)

Ahora necesitamos saber la forma de auditar este servicio. Recomiendo tirar de [Hacktricks](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis). *Hacktricks* es un recurso muy interesante que contiene mucha información sobre *pentesting*. Recomiendo siempre pensar en él cuando no sabemos como atacar un puerto.

*Hacktricks* nos recomienda una herramienta llamada *redis-cli* para poder conectarnos de forma interactiva con el servicio. La podemos instalar haciendo un *sudo apt-get install redis-tools*.  

Ejecutaremos el siguiente comando (*redis-cli -h 10.129.119.184*):

![](/photos/2022-09-10-Starting_point-Tier-0/redeemer/rediscli.jpg)

Con el parámetro *-h* indicaremos la IP del *host* víctima.

Es **importante** saber que este servicio suele requerir de credenciales para poder ver el contenido que almacena. Para saber si es necesario proveer de unas, podemos escribir el comando ***INFO***. En caso de requerir autenticación nos saldría el mensaje ***-NOAUTH Authentication required.***

Ahora que ya sabemos que el servicio no necesita autenticación, podemos escribir ***INFO keyspace*** para listar las bases de datos disponibles. Podremos ver la entrada ***db0:keys=4,expires=0,avg_ttl=0***.  
La información que extraemos de esto es que solo hay una BBDD disponible: la ***db0***. ***keys=4*** significa que esta BBDD almacena 4 variables. Podemos listar estas *keys* haciendo un ***KEYS \****. 

Como curiosidad, por defecto *Redis* utiliza la base de datos 0. Si quisiéramos enumerar las keys de una supuesta base de datos 1 tendríamos que hacer ***SELECT 1* y luego *KEYS \**** (en este caso no aplica).

Finalmente veremos que **la key 3 se llama *flag* y con el comando *GET flag* podremos visualizarla**. Todos estos pasos se muestran en la siguiente imagen:

![](/photos/2022-09-10-Starting_point-Tier-0/redeemer/redisflag.jpg)

### Extra: Redis Remote Command Execution (RCE)

En esta sección vamos a estar explotando un ***Remote Command Execution en Redis***. Según el [repositorio](https://github.com/n0b0dyCN/redis-rogue-server) donde he sacado el POC, pone que funciona para versiones *<=5.0.5*. Aunque nosotros hemos visto que la versión de *Redis* que estamos auditando es la *5.0.7*, lo he probado y funciona perfectamente.

Una ejecución remota de comandos consiste en ejecutar comandos en la máquina victima desde tu equipo. Es una vulnerabilidad muy grave, ya que a partir de aquí podriamos hacer que la víctima nos envíe una *shell* interactiva y ejecutar comandos como el usuario que estaba corriendo el servicio vulnerado. Esto es lo que vamos a hacer ahora, a **intentar enviarnos una *reverse shell***.

Lo que haremos será clonar este [repositorio](https://github.com/n0b0dyCN/redis-rogue-server) (git clone https://github.com/n0b0dyCN/redis-rogue-server) y ejecutar el *script* *redis-rogue-server.py*. Deberemos especificar:  

**Host remoto** (--rhost), que es la IP de la máquina victima.  
**Host local** (--lhost), que es la IP de nuestra máquina.  
**Local port** (--lport), que es el puerto por donde queremos recibir nuestra *reverse shell*. En mi caso pondré el 443 pero podría ser cualquier otro que no se estuviera utilizando por otro proceso.

Quedaría de la siguiente forma:

![](/photos/2022-09-10-Starting_point-Tier-0/redeemer/rce.jpg)

Cuando nos pregunte si queremos una *interactive shell* o *reverse shell*, elegiremos la segunda [r].

**NOTA**: **Despues de indicar esta opción [r], nos tendremos que poner en escucha en otra terminal por el puerto deseado (443 en mi caso). Lo podemos hacer con *nc***, de la siguiente forma:

![](/photos/2022-09-10-Starting_point-Tier-0/redeemer/nc.jpg)

**-n**, no queremos aplicar resolución DNS.  
**-l**, para ponernos en escucha.  
**-v**, verbose para que nos vuelque cualquier tipo de información que reciba.  
**-p**, para indicarle el puerto en escucha, en este caso el 443.

Ahora que ya estamos en escucha, volvemos al *script* anterior y nos volverá a preguntar por nuestra IP y por el puerto por el que queremos recibir la *reverse shell*.

Deberíamos recibir la siguiente conexión:

![](/photos/2022-09-10-Starting_point-Tier-0/redeemer/ncconexion.jpg)

¡Hemos recibido una shell de la maquina víctima! Ahora ya podremos ejecutar comandos de forma remota como el usuario que estaba corriendo el servicio de *Redis*, que sorprendentemente se llama también *redis*.

Este es el volcado */etc/passwd/* de la máquina víctima:

![](/photos/2022-09-10-Starting_point-Tier-0/redeemer/passwd.jpg)

## Explosion 

*Explosion* es un máquina Windows que tiene varios puertos interesantes abiertosentre ellos el **puerto 3389** (RDP). Nos vamos a aprovechar de unas **credenciales débiles** para autenticarnos en el servicio RDP (Remote Desktop Protocol), adentrarnos en el sistema y poder  así visualizar la flag.

### Fase de reconocimiento

Como siempre  procedemos a enviarle un *ping* a la máquina para saber si nos estamos enfrentando a un *Linux* o *Windows*. Recuerdo que esta primera fase de reconocimiento está mejor detallada en la primera máquina que hemos resuelto.

![](/photos/2022-09-10-Starting_point-Tier-0/explosion/ping.jpg)

Es una máquina ***Windows*** ya que el TTL es menor o igual a 128.

Procedemos ahora a **escanear** todo el **rango de puerto** de la máquina:

![](/photos/2022-09-10-Starting_point-Tier-0/explosion/allport.jpg)

Y ahora a detectar las **versiones y servicios** que corren para estos puertos con *nmap -sCV -p135,139,445,3389,5985,47001,49664,49665,49666,49667,49668,49669,49670,49671 10.129.121.64 -oN targeted*. Dentro del fichero *targeted* no encontramos con lo siguiente:

![](/photos/2022-09-10-Starting_point-Tier-0/explosion/targeted.jpg)

Menos el puerto 3389, todos los servicios que corren bajo estos puertos abiertos ya los había explicado en la máquina *Dancing*.

*Remote Desktop Protocol* (RDP, *3389 TCP*) es un protocolo que proporciona al usuario una interfaz gráfica para conectarse a otro equipo a través de una conexión de red. Pero necesitaremos poseer de **credenciales** válidas para podernos conectar. 

Teniendo toda esta información en cuenta empezaremos enumerando el servicio SMB.

### Puerto 445 abierto (SMB)

Recordemos que SBM era un protocolo para compartir ficheros en red.  
Primero tiraremos de ***crackmapexec*** para enumerar de forma general el servicio:

![](/photos/2022-09-10-Starting_point-Tier-0/explosion/cme.jpg)

Volvemos a ver que es un máquina *Windows* de 64 bits cuyo nombre de dominio es *Explosion*.

Para enumerar los ficheros compartidos podemos utilizar *smbmap*. Como disponemos de credenciales nos conectaremos utilizando una sesión de invitado:

![](/photos/2022-09-10-Starting_point-Tier-0/explosion/smbmap.jpg)

Vemos que no hay ningún recurso compartido interesante. 

### Puerto 3389 abierto (RDP)

Ya que no hay ningún puerto interesante abierto mas, podemos probar a autenticarnos contra este servicio probando credenciales básicas como *Administrator*, *root*, *admin*...

Vamos a utilizar la herramienta *xfreerdp*.  
La sintaxis seria la siguiente: *xfreerdp \[/d:domain\] /u:Username /p:Password /v:IP*

Después de varias pruebas, descubro que el usuario Administrator no requiere de contraseña para acceder. Esto es un problema de seguridad muy grave del cual nos podemos aprovechar. Por lo tanto, si ejecutamos *xfreerdp \/u:Administrator /v:10.129.121.64*, aceptamos el certificado (Y) y presionamos enter en la contraseña, deberíamos obtener la sesión:

![](/photos/2022-09-10-Starting_point-Tier-0/explosion/rdp.jpg)

Podemos ver que la *flag* se encuentra en el escritorio.

![](/photos/2022-09-10-Starting_point-Tier-0/explosion/flag.jpg)

## Preignition 
*   *Preignition* es un sistema *Linux* que tiene el **puerto 80** expuesto, una pagina web *HTTP*. Aplicando un poco de reconocimiento podremos encontrar un directorio *admin.php* con un panel de *login*. Probando las credenciales débiles *admin/admin* nos podremos autenticar y posteriormente visualizar la *flag*.

### Fase de reconocimiento

Primero, enviaremos un *ping* a la maquina víctima para saber si tenemos conexión con ella y averiguar a que sistema operativo nos estamos enfrentando. 

![](/photos/2022-09-10-Starting_point-Tier-0/preignition/ping.jpg)

En este caso nos enfrentamos a un máquina Linux ya que su *TTL* es menor o igual a 64.

Ahora analizaremos todo el rango de puertos en busca de aquellos que estén abiertos.

![](/photos/2022-09-10-Starting_point-Tier-0/preignition/allports.jpg)

**El único que se encuentra abierto es el 80.**

Ahora lanzamos un conjunto de *scripts* de reconocimiento para este puerto:

![](/photos/2022-09-10-Starting_point-Tier-0/preignition/targeted.jpg)

Podemos ver que, entre otros *scripts*, nmap ha lanzado dos que se llaman *http-title* y *http-server-header*. Nos descubre que como servidor web esta máquina esta utilizando un *nginx* y que el título de la página web es *Welcome to Nginx!*

### Puerto 80 abierto (HTTP)

Una buena práctica antes de abrir el navegador y visualizar la página web, es utilizar la herramienta *whatweb*, que nos descubre las tecnologías que está utilizando el servidor.

![](/photos/2022-09-10-Starting_point-Tier-0/preignition/whatweb.jpg)

En este caso no nos reporta ninguna tecnología que no supiéramos ya.  

También podríamos utilizar *curl* para poder ver las cabeceras, *curl -X GET http://10.129.121.240 -I*:

![](/photos/2022-09-10-Starting_point-Tier-0/preignition/curl.jpg)

Nada interesante tampoco. En este punto abriremos el navegador y visualizaremos la página web:

![](/photos/2022-09-10-Starting_point-Tier-0/preignition/defaultweb.jpg)

Esta es la página por defecto de *Nginx*. De aquí tampoco sacaremos nada interesante. Lo que si que podríamos hacer es  buscar algún directorio que se encuentre bajo la ip *10.129.121.240*. Para ello vamos a aplicar ***fuzzing*** con la herramienta ***wfuzz***. 

El *fuzzing* consiste en enviarle a un sistema *inputs* para ver como se comporta. En nuestro caso, a través de un listado de directorios (diccionario), vamos a probar todos estos contra la pagina web en busca de que alguno nos devuelva un código de estado que no sea el ***404 Not Found*** (Esto quiere decir que el directorio no existe). 

La sintaxis de *wfuzz* que utilizo es:  
*wfuzz -c --hc=404 -u http://10.129.121.240/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 200*.

![](/photos/2022-09-10-Starting_point-Tier-0/preignition/fuzzing.jpg)

**-c** es formato colorizado.  
**--hc=404** para esconder todas las repuestas 404 (No nos interesan ya que son directorios que no existen). *hc* viene de *hide code*.  
**-w** para especificar el diccionario que queremos utilizar. Para *fuzzear directorios yo casi siempre utilizo el mismo, directory-list-2.3-medium.txt*. Este diccionario se puede encontrar en el propio *Parrot OS o en Kali*. También se puede encontrar en el repositorio de [SecLists](https://github.com/danielmiessler/SecLists).  
**-t** para indicar la cantidad de threads que queremos utilizar. 200 hilos es una velocidad bastante rápida que pocas veces suele dar problemas.  
**-u** para especificar la *url*. La palabra *FUZZ* es un término de *wfuzz* y es donde se va a sustituir cada linea del diccionario. 

Así, con este escaneo, estaríamos probando por ejemplo si existe *http://10.129.121.240/index*, *http://10.129.121.240/body*, *http://10.129.121.240/table*...

Después de casi 22.000 peticiones vemos que no encuentra nada. En este punto yo voy a parar el escaneo porque siendo una máquina tan fácil no creo haya algo después del directorio 22.000, pero lo suyo seria recorrer todo el diccionario (220.546 entradas).

También podemos *fuzzear* con extensiones. Yo voy a probar a ver si existe alguna página con la extensión *php*. El escaneo será el mismo pero ahora la url sera *http://10.129.121.240/FUZZ.php*.

![](/photos/2022-09-10-Starting_point-Tier-0/preignition/phpfuzz.jpg)

¡Y vemos que existe un recurso *admin.php*!. En esta página nos vamos a encontrar un panel de login:

![](/photos/2022-09-10-Starting_point-Tier-0/preignition/loginpanel.jpg)

Antes de probar con cualquier tipo de inyección SQL, yo probaría con credenciales básicas como *user/user*, *admin/admin*, *root/root*, *guest/guest*...  
Finalmente, si probamos con *admin/admin* nos podremos autenticar y podremos visualizar la *flag*.

![](/photos/2022-09-10-Starting_point-Tier-0/preignition/flag.jpg)

## Mongod 

*   *Mongod*, la última máquina de esta sección, es una máquina *Linux* que tiene los puertos **22 y 27017** expuestos. El primero es SSH y en el segundo corre el servicio de **MongoDB**. Simplemente nos conectaremos a MongoDB y en una de sus bases de datos encontraremos la **flag**.

### Fase de reconocimiento

Primero, enviaremos un ***ping*** a la maquina víctima para saber si tenemos conexión con ella y averiguar a que sistema operativo nos estamos enfrentando. 

![](/photos/2022-09-10-Starting_point-Tier-0/mongod/ping.png)

En este caso nos enfrentamos a un máquina **Linux** ya que su *TTL* es menor o igual a 64.

Ahora analizaremos todo el **rango de puertos** en busca de aquellos que estén abiertos.

![](/photos/2022-09-10-Starting_point-Tier-0/mongod/allports.png)

**Los puertos abiertos que encuentra son el 22 y el 27017**

Ahora lanzamos un conjunto de *scripts* de reconocimiento para estos puertos con el comando ```nmap -sCV -p22,27017 10.129.138.155 -oN targeted```. Si posteriormente listamos el archivo **targeted** obtenemos lo siguiente:

```ruby
## Nmap 7.92 scan initiated Tue Oct  4 11:57:04 2022 as: nmap -sCV -p22,27017 -oN targeted 10.129.138.155
Nmap scan report for 10.129.138.155
Host is up (0.060s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
27017/tcp open  mongodb MongoDB 3.6.8 3.6.8
| mongodb-databases: 
|   databases
|     1
|       empty = false
|       name = config
|       sizeOnDisk = 73728.0
|     0
|       empty = false
|       name = admin
|       sizeOnDisk = 32768.0
|     4
|       empty = false
|       name = users
|       sizeOnDisk = 32768.0
|     3
|       empty = false
|       name = sensitive_information
|       sizeOnDisk = 32768.0
|     2
|       empty = false
|       name = local
|       sizeOnDisk = 73728.0
|   ok = 1.0
|_  totalSize = 245760.0
| mongodb-info: 
|   MongoDB Build info
|     allocator = tcmalloc
|     versionArray
|       1 = 6
|       0 = 3
|       3 = 0
|       2 = 8
|     modules
|     openssl
|       running = OpenSSL 1.1.1f  31 Mar 2020
|       compiled = OpenSSL 1.1.1f  31 Mar 2020
|     ok = 1.0
|     storageEngines
|       1 = ephemeralForTest
|       0 = devnull
|       3 = wiredTiger
|       2 = mmapv1
|     javascriptEngine = mozjs
|     maxBsonObjectSize = 16777216
|     debug = false
|     sysInfo = deprecated
|     version = 3.6.8
|     bits = 64
|     buildEnvironment
|       distarch = x86_64
|       ccflags = -fno-omit-frame-pointer -fno-strict-aliasing -ggdb -pthread -Wall -Wsign-compare -Wno-unknown-pragmas -Wno-error=c++1z-compat -Wno-error=noexcept-type -Wno-error=format-truncation -Wno-error=int-in-bool-context -Winvalid-pch -O2 -Wno-unused-local-typedefs -Wno-unused-function -Wno-deprecated-declarations -Wno-unused-const-variable -Wno-unused-but-set-variable -Wno-missing-braces -Wno-format-truncation -fstack-protector-strong -fno-builtin-memcmp
|       target_arch = x86_64
|       cxxflags = -g -O2 -fdebug-prefix-map=/build/mongodb-FO9rLu/mongodb-3.6.9+really3.6.8+90~g8e540c0b6d=. -fstack-protector-strong -Wformat -Werror=format-security -Woverloaded-virtual -Wpessimizing-move -Wredundant-move -Wno-maybe-uninitialized -Wno-class-memaccess -std=c++14
|       linkflags = -Wl,-Bsymbolic-functions -Wl,-z,relro -pthread -Wl,-z,now -rdynamic -fstack-protector-strong -fuse-ld=gold -Wl,--build-id -Wl,--hash-style=gnu -Wl,-z,noexecstack -Wl,--warn-execstack -Wl,-z,relro
|       cxx = g++: g++ (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0
|       distmod = 
|       target_os = linux
|       cc = cc: cc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0
|     gitVersion = 8e540c0b6db93ce994cc548f000900bdc740f80a
|   Server status
|     process = mongod
|     uptimeMillis = 253237
|     asserts
|       regular = 0
|       warning = 0
|       user = 0
|       rollovers = 0
|       msg = 0
|     pid = 846
|     ok = 1.0
|     metrics
|       record
|         moves = 0
|       operation
|         scanAndOrder = 0
|         writeConflicts = 0
|       storage
|         freelist
|           search
|             bucketExhausted = 0
|             scanned = 0
|             requests = 0
|       cursor
|         open
|           noTimeout = 0
|           pinned = 0
|           total = 0
|         timedOut = 0
|       queryExecutor
|         scannedObjects = 0
|         scanned = 0
|       commands
|         _recvChunkStatus
|           failed = 0
|           total = 0
|         findAndModify
|           failed = 0
|           total = 0
|         group
|           failed = 0
|           total = 0
|         filemd5
|           failed = 0
|           total = 0
|         dropAllUsersFromDatabase
|           failed = 0
|           total = 0
|         appendOplogNote
|           failed = 0
|           total = 0
|         connPoolSync
|           failed = 0
|           total = 0
|         parallelCollectionScan
|           failed = 0
|           total = 0
|         killCursors
|           failed = 0
|           total = 0
|         lockInfo
|           failed = 0
|           total = 0
|         dropAllRolesFromDatabase
|           failed = 0
|           total = 0
|         listIndexes
|           failed = 0
|           total = 0
|         delete
|           failed = 0
|           total = 0
|         listCollections
|           failed = 0
|           total = 0
|         geoNear
|           failed = 0
|           total = 0
|         getnonce
|           failed = 0
|           total = 0
|         getMore
|           failed = 0
|           total = 0
|         shutdown
|           failed = 0
|           total = 0
|         killAllSessions
|           failed = 0
|           total = 0
|         listDatabases
|           failed = 0
|           total = 1
|         dataSize
|           failed = 0
|           total = 0
|         replSetStepDown
|           failed = 0
|           total = 0
|         collMod
|           failed = 0
|           total = 0
|         replSetGetStatus
|           failed = 0
|           total = 0
|         _recvChunkAbort
|           failed = 0
|           total = 0
|         killSessions
|           failed = 0
|           total = 0
|         update
|           failed = 0
|           total = 0
|         geoSearch
|           failed = 0
|           total = 0
|         _configsvrRemoveShard
|           failed = 0
|           total = 0
|         copydbsaslstart
|           failed = 0
|           total = 0
|         convertToCapped
|           failed = 0
|           total = 0
|         _getUserCacheGeneration
|           failed = 0
|           total = 0
|         getLog
|           failed = 0
|           total = 0
|         hostInfo
|           failed = 0
|           total = 0
|         usersInfo
|           failed = 0
|           total = 0
|         validate
|           failed = 0
|           total = 0
|         _isSelf
|           failed = 0
|           total = 0
|         logRotate
|           failed = 0
|           total = 0
|         dropDatabase
|           failed = 0
|           total = 0
|         serverStatus
|           failed = 0
|           total = 2
|         _configsvrMoveChunk
|           failed = 0
|           total = 0
|         replSetMaintenance
|           failed = 0
|           total = 0
|         logout
|           failed = 0
|           total = 0
|         moveChunk
|           failed = 0
|           total = 0
|         reIndex
|           failed = 0
|           total = 0
|         repairDatabase
|           failed = 0
|           total = 0
|         _recvChunkCommit
|           failed = 0
|           total = 0
|         grantRolesToRole
|           failed = 0
|           total = 0
|         touch
|           failed = 0
|           total = 0
|         unsetSharding
|           failed = 0
|           total = 0
|         replSetUpdatePosition
|           failed = 0
|           total = 0
|         copydb
|           failed = 0
|           total = 0
|         checkShardingIndex
|           failed = 0
|           total = 0
|         planCacheClear
|           failed = 0
|           total = 0
|         createIndexes
|           failed = 0
|           total = 1
|         replSetResizeOplog
|           failed = 0
|           total = 0
|         compact
|           failed = 0
|           total = 0
|         refreshSessionsInternal
|           failed = 0
|           total = 0
|         listCommands
|           failed = 0
|           total = 0
|         dropIndexes
|           failed = 0
|           total = 0
|         getParameter
|           failed = 0
|           total = 0
|         currentOp
|           failed = 0
|           total = 0
|         profile
|           failed = 0
|           total = 0
|         _configsvrBalancerStatus
|           failed = 0
|           total = 0
|         _configsvrEnableSharding
|           failed = 0
|           total = 0
|         collStats
|           failed = 0
|           total = 0
|         drop
|           failed = 0
|           total = 0
|         mapReduce
|           failed = 0
|           total = 0
|         replSetInitiate
|           failed = 0
|           total = 0
|         _configsvrCommitChunkMerge
|           failed = 0
|           total = 0
|         planCacheClearFilters
|           failed = 0
|           total = 0
|         replSetHeartbeat
|           failed = 0
|           total = 0
|         whatsmyuri
|           failed = 0
|           total = 0
|         updateUser
|           failed = 0
|           total = 0
|         _configsvrRemoveShardFromZone
|           failed = 0
|           total = 0
|         explain
|           failed = 0
|           total = 0
|         updateRole
|           failed = 0
|           total = 0
|         getShardMap
|           failed = 0
|           total = 0
|         rolesInfo
|           failed = 0
|           total = 0
|         _mergeAuthzCollections
|           failed = 0
|           total = 0
|         top
|           failed = 0
|           total = 0
|         renameCollection
|           failed = 0
|           total = 0
|         mergeChunks
|           failed = 0
|           total = 0
|         splitVector
|           failed = 0
|           total = 0
|         applyOps
|           failed = 0
|           total = 0
|         shardConnPoolStats
|           failed = 0
|           total = 0
|         replSetReconfig
|           failed = 0
|           total = 0
|         _configsvrAddShard
|           failed = 0
|           total = 0
|         shardingState
|           failed = 0
|           total = 0
|         planCacheListFilters
|           failed = 0
|           total = 0
|         dbStats
|           failed = 0
|           total = 0
|         _configsvrBalancerStart
|           failed = 0
|           total = 0
|         endSessions
|           failed = 0
|           total = 0
|         _configsvrAddShardToZone
|           failed = 0
|           total = 0
|         getLastError
|           failed = 0
|           total = 0
|         createRole
|           failed = 0
|           total = 0
|         killAllSessionsByPattern
|           failed = 0
|           total = 0
|         connPoolStats
|           failed = 0
|           total = 0
|         _configsvrShardCollection
|           failed = 0
|           total = 0
|         grantRolesToUser
|           failed = 0
|           total = 0
|         saslStart
|           failed = 0
|           total = 0
|         _migrateClone
|           failed = 0
|           total = 0
|         _transferMods
|           failed = 0
|           total = 0
|         find
|           failed = 0
|           total = 1
|         features
|           failed = 0
|           total = 0
|         repairCursor
|           failed = 0
|           total = 0
|         grantPrivilegesToRole
|           failed = 0
|           total = 0
|         getCmdLineOpts
|           failed = 0
|           total = 0
|         revokeRolesFromUser
|           failed = 0
|           total = 0
|         connectionStatus
|           failed = 0
|           total = 0
|         planCacheListPlans
|           failed = 0
|           total = 0
|         authSchemaUpgrade
|           failed = 0
|           total = 0
|         resync
|           failed = 0
|           total = 0
|         invalidateUserCache
|           failed = 0
|           total = 0
|         _flushRoutingTableCacheUpdates
|           failed = 0
|           total = 0
|         getShardVersion
|           failed = 0
|           total = 0
|         resetError
|           failed = 0
|           total = 0
|         authenticate
|           failed = 0
|           total = 0
|         replSetSyncFrom
|           failed = 0
|           total = 0
|         replSetStepUp
|           failed = 0
|           total = 0
|         replSetAbortPrimaryCatchUp
|           failed = 0
|           total = 0
|         splitChunk
|           failed = 0
|           total = 0
|         _getNextSessionMods
|           failed = 0
|           total = 0
|         replSetGetRBID
|           failed = 0
|           total = 0
|         replSetGetConfig
|           failed = 0
|           total = 0
|         replSetFresh
|           failed = 0
|           total = 0
|         <UNKNOWN> = 0
|         replSetElect
|           failed = 0
|           total = 0
|         replSetRequestVotes
|           failed = 0
|           total = 0
|         create
|           failed = 0
|           total = 0
|         cloneCollection
|           failed = 0
|           total = 0
|         startSession
|           failed = 0
|           total = 0
|         aggregate
|           failed = 0
|           total = 0
|         replSetFreeze
|           failed = 0
|           total = 0
|         saslContinue
|           failed = 0
|           total = 0
|         setShardVersion
|           failed = 0
|           total = 0
|         getDiagnosticData
|           failed = 0
|           total = 0
|         count
|           failed = 0
|           total = 0
|         dropRole
|           failed = 0
|           total = 0
|         _configsvrMovePrimary
|           failed = 0
|           total = 0
|         refreshSessions
|           failed = 0
|           total = 0
|         killOp
|           failed = 0
|           total = 0
|         planCacheSetFilter
|           failed = 0
|           total = 0
|         distinct
|           failed = 0
|           total = 0
|         _configsvrBalancerStop
|           failed = 0
|           total = 0
|         _configsvrCommitChunkMigration
|           failed = 0
|           total = 0
|         availableQueryOptions
|           failed = 0
|           total = 0
|         dbHash
|           failed = 0
|           total = 0
|         planCacheListQueryShapes
|           failed = 0
|           total = 0
|         cloneCollectionAsCapped
|           failed = 0
|           total = 0
|         driverOIDTest
|           failed = 0
|           total = 0
|         dropUser
|           failed = 0
|           total = 0
|         _recvChunkStart
|           failed = 0
|           total = 0
|         clone
|           failed = 0
|           total = 0
|         mapreduce
|           shardedfinish
|             failed = 0
|             total = 0
|         handshake
|           failed = 0
|           total = 0
|         fsync
|           failed = 0
|           total = 0
|         fsyncUnlock
|           failed = 0
|           total = 0
|         revokePrivilegesFromRole
|           failed = 0
|           total = 0
|         _configsvrUpdateZoneKeyRange
|           failed = 0
|           total = 0
|         insert
|           failed = 0
|           total = 0
|         getPrevError
|           failed = 0
|           total = 0
|         _configsvrCreateDatabase
|           failed = 0
|           total = 0
|         setFeatureCompatibilityVersion
|           failed = 0
|           total = 0
|         copydbgetnonce
|           failed = 0
|           total = 0
|         setParameter
|           failed = 0
|           total = 0
|         forceerror
|           failed = 0
|           total = 0
|         revokeRolesFromRole
|           failed = 0
|           total = 0
|         eval
|           failed = 0
|           total = 0
|         ping
|           failed = 0
|           total = 0
|         cleanupOrphaned
|           failed = 0
|           total = 0
|         buildInfo
|           failed = 0
|           total = 0
|         isMaster
|           failed = 0
|           total = 0
|         createUser
|           failed = 0
|           total = 0
|         _configsvrCommitChunkSplit
|           failed = 0
|           total = 0
|       ttl
|         deletedDocuments = 0
|         passes = 4
|       document
|         updated = 0
|         deleted = 0
|         inserted = 0
|         returned = 0
|       repl
|         apply
|           batches
|             totalMillis = 0
|             num = 0
|           attemptsToBecomeSecondary = 0
|           ops = 0
|         executor
|           pool
|             inProgressCount = 0
|           unsignaledEvents = 0
|           shuttingDown = false
|           networkInterface = 
|           NetworkInterfaceASIO Operations' Diagnostic:
|           Operation:    Count:   
|           Connecting    0        
|           In Progress   0        
|           Succeeded     0        
|           Canceled      0        
|           Failed        0        
|           Timed Out     0        
|           
|           queues
|             networkInProgress = 0
|             sleepers = 0
|         network
|           readersCreated = 0
|           ops = 0
|           getmores
|             totalMillis = 0
|             num = 0
|           bytes = 0
|         buffer
|           count = 0
|           maxSizeBytes = 0
|           sizeBytes = 0
|         initialSync
|           failures = 0
|           completed = 0
|           failedAttempts = 0
|         preload
|           docs
|             totalMillis = 0
|             num = 0
|           indexes
|             totalMillis = 0
|             num = 0
|       getLastError
|         wtime
|           totalMillis = 0
|           num = 0
|         wtimeouts = 0
|     version = 3.6.8
|     logicalSessionRecordCache
|       lastSessionsCollectionJobEntriesRefreshed = 0
|       lastSessionsCollectionJobEntriesEnded = 0
|       sessionsCollectionJobCount = 1
|       lastSessionsCollectionJobCursorsClosed = 0
|       lastSessionsCollectionJobDurationMillis = 27
|       lastSessionsCollectionJobTimestamp = 1664877182743
|       lastTransactionReaperJobTimestamp = 1664877182743
|       lastTransactionReaperJobEntriesCleanedUp = 0
|       lastTransactionReaperJobDurationMillis = 0
|       transactionReaperJobCount = 0
|       activeSessionsCount = 0
|     mem
|       mappedWithJournal = 0
|       bits = 64
|       virtual = 956
|       supported = true
|       mapped = 0
|       resident = 72
|     transportSecurity
|       1.2 = 0
|       1.0 = 0
|       1.1 = 0
|     wiredTiger
|       async
|         maximum work queue length = 0
|         total compact calls = 0
|         current work queue length = 0
|         total update calls = 0
|         number of operation slots viewed for allocation = 0
|         total search calls = 0
|         total remove calls = 0
|         total insert calls = 0
|         number of times operation allocation failed = 0
|         number of times worker found no work = 0
|         number of allocation state races = 0
|         total allocations = 0
|         number of flush calls = 0
|       data-handle
|         connection sweeps = 120
|         session sweep attempts = 20
|         session dhandles swept = 0
|         connection sweep time-of-death sets = 13
|         connection sweep dhandles removed from hash list = 3
|         connection data handles currently active = 22
|         connection sweep dhandles closed = 0
|         connection sweep candidate became referenced = 0
|       lock
|         commit timestamp queue lock application thread time waiting for the dhandle lock (usecs) = 0
|         metadata lock application thread wait time (usecs) = 0
|         dhandle lock application thread time waiting for the dhandle lock (usecs) = 0
|         read timestamp queue lock application thread time waiting for the dhandle lock (usecs) = 0
|         dhandle write lock acquisitions = 28
|         txn global write lock acquisitions = 15
|         metadata lock acquisitions = 5
|         read timestamp queue lock internal thread time waiting for the dhandle lock (usecs) = 0
|         read timestamp queue write lock acquisitions = 0
|         read timestamp queue read lock acquisitions = 0
|         schema lock internal thread wait time (usecs) = 0
|         schema lock acquisitions = 29
|         dhandle read lock acquisitions = 1049
|         table read lock acquisitions = 0
|         commit timestamp queue write lock acquisitions = 0
|         txn global lock internal thread time waiting for the dhandle lock (usecs) = 0
|         metadata lock internal thread wait time (usecs) = 0
|         checkpoint lock application thread wait time (usecs) = 0
|         checkpoint lock acquisitions = 5
|         table lock internal thread time waiting for the table lock (usecs) = 0
|         txn global lock application thread time waiting for the dhandle lock (usecs) = 0
|         schema lock application thread wait time (usecs) = 0
|         txn global read lock acquisitions = 16
|         checkpoint lock internal thread wait time (usecs) = 0
|         table write lock acquisitions = 12
|         commit timestamp queue read lock acquisitions = 0
|         table lock application thread time waiting for the table lock (usecs) = 0
|         commit timestamp queue lock internal thread time waiting for the dhandle lock (usecs) = 0
|         dhandle lock internal thread time waiting for the dhandle lock (usecs) = 0
|       perf
|         operation write latency histogram (bucket 4) - 1000-9999us = 0
|         operation read latency histogram (bucket 1) - 100-249us = 0
|         operation read latency histogram (bucket 2) - 250-499us = 0
|         file system read latency histogram (bucket 1) - 10-49ms = 3
|         file system write latency histogram (bucket 4) - 250-499ms = 0
|         operation read latency histogram (bucket 3) - 500-999us = 0
|         operation read latency histogram (bucket 4) - 1000-9999us = 0
|         file system write latency histogram (bucket 6) - 1000ms+ = 0
|         operation read latency histogram (bucket 5) - 10000us+ = 0
|         file system read latency histogram (bucket 6) - 1000ms+ = 0
|         file system write latency histogram (bucket 5) - 500-999ms = 0
|         file system write latency histogram (bucket 2) - 50-99ms = 0
|         operation write latency histogram (bucket 3) - 500-999us = 1
|         operation write latency histogram (bucket 1) - 100-249us = 0
|         operation write latency histogram (bucket 5) - 10000us+ = 0
|         file system read latency histogram (bucket 5) - 500-999ms = 0
|         file system write latency histogram (bucket 3) - 100-249ms = 0
|         file system read latency histogram (bucket 3) - 100-249ms = 2
|         file system read latency histogram (bucket 4) - 250-499ms = 0
|         file system read latency histogram (bucket 2) - 50-99ms = 3
|         file system write latency histogram (bucket 1) - 10-49ms = 0
|         operation write latency histogram (bucket 2) - 250-499us = 0
|       log
|         pre-allocated log files not ready and missed = 1
|         log bytes written = 6528
|         records processed by log scan = 13
|         logging bytes consolidated = 6016
|         force archive time sleeping (usecs) = 0
|         log write operations = 16
|         slot join found active slot closed = 0
|         busy returns attempting to switch slots = 0
|         maximum log file size = 104857600
|         log records not compressed = 0
|         log sync time duration (usecs) = 8782
|         log release advances write LSN = 5
|         pre-allocated log files used = 0
|         log flush operations = 2485
|         log files manually zero-filled = 0
|         log bytes of payload data = 4516
|         log force write operations skipped = 2748
|         yields waiting for previous log file close = 0
|         slot close lost race = 0
|         total size of compressed records = 4277
|         total log buffer size = 33554432
|         log server thread advances write LSN = 4
|         slot unbuffered writes = 0
|         number of pre-allocated log files to create = 2
|         slot join calls found active slot closed = 0
|         slot transitions unable to find free slot = 0
|         log server thread write LSN walk skipped = 1247
|         slot joins yield time (usecs) = 0
|         slot join calls yielded = 0
|         log sync operations = 9
|         slot join calls did not yield = 16
|         log scan operations = 6
|         total in-memory size of compressed records = 6456
|         log sync_dir time duration (usecs) = 88566
|         log scan records requiring two reads = 0
|         slot closures = 9
|         log sync_dir operations = 1
|         slot join atomic update races = 0
|         log force write operations = 2752
|         written slots coalesced = 0
|         pre-allocated log files prepared = 2
|         log records too small to compress = 11
|         slot join calls atomic updates raced = 0
|         slot join calls slept = 0
|         slot close unbuffered waits = 0
|         log records compressed = 5
|       thread-state
|         active filesystem write calls = 0
|         active filesystem fsync calls = 0
|         active filesystem read calls = 0
|       cursor
|         cursor sweep cursors closed = 0
|         truncate calls = 0
|         cursor insert calls = 12
|         cursor sweep buckets = 0
|         cursor search near calls = 5
|         cursor modify calls = 0
|         cursor remove calls = 1
|         cursor next calls = 76
|         cursor search calls = 310
|         cursor sweeps = 0
|         cursor reserve calls = 0
|         cursor sweep cursors examined = 0
|         cursors reused from cache = 0
|         cursors cached on close = 0
|         cursor update calls = 0
|         cursor prev calls = 10
|         cursor reset calls = 348
|         cursor restarted searches = 0
|         cursor create calls = 39
|       session
|         table drop failed calls = 0
|         table drop successful calls = 0
|         table compact successful calls = 0
|         table rebalance failed calls = 0
|         table rename failed calls = 0
|         table salvage failed calls = 0
|         table rebalance successful calls = 0
|         table create successful calls = 1
|         table verify successful calls = 0
|         table rename successful calls = 0
|         open session count = 20
|         table create failed calls = 0
|         table verify failed calls = 0
|         table alter failed calls = 0
|         table alter unchanged and skipped = 0
|         table truncate failed calls = 0
|         table salvage successful calls = 0
|         table alter successful calls = 0
|         table compact failed calls = 0
|         table truncate successful calls = 0
|         open cursor count = 36
|       LSM
|         sleep for LSM merge throttle = 0
|         tree maintenance operations discarded = 0
|         rows merged in an LSM tree = 0
|         tree queue hit maximum = 0
|         merge work units currently queued = 0
|         tree maintenance operations scheduled = 0
|         switch work units currently queued = 0
|         application work units currently queued = 0
|         tree maintenance operations executed = 0
|         sleep for LSM checkpoint throttle = 0
|       reconciliation
|         split objects currently awaiting free = 0
|         fast-path pages deleted = 0
|         page reconciliation calls = 11
|         split bytes currently awaiting free = 0
|         page reconciliation calls for eviction = 0
|         pages deleted = 0
|       cache
|         internal pages evicted = 0
|         bytes currently in the cache = 72550
|         eviction walk target pages histogram - 0-9 = 0
|         hazard pointer blocked page eviction = 0
|         eviction server unable to reach eviction goal = 0
|         tracked bytes belonging to leaf pages in the cache = 69152
|         pages read into cache skipping older lookaside entries = 0
|         eviction worker thread evicting pages = 0
|         pages queued for eviction = 0
|         pages read into cache requiring lookaside for checkpoint = 0
|         eviction worker thread removed = 0
|         pages evicted because they exceeded the in-memory maximum count = 0
|         files with active eviction walks = 0
|         overflow pages read into cache = 0
|         eviction walks gave up because they saw too many pages and found no candidates = 0
|         page split during eviction deepened the tree = 0
|         pages read into cache = 18
|         pages evicted by application threads = 0
|         eviction worker thread created = 0
|         tracked dirty bytes in the cache = 0
|         eviction server candidate queue empty when topping up = 0
|         lookaside table insert calls = 0
|         pages read into cache with skipped lookaside entries needed later = 0
|         pages requested from the cache = 378
|         tracked dirty pages in the cache = 0
|         eviction walk target pages histogram - 64-128 = 0
|         eviction worker thread stable number = 0
|         eviction worker thread active = 4
|         eviction server candidate queue not empty when topping up = 0
|         eviction calls to get a page = 0
|         lookaside table remove calls = 0
|         eviction walks started from saved location in tree = 0
|         eviction calls to get a page found queue empty after locking = 0
|         eviction walks gave up because they saw too many pages and found too few candidates = 0
|         pages read into cache with skipped lookaside entries needed later by checkpoint = 0
|         bytes written from cache = 67126
|         lookaside table entries = 0
|         checkpoint blocked page eviction = 0
|         eviction walks abandoned = 0
|         internal pages split during eviction = 0
|         application threads page write from cache to disk time (usecs) = 784
|         pages read into cache after truncate in prepare state = 0
|         percentage overhead = 8
|         bytes read into cache = 53696
|         hazard pointer check calls = 0
|         eviction passes of a file = 0
|         hazard pointer maximum array length = 0
|         hazard pointer check entries walked = 0
|         unmodified pages evicted = 0
|         eviction empty score = 0
|         leaf pages split during eviction = 0
|         force re-tuning of eviction workers once in a while = 0
|         lookaside score = 0
|         application threads page read from disk to cache count = 8
|         eviction walks reached end of tree = 0
|         pages written requiring in-memory restoration = 0
|         pages read into cache requiring lookaside entries = 0
|         pages walked for eviction = 0
|         pages selected for eviction unable to be evicted = 0
|         pages evicted because they had chains of deleted items count = 0
|         pages seen by eviction walk = 0
|         eviction server slept, because we did not make progress with eviction = 0
|         modified pages evicted by application threads = 0
|         pages read into cache after truncate = 1
|         pages queued for urgent eviction during walk = 0
|         pages queued for urgent eviction = 0
|         in-memory page splits = 0
|         pages evicted because they exceeded the in-memory maximum time (usecs) = 0
|         pages currently held in the cache = 22
|         pages written from cache = 11
|         in-memory page passed criteria to be split = 0
|         modified pages evicted = 0
|         eviction currently operating in aggressive mode = 0
|         bytes not belonging to page images in the cache = 14558
|         eviction state = 32
|         application threads page read from disk to cache time (usecs) = 2175
|         eviction walk target pages histogram - 32-63 = 0
|         maximum page size at eviction = 0
|         files with new eviction walks started = 0
|         maximum bytes configured = 502267904
|         eviction walk target pages histogram - 10-31 = 0
|         bytes belonging to the lookaside table in the cache = 182
|         eviction calls to get a page found queue empty = 0
|         bytes belonging to page images in the cache = 57991
|         failed eviction of pages that exceeded the in-memory maximum count = 0
|         tracked bytes belonging to internal pages in the cache = 3398
|         eviction walk target pages histogram - 128 and higher = 0
|         pages evicted because they had chains of deleted items time (usecs) = 0
|         page written requiring lookaside records = 0
|         eviction walks gave up because they restarted their walk twice = 0
|         eviction walks started from root of tree = 0
|         eviction server evicting pages = 0
|         application threads page write from cache to disk count = 10
|         failed eviction of pages that exceeded the in-memory maximum time (usecs) = 0
|       concurrentTransactions
|         write
|           out = 0
|           totalTickets = 128
|           available = 128
|         read
|           out = 1
|           totalTickets = 128
|           available = 127
|       connection
|         memory frees = 7083
|         auto adjusting condition wait calls = 1569
|         memory allocations = 8050
|         total write I/Os = 40
|         files currently open = 15
|         total read I/Os = 1283
|         pthread mutex condition wait calls = 4179
|         pthread mutex shared lock write-lock calls = 353
|         auto adjusting condition resets = 27
|         pthread mutex shared lock read-lock calls = 1902
|         total fsync I/Os = 33
|         detected system time went backwards = 0
|         memory re-allocations = 873
|       transaction
|         set timestamp commit calls = 0
|         prepared transactions committed = 0
|         transaction checkpoint scrub time (msecs) = 0
|         set timestamp calls = 0
|         set timestamp oldest calls = 0
|         set timestamp stable calls = 0
|         read timestamp queue insert to empty = 0
|         prepared transactions currently active = 0
|         transaction checkpoint min time (msecs) = 0
|         transaction range of IDs currently pinned = 0
|         transaction sync calls = 0
|         transaction range of timestamps pinned by the oldest timestamp = 0
|         number of named snapshots created = 0
|         number of named snapshots dropped = 0
|         rollback to stable updates removed from lookaside = 0
|         set timestamp oldest updates = 0
|         commit timestamp queue length = 0
|         transactions rolled back = 17
|         read timestamp queue inserts total = 0
|         commit timestamp queue inserts to tail = 0
|         update conflicts = 0
|         rollback to stable updates aborted = 0
|         set timestamp commit updates = 0
|         transactions committed = 2
|         transaction checkpoint generation = 6
|         query timestamp calls = 1054
|         transaction checkpoints skipped because database was clean = 0
|         transaction range of IDs currently pinned by named snapshots = 0
|         transaction range of IDs currently pinned by a checkpoint = 0
|         transaction begins = 19
|         transaction checkpoint max time (msecs) = 13
|         set timestamp stable updates = 0
|         commit timestamp queue insert to empty = 0
|         transaction fsync calls for checkpoint after allocating the transaction ID = 5
|         prepared transactions = 0
|         transaction failures due to cache overflow = 0
|         read timestamp queue inserts to head = 0
|         transaction checkpoints = 5
|         transaction checkpoint total time (msecs) = 30
|         read timestamp queue length = 0
|         transaction checkpoint scrub dirty target = 0
|         transaction checkpoint currently running = 0
|         commit timestamp queue inserts total = 0
|         transaction checkpoint most recent time (msecs) = 0
|         transaction range of timestamps currently pinned = 0
|         rollback to stable calls = 0
|         transaction fsync duration for checkpoint after allocating the transaction ID (usecs) = 0
|         prepared transactions rolled back = 0
|       thread-yield
|         data handle lock yielded = 0
|         page acquire read blocked = 0
|         page reconciliation yielded due to child modification = 0
|         application thread time evicting (usecs) = 0
|         page acquire eviction blocked = 0
|         log server sync yielded for log write = 0
|         page access yielded due to prepare state change = 0
|         application thread time waiting for cache (usecs) = 0
|         page acquire time sleeping (usecs) = 0
|         page acquire locked blocked = 0
|         get reference for page index and slot time sleeping (usecs) = 0
|         page delete rollback time sleeping for state change (usecs) = 0
|         connection close yielded for lsm manager shutdown = 0
|         connection close blocked waiting for transaction state stabilization = 0
|         page acquire busy blocked = 0
|       block-manager
|         bytes written = 126976
|         bytes written for checkpoint = 126976
|         mapped blocks read = 0
|         mapped bytes read = 0
|         blocks written = 23
|         blocks pre-loaded = 9
|         bytes read = 143360
|         blocks read = 31
|       uri = statistics:
|     transactions
|       transactionsCollectionWriteCount = 0
|       retriedStatementsCount = 0
|       retriedCommandsCount = 0
|     tcmalloc
|       generic
|         current_allocated_bytes = 67907848
|         heap_size = 71802880
|       tcmalloc
|         central_cache_free_bytes = 550320
|         pageheap_unmapped_bytes = 0
|         pageheap_decommit_count = 0
|         transfer_cache_free_bytes = 153088
|         pageheap_reserve_count = 47
|         pageheap_total_reserve_bytes = 71802880
|         thread_cache_free_bytes = 1507016
|         max_total_thread_cache_bytes = 258998272
|         pageheap_scavenge_count = 0
|         current_total_thread_cache_bytes = 1502088
|         formattedString = ------------------------------------------------
|         MALLOC:       67906008 (   64.8 MiB) Bytes in use by application
|         MALLOC: +      1687552 (    1.6 MiB) Bytes in page heap freelist
|         MALLOC: +       550096 (    0.5 MiB) Bytes in central cache freelist
|         MALLOC: +       153088 (    0.1 MiB) Bytes in transfer cache freelist
|         MALLOC: +      1506136 (    1.4 MiB) Bytes in thread cache freelists
|         MALLOC: +      2752512 (    2.6 MiB) Bytes in malloc metadata
|         MALLOC:   ------------
|         MALLOC: =     74555392 (   71.1 MiB) Actual memory used (physical + swap)
|         MALLOC: +            0 (    0.0 MiB) Bytes released to OS (aka unmapped)
|         MALLOC:   ------------
|         MALLOC: =     74555392 (   71.1 MiB) Virtual address space used
|         MALLOC:
|         MALLOC:            500              Spans in use
|         MALLOC:             18              Thread heaps in use
|         MALLOC:           8192              Tcmalloc page size
|         ------------------------------------------------
|         Call ReleaseFreeMemory() to release freelist memory to the OS (via madvise()).
|         Bytes released to the OS take up virtual address space but no physical memory.
|         pageheap_total_commit_bytes = 71802880
|         total_free_bytes = 2207496
|         pageheap_committed_bytes = 71802880
|         aggressive_memory_decommit = 0
|         pageheap_commit_count = 47
|         pageheap_total_decommit_bytes = 0
|         pageheap_free_bytes = 1687552
|     network
|       bytesIn = 197
|       numRequests = 3
|       serviceExecutorTaskStats
|         executor = passthrough
|         threadsRunning = 2
|       bytesOut = 29858
|       compression
|         snappy
|           decompressor
|             bytesIn = 0
|             bytesOut = 0
|           compressor
|             bytesIn = 0
|             bytesOut = 0
|       physicalBytesOut = 29858
|       physicalBytesIn = 197
|     opcountersRepl
|       update = 0
|       insert = 0
|       delete = 0
|       query = 0
|       command = 0
|       getmore = 0
|     opLatencies
|       reads
|         ops = 0
|         latency = 0
|       writes
|         ops = 0
|         latency = 0
|       commands
|         ops = 1
|         latency = 1319
|     connections
|       available = 51198
|       totalCreated = 3
|       current = 2
|     locks
|       Collection
|         acquireCount
|           w = 5
|           r = 334
|       Global
|         acquireCount
|           W = 5
|           w = 14
|           r = 952
|       Database
|         acquireCount
|           W = 8
|           R = 5
|           w = 6
|           r = 335
|     uptimeEstimate = 253
|     storageEngine
|       persistent = true
|       name = wiredTiger
|       supportsCommittedReads = true
|       readOnly = false
|     host = mongod
|     uptime = 252.0
|     globalLock
|       totalTime = 252591000
|       activeClients
|         writers = 0
|         readers = 1
|         total = 11
|       currentQueue
|         writers = 0
|         readers = 0
|         total = 0
|     opcounters
|       update = 0
|       insert = 0
|       delete = 0
|       query = 1
|       command = 4
|       getmore = 0
|     extra_info
|       note = fields vary by platform
|       page_faults = 268
|_    localTime = 1664877431599
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
## Nmap done at Tue Oct  4 11:57:11 2022 -- 1 IP address (1 host up) scanned in 7.92 seconds
```

Entre otra mucha información, nos muestra las versiones de SSH y de mongoDB, que son **OpenSSH 8.2p1 Ubuntu 4ubuntu0.5** y **MongoDB 3.6.8** respectivamente. Como no disponemos de credenciales para autenticarnos por SSH, empezaremos auditando el servicio de mongoDB.

### Puerto 27017 abierto (MongoDB)

MongoDB es una base de datos NoSQL. Una de sus principales diferencias con las bases de datos SQL es que no utilizan SQL como lenguaje principal de consultas. Para conectarnos a esta base de datos yo utilizare la herramienta **mongosh** (mongo shell), que me la he descargado de la página oficial de [mongo](https://www.mongodb.com/try/download/shell).

Para conectarnos introduciremos el siguiente comando: ```mongosh --host 10.129.138.155 --port 27017```

Una vez conectados podremos listar las bases de datos disponibles con ```show dbs o show databases``:

```ruby
test> show dbs
admin                  32.00 KiB
config                 72.00 KiB
local                  72.00 KiB
sensitive_information  32.00 KiB
users                  32.00 KiB
```

Existe un base de datos **sensitive_information** que me llama bastante la atención. Para conectarnos a esta base de datos podemos escribir ```use sensitive_information```. Posteriormente para listar las tablas disponibles de *sensitive_information* ejecutaremos ```show tables o show collections```.

```ruby
test> use sensitive_information
switched to db sensitive_information
sensitive_information> show tables
flag
```

Vemos que existe una tabla llamada **flag**. Finalmente para listar su contenido, ejecutaremos ```db.flag.find().pretty()```. La función **pretty** hace que el contenido se muestre mas bonito.

```ruby
sensitive_information> db.flag.find().pretty()
[
  {
    _id: ObjectId("630e3dbcb82540ebbd1748c5"),
    flag: '1b6e6fb359e7c40241b6d431427ba6ea'
  }
]
```
Y ya obtendremos la flag que nos piden. 

## Final 

Y aquí concluye este post de *Starting Point Tier 0*. Espero que os haya servido la explicación y si tenéis alguna duda me podéis contactar en ripfr4n0@gmail.com.