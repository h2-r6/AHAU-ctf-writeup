# Apuntes

| Campo | Detalle |
|---|---|
| **Categoría** | Web |
| **Puntos** | 100 |
| **Evento** | Kernel CTF — AHAU Team |
| **Autor del reto** | Lychi3 |
| **Objetivo** | `http://3.236.190.110` |
| **Descripción** | *"Bienvenido a tu plataforma para guardar notas"* |
| **Vulnerabilidad** | Información sensible en una cookie codificada en Base64 (sin cifrado ni firma) |
| **CWE** | CWE-315 (Cleartext Storage of Sensitive Information in a Cookie) |
| **OWASP** | A02:2021 – Cryptographic Failures |

> Este es el primero de cinco retos (**Apuntes 1 → 5**) sobre la misma aplicación. Cada uno parte de lo obtenido en el anterior.

## 1. Reconocimiento

```text
$ curl -i http://3.236.190.110/
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.12.16
Content-Type: text/html; charset=utf-8
Content-Length: 2780
```

Es una aplicación **Flask** llamada "NotasSeguras", con enlaces a `/login` y `/register`.

Enumeración de rutas:

```bash
for p in robots.txt .git/HEAD login register notes note api admin flag note/1 notes/1; do
  echo -n "$p -> "; curl -s -o /dev/null -w "%{http_code}\n" http://3.236.190.110/$p
done
```

| Ruta | Código | Significado |
|---|---|---|
| `/login` | 200 | Formulario de login |
| `/register` | 200 | Formulario de registro |
| `/admin` | **302** | Existe, pero redirige: requiere sesión |
| `/notes`, `/note`, `/api`, `/flag`, `/note/1`, `/notes/1` | 404 | No existen |
| `/robots.txt`, `/.git/HEAD` | 404 | — |

El `302` de `/admin` indica que hay un panel protegido. Para avanzar hace falta una sesión.

## 2. Análisis

Se crea una cuenta y se inspecciona la cookie que entrega el servidor:

```text
$ curl -s -c cj.txt -d "username=h2r6test&password=pass123" http://3.236.190.110/register -i
HTTP/1.1 302 FOUND
Server: Werkzeug/3.1.9 Python/3.12.16
Location: /dashboard
Set-Cookie: session=eyJ1c2VyIjogImgycjZ0ZXN0IiwgImFkbWluIjogZmFsc2UsICJ0b2tlbiI6ICJBSEFVe2cwMGRfZXllX2wwMGsxbmdfdGgzX2MwMGsxZX0iLCAibm90ZV9pZCI6IDEwfQ==; Path=/
```

Lo que se observa en la cookie:

- Empieza con `eyJ`, que es `{"` en Base64: un **JSON codificado en Base64**.
- No tiene puntos (`.`). Una cookie de sesión firmada de Flask (*itsdangerous*) tiene el formato `payload.timestamp.firma`, así que esta **no está firmada**.
- La cookie se envía sin los atributos `HttpOnly`, `Secure` ni `SameSite`.

## 3. Explotación

Basta con decodificarla:

```text
$ echo 'eyJ1c2VyIjogImgycjZ0ZXN0IiwgImFkbWluIjogZmFsc2UsICJ0b2tlbiI6ICJBSEFVe2cwMGRfZXllX2wwMGsxbmdfdGgzX2MwMGsxZX0iLCAibm90ZV9pZCI6IDEwfQ==' | base64 -d
{"user": "h2r6test", "admin": false, "token": "AHAU{g00d_eye_l00k1ng_th3_c00k1e}", "note_id": 10}
```

`flask-unsign` también la decodifica, porque solo aplica Base64:

```text
$ flask-unsign --unsign --cookie "$SESSION" --secret 'x'
[*] Session decodes to: {'user': 'h2r6b', 'admin': False, 'token': 'AHAU{g00d_eye_l00k1ng_th3_c00k1e}', 'note_id': 11}
```

La cookie tiene cuatro campos:

| Campo | Valor | Uso |
|---|---|---|
| `user` | `h2r6test` | Usuario autenticado |
| `admin` | `false` | Rol (→ [Apuntes 2](../apuntes-2/README.md)) |
| `token` | **la bandera** | Secreto expuesto |
| `note_id` | `10` | Nota del usuario (→ [Apuntes 3](../apuntes-3/README.md)) |

## 4. Causa raíz

Fragmento de `/app/app.py` (obtenido después mediante el LFI de [Apuntes 5](../apuntes-5/README.md)):

```python
FLAG1 = os.environ.get("FLAG_WEB1", "CTF{base64_is_not_encryption}")

def encode_session(data):
    return base64.b64encode(json.dumps(data).encode()).decode()

@app.route("/register", methods=["GET", "POST"])
def register():
    ...
    data = {"user": u, "admin": False, "token": FLAG1, "note_id": nid}
    resp = make_response(redirect("/dashboard"))
    resp.set_cookie("session", encode_session(data))
```

- **Base64 no es cifrado**, solo es una representación. Cualquiera la revierte.
- Se guarda un secreto (`FLAG1`) en un lugar que controla y lee el cliente.

## 5. Impacto

- Cualquier dato en la sesión (tokens, roles, IDs) queda visible para el usuario y para cualquier script que lea la cookie. Sin `HttpOnly`, un XSS la roba con `document.cookie`.
- Como no está firmada, también se puede **modificar** (ver Apuntes 2).

## 6. Remediación

- No guardar secretos en cookies. Usar sesiones del lado del servidor (Flask-Session con Redis o base de datos) y que la cookie solo lleve un ID aleatorio.
- Si se usan sesiones de cliente, que sean firmadas con una `SECRET_KEY` fuerte:

```python
import secrets
app.config.update(
    SECRET_KEY=os.environ["SECRET_KEY"],   # secrets.token_hex(32)
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
session["user_id"] = user.id
```

## 🚩 Flag

```text
AHAU{g00d_eye_l00k1ng_th3_c00k1e}
```

---
[⬅ Volver al índice](../../README.md) · [Siguiente: Apuntes 2 ➡](../apuntes-2/README.md)
