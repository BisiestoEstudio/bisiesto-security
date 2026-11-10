# Bisiesto Security Headers

Plugin de WordPress que añade las cabeceras de seguridad HTTP que suelen faltar en un WP por defecto.

Versión actual: **1.1.0**

## Cabeceras

| Cabecera | Valor por defecto | Notas |
|---|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Solo se envía si la petición es HTTPS. |
| `Content-Security-Policy` | `default-src 'self' https: data: blob: 'unsafe-inline' 'unsafe-eval'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'` | Solo en el front-end (no en `wp-admin`). Ver sección CSP. |
| `X-Frame-Options` | `SAMEORIGIN` | Protege contra clickjacking. |
| `X-Content-Type-Options` | `nosniff` | Único valor válido. |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | |

Las cabeceras se envían con la acción `send_headers` y con el filtro `wp_headers` (cubre REST y feeds).

## Instalación

1. Copia la carpeta `bisiesto-security-headers` a `wp-content/plugins/` (o comprímela en `.zip` y súbela desde *Plugins → Añadir nuevo*).
2. Actívalo.
3. Configúralo en *Ajustes → Security Headers*.
4. **Purga las cachés** (ver más abajo).

## Ajustes

Cada cabecera tiene una casilla **Activada** y un campo de valor editable. Los saltos de línea se eliminan al guardar para evitar inyección de cabeceras.

## Content-Security-Policy: tres niveles

La CSP tiene dos casillas independientes: **Modo solo-informe** y **Modo estricto** (ambas desmarcadas por defecto).

| Nivel | Casillas | Comportamiento |
|---|---|---|
| 1. Permisivo (por defecto) | Estricto ✗, Solo-informe ✗ | Envía y **aplica** el valor del campo. Equivale a la versión 1.0.0. No calcula hashes. **Suspende en Mozilla** (−20) por `'unsafe-inline'` en scripts. |
| 2. Estricto en pruebas | Estricto ✓, Solo-informe ✓ | Genera la política estricta pero no bloquea nada; solo avisa en la consola del navegador. |
| 3. Estricto en producción | Estricto ✓, Solo-informe ✗ | Genera la política estricta y **bloquea**. Es la que pasa el test de Mozilla. |

La casilla de solo-informe también funciona con la política permisiva (envía `Content-Security-Policy-Report-Only`).

## Cachés

¡Ojo! Los cambios de ajustes no se ven hasta purgar todas las capas de caché:

## Otras notas

- **HSTS:** actívalo solo si todo el sitio y los subdominios funcionan con HTTPS. Los navegadores lo recuerdan durante un año.
- **Duplicados:** si el servidor (nginx/Apache) o un CDN ya envía alguna de estas cabeceras, puede duplicarse o pisarse.
- **Permissions-Policy:** el plugin no la gestiona. En bisiesto.es ya la envía otro componente (probablemente un plugin de captcha o Cloudflare).
- **Recuperación:** si algo rompe el acceso al panel, renombra la carpeta del plugin por FTP/SFTP para desactivarlo.