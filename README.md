# Bisiesto Security Headers

Plugin de WordPress que añade las cabeceras de seguridad HTTP que suelen faltar (según Mozilla Observatory / securityheaders.com).

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

### Para que funcione como antes, sin riesgo de hashes

- Activada: ✓
- Valor: el de por defecto
- Modo solo-informe: ✗
- Modo estricto: ✗

Si quieres que no pueda romper nada en absoluto, marca solo-informe (deja de proteger, solo informa).

### Modo estricto (hashes)

Quita `'unsafe-inline'` de `script-src`. En cada página del front-end:

1. Captura el HTML.
2. Calcula el hash SHA-256 de cada `<script>` inline (ignora bloques de datos como JSON o `ld+json`).
3. Añade los dominios de los `<script src>` externos.
4. Emite un `script-src` con `'self'`, esos dominios y los hashes.

El resto de directivas (`style-src`, `img-src`, `font-src`, etc.) se mantienen amplias. `object-src 'none'` queda fijado. El valor del campo de CSP se ignora en este modo.

El campo **Fuentes extra para `script-src`** sirve para dominios cuyos scripts se cargan dinámicamente y no aparecen en el HTML (p. ej. `https://www.google.com https://www.gstatic.com` para reCAPTCHA).

#### Cómo activarlo con seguridad

1. Marca **Modo estricto** y **Modo solo-informe**.
2. Navega por el sitio con la consola del navegador abierta y revisa los avisos de CSP.
3. Añade a *Fuentes extra* los dominios que falten.
4. Cuando no haya avisos, desmarca solo-informe.
5. Purga cachés y vuelve a pasar Mozilla.

#### Riesgos del modo estricto

- **Minificado de LiteSpeed Cache:** si modifica los scripts inline (minificar, combinar, diferir) *después* de que el plugin calcule los hashes, no coincidirán y esos scripts se bloquearán. Solución: desactivar el minificado de JS inline.
- **Manejadores inline** (`onclick="..."`): quedan bloqueados; no hay hash que lo arregle. Algunos temas y plugins los usan.
- **No lo actives sin pasar por solo-informe**: podría romper formularios, captcha o menús.

## Cachés

Los cambios de ajustes no se ven hasta purgar todas las capas de caché; si no, se sigue sirviendo la respuesta antigua hasta que caduque. En bisiesto.es hay tres:

1. LiteSpeed Cache (*Purge All*).
2. WP Engine (panel o barra de administración).
3. Cloudflare (*Caching → Purge Everything*).

Para comprobar saltándote la caché:

```sh
curl -sI "https://tusitio.es/?nocache=$(date +%s)" -H 'Cache-Control: no-cache'
```

## Otras notas

- **HSTS:** actívalo solo si todo el sitio y los subdominios funcionan con HTTPS. Los navegadores lo recuerdan durante un año.
- **Duplicados:** si el servidor (nginx/Apache) o un CDN ya envía alguna de estas cabeceras, puede duplicarse o pisarse.
- **Permissions-Policy:** el plugin no la gestiona. En bisiesto.es ya la envía otro componente (probablemente un plugin de captcha o Cloudflare).
- **Recuperación:** si algo rompe el acceso al panel, renombra la carpeta del plugin por FTP/SFTP para desactivarlo.

## Historial

- **1.1.0:** modo estricto de CSP con hashes SHA-256 y campo de fuentes extra.
- **1.0.0:** versión inicial con las cinco cabeceras y página de ajustes.
