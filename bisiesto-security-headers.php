<?php
/**
 * Plugin Name: Bisiesto Security Headers
 * Description: Añade las cabeceras de seguridad HTTP que suelen faltar en WordPress: HSTS, CSP, X-Frame-Options, X-Content-Type-Options y Referrer-Policy.
 * Version:     1.1.0
 * Author:      Bisiesto
 * License:     GPL-2.0-or-later
 * Text Domain: bisiesto-security-headers
 */

defined( 'ABSPATH' ) || exit;

final class Bisiesto_Security_Headers {

	const OPTION = 'bsh_settings';

	/** Definición de cabeceras: slug => [nombre, valor por defecto, descripción]. */
	private static function headers() {
		return array(
			'hsts'     => array(
				'name'    => 'Strict-Transport-Security',
				'default' => 'max-age=31536000; includeSubDomains',
				'desc'    => 'Fuerza HTTPS. Solo se envía cuando la petición ya es HTTPS.',
			),
			'csp'      => array(
				'name'    => 'Content-Security-Policy',
				'default' => "default-src 'self' https: data: blob: 'unsafe-inline' 'unsafe-eval'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'",
				'desc'    => 'Política permisiva por defecto, pensada para no romper WordPress/plugins. Endurécela según tu sitio. Solo se aplica en el front-end (no en wp-admin).',
			),
			'xfo'      => array(
				'name'    => 'X-Frame-Options',
				'default' => 'SAMEORIGIN',
				'desc'    => 'Protege contra clickjacking.',
			),
			'xcto'     => array(
				'name'    => 'X-Content-Type-Options',
				'default' => 'nosniff',
				'desc'    => 'Evita el MIME-sniffing. El único valor válido es nosniff.',
			),
			'referrer' => array(
				'name'    => 'Referrer-Policy',
				'default' => 'strict-origin-when-cross-origin',
				'desc'    => 'Controla qué información de referrer se envía.',
			),
		);
	}

	public static function init() {
		add_action( 'send_headers', array( __CLASS__, 'send' ), 20 );
		add_filter( 'wp_headers', array( __CLASS__, 'filter_wp_headers' ), 20 );
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_init', array( __CLASS__, 'register' ) );
		add_action( 'template_redirect', array( __CLASS__, 'maybe_buffer' ), 0 );
	}

	private static function settings() {
		$saved = get_option( self::OPTION, array() );
		$out   = array();
		foreach ( self::headers() as $slug => $h ) {
			$out[ $slug ] = array(
				'enabled' => isset( $saved[ $slug ]['enabled'] ) ? (bool) $saved[ $slug ]['enabled'] : true,
				'value'   => ( isset( $saved[ $slug ]['value'] ) && '' !== $saved[ $slug ]['value'] ) ? $saved[ $slug ]['value'] : $h['default'],
			);
		}
		$out['csp_report_only'] = ! empty( $saved['csp_report_only'] );
		$out['csp_strict']      = ! empty( $saved['csp_strict'] );
		$out['csp_extra']       = isset( $saved['csp_extra'] ) ? $saved['csp_extra'] : '';
		return $out;
	}

	/** Calcula las cabeceras a enviar: nombre => valor. */
	private static function compute() {
		$s       = self::settings();
		$headers = array();
		foreach ( self::headers() as $slug => $h ) {
			if ( empty( $s[ $slug ]['enabled'] ) ) {
				continue;
			}
			if ( 'hsts' === $slug && ! is_ssl() ) {
				continue;
			}
			if ( 'csp' === $slug && ( is_admin() || $s['csp_strict'] ) ) {
				continue; // En modo estricto la CSP se genera al vuelo (ver filter_html).
			}
			$name = $h['name'];
			if ( 'csp' === $slug && $s['csp_report_only'] ) {
				$name = 'Content-Security-Policy-Report-Only';
			}
			$headers[ $name ] = $s[ $slug ]['value'];
		}
		return $headers;
	}

	public static function send() {
		if ( headers_sent() ) {
			return;
		}
		foreach ( self::compute() as $name => $value ) {
			header( $name . ': ' . $value, true );
		}
	}

	/** Cubre respuestas (REST, feeds…) que pasan por wp_headers. */
	public static function filter_wp_headers( $headers ) {
		return array_merge( (array) $headers, self::compute() );
	}

	/* ---------- CSP estricta (hashes) ---------- */

	public static function maybe_buffer() {
		$s = self::settings();
		if ( ! $s['csp_strict'] || empty( $s['csp']['enabled'] ) || is_admin() || is_feed() || is_embed() ) {
			return;
		}
		ob_start( array( __CLASS__, 'filter_html' ) );
	}

	public static function filter_html( $html ) {
		if ( headers_sent() || false === stripos( $html, '<html' ) ) {
			return $html;
		}
		$s       = self::settings();
		$hashes  = array();
		$hosts   = array();
		$site    = wp_parse_url( home_url(), PHP_URL_HOST );

		if ( preg_match_all( '#<script\b([^>]*)>(.*?)</script>#is', $html, $m, PREG_SET_ORDER ) ) {
			foreach ( $m as $tag ) {
				$attrs = $tag[1];
				if ( preg_match( '#\ssrc\s*=\s*["\']?([^"\'\s>]+)#i', $attrs, $src ) ) {
					$url = html_entity_decode( $src[1] );
					if ( 0 === strpos( $url, '//' ) ) {
						$url = 'https:' . $url;
					}
					$host = wp_parse_url( $url, PHP_URL_HOST );
					if ( $host && $host !== $site ) {
						$hosts[ 'https://' . $host ] = true;
					}
					continue;
				}
				// Ignorar bloques de datos que el navegador no ejecuta (JSON, ld+json…).
				if ( preg_match( '#\stype\s*=\s*["\']?([^"\'\s>]+)#i', $attrs, $t )
					&& ! preg_match( '#^(module|(text|application)/(javascript|ecmascript))$#i', $t[1] ) ) {
					continue;
				}
				if ( '' !== trim( $tag[2] ) ) {
					$hashes[ "'sha256-" . base64_encode( hash( 'sha256', $tag[2], true ) ) . "'" ] = true;
				}
			}
		}

		foreach ( preg_split( '/\s+/', $s['csp_extra'], -1, PREG_SPLIT_NO_EMPTY ) as $extra ) {
			$hosts[ $extra ] = true;
		}

		$script_src = "'self' " . implode( ' ', array_keys( $hosts ) ) . ' ' . implode( ' ', array_keys( $hashes ) );
		$policy     = "default-src 'self'; script-src " . trim( preg_replace( '/\s+/', ' ', $script_src ) ) .
			"; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: blob: https:; font-src 'self' data: https:;" .
			" connect-src 'self' https:; media-src 'self' data: blob: https:; frame-src 'self' https:;" .
			" object-src 'none'; base-uri 'self'; frame-ancestors 'self'";

		$name = $s['csp_report_only'] ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
		header( $name . ': ' . $policy, true );
		return $html;
	}

	/* ---------- Ajustes ---------- */

	public static function menu() {
		add_options_page( 'Security Headers', 'Security Headers', 'manage_options', 'bsh', array( __CLASS__, 'page' ) );
	}

	public static function register() {
		register_setting( 'bsh_group', self::OPTION, array( 'sanitize_callback' => array( __CLASS__, 'sanitize' ) ) );
	}

	public static function sanitize( $input ) {
		$out = array();
		foreach ( self::headers() as $slug => $h ) {
			$value = isset( $input[ $slug ]['value'] ) ? $input[ $slug ]['value'] : '';
			// Una cabecera es una sola línea: eliminar saltos de línea (evita header injection).
			$value = trim( preg_replace( '/[\r\n\0]+/', ' ', wp_unslash( $value ) ) );
			$out[ $slug ] = array(
				'enabled' => ! empty( $input[ $slug ]['enabled'] ) ? 1 : 0,
				'value'   => $value,
			);
		}
		$out['csp_report_only'] = ! empty( $input['csp_report_only'] ) ? 1 : 0;
		$out['csp_strict']      = ! empty( $input['csp_strict'] ) ? 1 : 0;
		$out['csp_extra']       = trim( preg_replace( '/[\r\n\0;,]+/', ' ', isset( $input['csp_extra'] ) ? wp_unslash( $input['csp_extra'] ) : '' ) );
		return $out;
	}

	public static function page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$s = self::settings();
		?>
		<div class="wrap">
			<h1>Security Headers</h1>
			<form method="post" action="options.php">
				<?php settings_fields( 'bsh_group' ); ?>
				<table class="form-table" role="presentation">
					<?php foreach ( self::headers() as $slug => $h ) : ?>
						<tr>
							<th scope="row"><?php echo esc_html( $h['name'] ); ?></th>
							<td>
								<label>
									<input type="checkbox" name="<?php echo esc_attr( self::OPTION . "[$slug][enabled]" ); ?>" value="1" <?php checked( $s[ $slug ]['enabled'] ); ?>>
									Activada
								</label><br>
								<input type="text" class="large-text code" name="<?php echo esc_attr( self::OPTION . "[$slug][value]" ); ?>" value="<?php echo esc_attr( $s[ $slug ]['value'] ); ?>">
								<p class="description"><?php echo esc_html( $h['desc'] ); ?></p>
								<?php if ( 'csp' === $slug ) : ?>
									<label>
										<input type="checkbox" name="<?php echo esc_attr( self::OPTION . '[csp_report_only]' ); ?>" value="1" <?php checked( $s['csp_report_only'] ); ?>>
										Modo solo-informe (<code>Content-Security-Policy-Report-Only</code>): no bloquea nada, solo avisa en la consola del navegador.
									</label><br>
									<label>
										<input type="checkbox" name="<?php echo esc_attr( self::OPTION . '[csp_strict]' ); ?>" value="1" <?php checked( $s['csp_strict'] ); ?>>
										<strong>Modo estricto</strong>: sin <code>'unsafe-inline'</code> en <code>script-src</code>. Calcula hashes SHA-256 de los scripts inline de cada página e ignora el valor de arriba. Pruébalo primero en modo solo-informe.
									</label><br>
									<label>
										Fuentes extra para <code>script-src</code> (separadas por espacios):<br>
										<input type="text" class="large-text code" name="<?php echo esc_attr( self::OPTION . '[csp_extra]' ); ?>" value="<?php echo esc_attr( $s['csp_extra'] ); ?>" placeholder="https://www.google.com https://www.gstatic.com">
									</label>
									<p class="description">Dominios cuyos scripts se cargan dinámicamente (no aparecen como &lt;script src&gt; en el HTML), p. ej. reCAPTCHA.</p>
								<?php endif; ?>
							</td>
						</tr>
					<?php endforeach; ?>
				</table>
				<?php submit_button(); ?>
			</form>
		</div>
		<?php
	}
}

Bisiesto_Security_Headers::init();
