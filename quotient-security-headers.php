<?php
/**
 * Plugin Name: Security Headers by Quotient
 * Plugin URI: https://github.com/quotientinc/quotient-security-headers 
 * Description: Adds essential web security headers to improve site security.
 * Version: 1.0.0
 * Requires at least: 5.0
 * Requires PHP: 7.4
 * Author: Mike Broyles
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Send security headers on frontend requests.
 */
function wp_security_headers_send() {
	if (
		is_admin() ||
		wp_doing_ajax() ||
		wp_doing_cron() ||
		headers_sent()
	) {
		return;
	}

	if ( is_ssl() ) {
		header( 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' );
	}

	$csp_directives = array(
		"default-src * 'unsafe-inline' 'unsafe-eval' data: blob:",
		"script-src * 'unsafe-inline' 'unsafe-eval'",
		"style-src * 'unsafe-inline'",
		"img-src * data: blob:",
		"font-src * data:",
		"connect-src *",
		"media-src *",
		"object-src *",
		"child-src *",
		"frame-src *",
		"worker-src *",
		"frame-ancestors 'self'",
	);
	$csp_directives = apply_filters(
		'wp_security_headers_csp_directives',
		$csp_directives
	);
	header( 'Content-Security-Policy: ' . implode( '; ', $csp_directives ) );

	header( 'X-Frame-Options: SAMEORIGIN' );
	header( 'X-Content-Type-Options: nosniff' );
	header( 'Referrer-Policy: strict-origin-when-cross-origin' );

	$permissions = array(
		'camera=()',
		'microphone=()',
		'geolocation=()',
		'payment=()',
		'usb=()',
		'magnetometer=()',
		'gyroscope=()',
		'accelerometer=()',
	);
	$permissions = apply_filters(
		'wp_security_headers_permissions_policies',
		$permissions
	);
	header( 'Permissions-Policy: ' . implode( ', ', $permissions ) );
}
add_action( 'send_headers', 'wp_security_headers_send' );

/**
 * Display admin activation notice.
 */
function wp_security_headers_admin_notice() {
	if ( ! get_option( 'wp_security_headers_activation_notice' ) ) {
		return;
	}
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	?>
	<div class="notice notice-success is-dismissible">
		<p>
			<strong>
				<?php esc_html_e( 'Security Headers Plugin activated!', 'security-headers' ); ?>
			</strong>
			<?php esc_html_e(
				'Your site is now sending security headers to improve protection.',
				'security-headers'
			); ?>
		</p>
	</div>
	<?php
	delete_option( 'wp_security_headers_activation_notice' );
}
add_action( 'admin_notices', 'wp_security_headers_admin_notice' );

/**
 * Add info link to plugin row.
 *
 * @param array $links Existing action links.
 * @return array Modified links.
 */
function wp_security_headers_action_links( $links ) {
	$info_link = sprintf(
		'<a href="#" onclick="alert(%s); return false;">%s</a>',
		esc_js( __( 'Security headers are automatically applied. No configuration needed!', 'security-headers' ) ),
		esc_html__( 'Info', 'security-headers' )
	);
	array_unshift( $links, $info_link );
	return $links;
}
add_filter(
	'plugin_action_links_' . plugin_basename( __FILE__ ),
	'wp_security_headers_action_links'
);

/**
 * Plugin activation.
 */
function wp_security_headers_activate() {
	add_option( 'wp_security_headers_activation_notice', true );
}
register_activation_hook( __FILE__, 'wp_security_headers_activate' );

/**
 * Plugin deactivation.
 */
function wp_security_headers_deactivate() {
	delete_option( 'wp_security_headers_activation_notice' );
}
register_deactivation_hook( __FILE__, 'wp_security_headers_deactivate' );

