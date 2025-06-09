<?php
/**
 * Plugin Name: Security Headers
 * Description: Adds security headers with admin settings and tooltips.
 * Version: 1.0.2
 * Author: Mike Broyles
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

add_action( 'plugins_loaded', 'wp_security_headers_init' );
function wp_security_headers_init() {
    add_action( 'admin_menu', 'wp_security_headers_admin_menu' );
    add_action( 'admin_init', 'wp_security_headers_register_settings' );
    add_action( 'send_headers', 'wp_security_headers_send_headers' );
}

function wp_security_headers_admin_menu() {
    add_options_page(
        'Security Headers',
        'Security Headers',
        'manage_options',
        'security-headers',
        'wp_security_headers_settings_page'
    );
}

function wp_security_headers_register_settings() {
    $headers = wp_security_headers_defaults();
    foreach ( $headers as $key => $header ) {
        register_setting( 'wp_security_headers_settings', $key );
    }
    register_setting( 'wp_security_headers_settings', 'wp_security_headers_reset' );
}

function wp_security_headers_defaults() {
    return array(
        'security_header_hsts' => array(
            'label'       => 'Strict-Transport-Security',
            'description' => 'Forces HTTPS and instructs browsers to only access the site over HTTPS for a ' .
                             'specified time. Helps prevent downgrade attacks and cookie hijacking.',
            'enabled'     => true,
        ),
        'security_header_csp' => array(
            'label'       => 'Content-Security-Policy',
            'description' => 'Restricts where content (scripts, styles, images) can load from. ' .
                             'Helps mitigate XSS and data injection attacks.',
            'enabled'     => true,
        ),
        'security_header_frame' => array(
            'label'       => 'X-Frame-Options',
            'description' => 'Prevents the site from being embedded in iframes on other sites, protecting ' .
                             'against clickjacking attacks.',
            'enabled'     => true,
        ),
        'security_header_mime' => array(
            'label'       => 'X-Content-Type-Options',
            'description' => 'Instructs browsers not to sniff MIME types. Reduces exposure to drive-by ' .
                             'download and content-type confusion attacks.',
            'enabled'     => true,
        ),
        'security_header_referrer' => array(
            'label'       => 'Referrer-Policy',
            'description' => 'Controls how much referrer information is included with requests. Helps balance ' .
                             'privacy and analytics needs.',
            'enabled'     => true,
        ),
        'security_header_permissions' => array(
            'label'       => 'Permissions-Policy',
            'description' => 'Gives fine-grained control over access to powerful browser features like ' .
                             'camera, microphone, and geolocation.',
            'enabled'     => true,
        ),
    );
}

function wp_security_headers_settings_page() {
    $headers = wp_security_headers_defaults();
    ?>
    <div class="wrap">
        <h1>Security Headers Settings</h1>
        <form method="post" action="options.php">
            <?php settings_fields( 'wp_security_headers_settings' ); ?>
            <table class="form-table">
                <?php foreach ( $headers as $key => $header ) :
                    $enabled = get_option( $key, $header['enabled'] ); ?>
                    <tr>
                        <th scope="row">
                            <?php echo esc_html( $header['label'] ); ?>
                        </th>
                        <td>
                            <label>
                                <input type="checkbox" name="<?php echo esc_attr( $key ); ?>"
                                       value="1" <?php checked( $enabled, true ); ?> />
                                Enable
                            </label>
                            <p class="description"><?php echo esc_html( $header['description'] ); ?></p>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </table>
            <p>
                <input type="submit" class="button button-primary" value="Save Changes">
                <input type="submit" name="wp_security_headers_reset" class="button button-secondary"
                       value="Reset to Recommended">
            </p>
        </form>
    </div>
    <?php
}

function wp_security_headers_send_headers() {
    $headers = wp_security_headers_defaults();

    foreach ( $headers as $key => $header ) {
        $enabled = get_option( $key, $header['enabled'] );
        if ( ! $enabled ) {
            continue;
        }

        switch ( $key ) {
            case 'security_header_hsts':
                if ( is_ssl() ) {
                    header( 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' );
                }
                break;
            case 'security_header_csp':
                $csp = "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; script-src * 'unsafe-inline' 'unsafe-eval'; ";
                $csp .= "style-src * 'unsafe-inline'; img-src * data: blob:; font-src * data:; connect-src *; ";
                $csp .= "media-src *; object-src *; child-src *; frame-src *; worker-src *; frame-ancestors 'self';";
                header( 'Content-Security-Policy: ' . $csp );
                break;
            case 'security_header_frame':
                header( 'X-Frame-Options: SAMEORIGIN' );
                break;
            case 'security_header_mime':
                header( 'X-Content-Type-Options: nosniff' );
                break;
            case 'security_header_referrer':
                header( 'Referrer-Policy: strict-origin-when-cross-origin' );
                break;
            case 'security_header_permissions':
                $permissions = [
                    'camera=()', 'microphone=()', 'geolocation=()', 'payment=()',
                    'usb=()', 'magnetometer=()', 'gyroscope=()', 'accelerometer=()'
                ];
                header( 'Permissions-Policy: ' . implode( ', ', $permissions ) );
                break;
        }
    }
}

register_activation_hook( __FILE__, 'wp_security_headers_activate' );
register_deactivation_hook( __FILE__, 'wp_security_headers_deactivate' );

function wp_security_headers_activate() {
    $defaults = wp_security_headers_defaults();
    foreach ( $defaults as $key => $val ) {
        add_option( $key, $val['enabled'] );
    }
}

function wp_security_headers_deactivate() {
    $defaults = wp_security_headers_defaults();
    foreach ( $defaults as $key => $val ) {
        delete_option( $key );
    }
}

