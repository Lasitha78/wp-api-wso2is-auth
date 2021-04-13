<?php
/**
 * Plugin Name: OAuth2/OpenID Authentication
 * Description: OAuth2/OpenID Authentication plugin to authenticate wordpress REST API endpoints using an external identity server
 * Author: Lasitha Gunawardena
 * Author URI: https://github.com/lasitha78
 * Version: 0.1
 * Plugin URI: https://github.com/Lasitha78/wp-api-wso2is-auth
 */
global $ooa_db_version;
$ooa_db_version = '1.0';

/**
 * Install database table to store access tokens.
 * 
 * @global type $wpdb
 * @global string $ooa_db_version
 */
function ooa_install() {
    global $wpdb;
    global $ooa_db_version;

    $table_name = $wpdb->prefix . 'ooa_token';
    $user_table = $wpdb->prefix . 'users';

    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE $table_name (
		ID BIGINT(20) NOT NULL AUTO_INCREMENT,
                user_id BIGINT(20) UNSIGNED NOT NULL,
		expired_on datetime NOT NULL,
		token text NOT NULL,
		PRIMARY KEY  (ID),
                FOREIGN KEY (user_id) REFERENCES $user_table(ID)
	) $charset_collate;";

    require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
    dbDelta($sql);

    add_option('ooa_db_version', $ooa_db_version);
}
/**
 * Register installation scripts
 */
register_activation_hook(__FILE__, 'ooa_install');

function json_oauth2_openid_auth_handler($user) {
    global $wpdb;
    global $wp_json_oauth2_openid_auth_error;

    $wp_json_oauth2_openid_auth_error = null;

    // Don't authenticate twice
    if (!empty($user)) {
        return $user;
    }

    $headers = getallheaders();

    /**
     * In multi-site, wp_authenticate_spam_check filter is run on authentication. This filter calls
     * get_currentuserinfo which in turn calls the determine_current_user filter. This leads to infinite
     * recursion and a stack overflow unless the current function is removed from the determine_current_user
     * filter during authentication.
     */
    remove_filter('determine_current_user', 'json_oauth2_openid_auth_handler', 20);
         
    // Check whther the uathorization header is present
    if (!isset($headers['Authorization'])) {
        $user = new WP_Error('forbidden_access', 'Access denied.No authentication header found', array('status' => 403));
    } else {
        if (preg_match('/Bearer\s(\S+)/', $headers['Authorization'], $matches)) {
            $options = get_option('ooa_plugin_options');
            //IF endpoints are not setup throw an error
            if ((!isset($options['api_endpoint_userinfo']) && empty($options['api_endpoint_userinfo'])) || (!isset($options['api_endpoint_introspect']) && empty($options['api_endpoint_introspect']))) {
                $wp_json_oauth2_openid_auth_error = new WP_Error('forbidden_access', 'Identity server endpoint is not set!', array('status' => 403));
                return null;
            }

            $token = $matches[1];
            $remote_url = $options['api_endpoint_userinfo'];
            $validate_url = $options['api_endpoint_introspect'];

            $table_name = $wpdb->prefix . 'ooa_token';
            $now = date("Y-m-d H:i:s");
            $sql = "SELECT * FROM $table_name WHERE expired_on > '$now' AND token = '$token'";
            $row = $wpdb->get_results($sql, OBJECT);

            if (count($row) > 0) {
                $std = $row[0];
                $user = get_user_by('id', $std->user_id);
                return $user;
            } else {
                $args = array("headers" => array("Authorization" => "Bearer $token"), "sslverify" => ($options['ssl_verify'] != 1));
                $result = wp_remote_get($remote_url, $args);
                $code = wp_remote_retrieve_response_code($result);
                if ($code == 200) {
                    $body = wp_remote_retrieve_body($result);
                    $body = json_decode($body);
                    $user = get_user_by('email', $body->sub);
                    if (empty($user)) {
                        $user_id = username_exists($body->sub);
                        if (!$user_id && false == email_exists($body->sub)) {
                            $random_password = wp_generate_password($length = 12, $include_standard_special_chars = false);
                            $user_id = wp_create_user($body->sub, $random_password, $body->sub);
                            $user = get_user_by('id', $user_id);
                        } else {
                            $user = get_user_by('id', $user_id);
                        }
                    }

                    $username = $options['username'];
                    $password = $options['password'];
                    $args["headers"]["Authorization"] = "Basic " . base64_encode("$username:$password");
                    $result = wp_remote_post("$validate_url?token=$token", $args);
                    $code = wp_remote_retrieve_response_code($result);
                    if ($code == 200) {
                        $body = wp_remote_retrieve_body($result);
                        $body = json_decode($body);
                        $uid = $user->ID;
                        $datetime = date("Y-m-d H:i:s", (int)$body->exp);
                        $sql = $wpdb->prepare("INSERT INTO $table_name(`user_id`, `expired_on`, `token`) VALUES(%d,%s,%s)", $uid, $datetime, $token);
                        $wpdb->query($sql);
                    }
                } else {
                    $user = new WP_Error('forbidden_access', 'Access denied.Invalid Token', array('status' => 403));
                }
            }
        }
    }

    add_filter('determine_current_user', 'json_oauth2_openid_auth_handler', 20);

    if (is_wp_error($user)) {
        $wp_json_oauth2_openid_auth_error = $user;
        return null;
    }

    $wp_json_oauth2_openid_auth_error = true;

    return $user->ID;
}

add_filter('determine_current_user', 'json_oauth2_openid_auth_handler', 20);

function json_oauth2_openid_auth_error($error) {
    
    // Passthrough other errors
    if (!empty($error)) {
        return $error;
    }

    global $wp_json_oauth2_openid_auth_error;

    return $wp_json_oauth2_openid_auth_error;
}

add_filter('rest_authentication_errors', 'json_oauth2_openid_auth_error');

/**
 * Setup endpoint in WP admin settings 
 */
function ooa_add_settings_page() {
    add_options_page('OAuth2/OpenID Authentication', 'OAuth2/OpenID', 'manage_options', 'oauth2-openid-authentication-plugin', 'ooa_render_plugin_settings_page');
}

add_action('admin_menu', 'ooa_add_settings_page');

function ooa_render_plugin_settings_page() {
    ?>
    <h2>OAuth2/OpenID Authentication Plugin Settings</h2>
    <form action="options.php" method="post">
        <?php
        settings_fields('ooa_plugin_options');
        do_settings_sections('ooa_plugin');
        ?>
        <input name="submit" class="button button-primary" type="submit" value="<?php esc_attr_e('Save'); ?>" />
    </form>
    <?php
}

function ooa_register_settings() {
    register_setting('ooa_plugin_options', 'ooa_plugin_options', 'ooa_plugin_options_validate');
    add_settings_section('api_settings', '', 'ooa_plugin_section_text', 'ooa_plugin');

    add_settings_field('ooa_plugin_setting_api_endpoint_userinfo', 'Userinfo Endpoint', 'ooa_plugin_setting_api_endpoint_userinfo', 'ooa_plugin', 'api_settings');
    add_settings_field('ooa_plugin_setting_api_endpoint_introspect', 'Token Validation Endpoint', 'ooa_plugin_setting_api_endpoint_introspect', 'ooa_plugin', 'api_settings');
    add_settings_field('ooa_plugin_setting_api_username', 'Username', 'ooa_plugin_setting_api_username', 'ooa_plugin', 'api_settings');
    add_settings_field('ooa_plugin_setting_api_password', 'Password', 'ooa_plugin_setting_api_password', 'ooa_plugin', 'api_settings');
    add_settings_field('ooa_plugin_setting_ssl_verify', 'Skip SSL Verification', 'ooa_plugin_setting_ssl_verify', 'ooa_plugin', 'api_settings');
}

add_action('admin_init', 'ooa_register_settings');

function ooa_plugin_options_validate($input) {
    $newinput['api_endpoint_userinfo'] = trim($input['api_endpoint_userinfo']);
    $newinput['api_endpoint_introspect'] = trim($input['api_endpoint_introspect']);
    $newinput['username'] = trim($input['username']);
    $newinput['password'] = trim($input['password']);
    $newinput['ssl_verify'] = trim($input['ssl_verify']);
    return $newinput;
}

function ooa_plugin_section_text() {
    echo '<p>Setup Oauth2/OpenID user information endpoint</p>';
}

function ooa_plugin_setting_api_endpoint_userinfo() {
    $options = get_option('ooa_plugin_options');
    echo "<input id='ooa_plugin_setting_api_endpoint_userinfo' size='50' name='ooa_plugin_options[api_endpoint_userinfo]' type='text' value='" . esc_attr($options['api_endpoint_userinfo']) . "' />";
}

function ooa_plugin_setting_api_endpoint_introspect() {
    $options = get_option('ooa_plugin_options');
    echo "<input id='ooa_plugin_setting_api_endpoint_introspect' size='50' name='ooa_plugin_options[api_endpoint_introspect]' type='text' value='" . esc_attr($options['api_endpoint_introspect']) . "' />";
}

function ooa_plugin_setting_api_username() {
    $options = get_option('ooa_plugin_options');
    echo "<input id='ooa_plugin_setting_api_username' name='ooa_plugin_options[username]' type='text' value='" . esc_attr($options['username']) . "' />";
}

function ooa_plugin_setting_api_password() {
    $options = get_option('ooa_plugin_options');
    echo "<input id='ooa_plugin_setting_api_password'  name='ooa_plugin_options[password]' type='password' value='" . esc_attr($options['password']) . "' />";
}

function ooa_plugin_setting_ssl_verify() {
    $options = get_option('ooa_plugin_options');
    if ($options['ssl_verify'] == 1) {
        echo "<input id='ooa_plugin_setting_ssl_verify' name='ooa_plugin_options[ssl_verify]' type='checkbox' value='1' checked/>";
    } else {
        echo "<input id='ooa_plugin_setting_ssl_verify' name='ooa_plugin_options[ssl_verify]' type='checkbox' value='1'/>";
    }
}
