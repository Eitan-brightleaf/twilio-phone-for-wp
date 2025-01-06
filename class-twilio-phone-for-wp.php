<?php
/**
 * The file that defines the core plugin class
 *
 * A class definition that includes attributes and functions used across both the
 * public-facing side of the site and the admin area.
 *
 * @link       https://digital.brightleaf.info
 * @since      1.0.0
 *
 * @package    Twilio_phone_for_wp
 * @subpackage Twilio_phone_for_wp/includes
 */


use BrightleafDigital\TwilioPhoneForWordPress\Twilio\Jwt\AccessToken;
use BrightleafDigital\TwilioPhoneForWordPress\Twilio\Jwt\Grants\VoiceGrant;
use Random\RandomException;

if ( ! defined( 'ABSPATH' ) ) {
	die;
}

require_once 'vendor/autoload.php';


/**
 * The core plugin class.
 *
 * This is used to define internationalization, admin-specific hooks, and
 * public-facing site hooks.
 *
 * Also maintains the unique identifier of this plugin as well as the current
 * version of the plugin.
 *
 * @since      1.0.0
 * @package    Twilio_phone_for_wp
 * @subpackage Twilio_phone_for_wp/includes
 * @author     Brightleaf Digital <eitan@brightleafc.com>
 */
class Twilio_Phone_For_WP {

	/**
	 * The unique identifier of this plugin.
	 *
	 * @var      string    $plugin_name    The string used to uniquely identify this plugin.
	 */
	protected string $plugin_name = 'Twilio_Phone_For_WP';

	/**
	 * The current version of the plugin.
	 *
	 * @var      string    $version    The current version of the plugin.
	 */
	protected string $version = TWILIO_PHONE_FOR_WP_VERSION;
	/**
	 * Holds the short title for the Twilio Phone integration in WordPress.
	 *
	 * @var string $short_title A short title for the plugin
	 */
	protected string $short_title = 'Twilio Phone';
	/**
	 * The slug identifier for the Twilio Phone for WordPress plugin.
	 *
	 * @var string The slug for the plugin
	 */
	protected string $slug = 'twilio-phone-for-wp';

	/**
	 * Holds the prefix used for identifying plugin-specific settings or options.
	 *
	 * @var string $prefix A unique prefix for the plugin.
	 */
	protected string $prefix = 'tpfwp';

    /**
     * Stores the URL for the settings page.
     *
     * @var string $settings_url The URL used to navigate to the settings page.
     */
    protected string $settings_url;

    /**
     * Initializes the class instance and sets up the settings URL for the admin page.
     * The settings URL is generated dynamically based on the specified slug and admin base URL.
     *
     * @return void
     */
    public function __construct() {
        $this->settings_url = add_query_arg( 'page', $this->slug, admin_url( 'admin.php' ) );
    }


	/**
	 * Executes the primary functionality of the class or initiates the process it is designed to manage.
	 *
	 * @return void
	 */
	public function run(): void {
		$this->init_admin();
	}

	/**
	 * The name of the plugin used to uniquely identify it within the context of
	 * WordPress and to define internationalization functionality.
	 *
	 * @since     1.0.0
	 * @return    string    The name of the plugin.
	 */
	public function get_plugin_name(): string {
		return $this->plugin_name;
	}


	/**
	 * Retrieve the version number of the plugin.
	 *
	 * @since     1.0.0
	 * @return    string    The version number of the plugin.
	 */
	public function get_version(): string {
		return $this->version;
	}

	/**
	 * Initializes the admin functionality by attaching the 'add_top_level_menu' method
	 * to the 'admin_menu' action hook.
	 *
	 * @return void
	 */
	private function init_admin(): void {
        add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_scripts' ] );
		add_action( 'admin_menu', [ $this, 'add_top_level_menu' ] );
        add_action( 'wp_ajax_get_token', [ $this, 'get_token' ] );
        // todo add settings link to plugin pg
	}

	/**
	 * Generates and returns a Twilio access token required for communication.
	 *
	 * This method verifies the security nonce, retrieves Twilio credentials from WordPress options,
	 * instantiates a new Twilio AccessToken, applies necessary voice grants, and then returns the JWT token
	 * and associated identity in a JSON response. If any step fails, an appropriate error is returned as JSON.
	 *
	 * @return void Outputs a JSON response containing either the access token and identity or an error message.
	 * @throws Exception Throws an exception if the Twilio library encounters an issue while generating the token.
	 */
	public function get_token(): void {

		if ( ! isset( $_POST['security'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['security'] ) ), 'get_token_nonce' ) ) {
			wp_send_json_error( 'Invalid nonce', 403 );
			die();
		}

		$connect_info = get_option( 'twilio_connect_info' );
		if ( ! is_array( $connect_info ) ) {
			wp_send_json_error( 'Invalid credentials', 500 );
		}
		$account_sid    = $connect_info['account_sid'] ?? null;
		$api_key_sid    = $connect_info['api_key_sid'] ?? null;
		$api_key_secret = $connect_info['api_key_secret'] ?? null;
		$app_sid        = $connect_info['app_sid'] ?? null;
		$phone_number   = $connect_info['phone_number'] ?? null;

		$access_token = new AccessToken( $account_sid, $api_key_sid, $api_key_secret, 3600, $phone_number );

		$voice_grant = new VoiceGrant();
		$voice_grant->setOutgoingApplicationSid( $app_sid );
		$voice_grant->setIncomingAllow( true );
		$access_token->addGrant( $voice_grant );

		$result = [
			'token'    => $access_token->toJWT(),
		];
		wp_send_json_success( $result );
	}

	/**
	 * Encrypts the provided data using AES-256-CTR encryption or a fallback method.
	 * If the OpenSSL extension is available, it generates a secure encryption key,
	 * nonce, and MAC to ensure data integrity. Otherwise, it falls back to a database-based encryption method.
	 *
	 * @param string $data The data to encrypt.
	 *
	 * @return string|false The encrypted data as a base64-encoded string, or false if encryption fails.
	 * @throws RandomException Could theoretically throw an exception if no source of randomness is found.
	 */
	public static function encrypt( string $data ): false|string {

		if ( function_exists( 'openssl_encrypt' ) ) {
			$salt           = wp_salt( 'nonce' ); // Generate a secure salt for encryption.
			$encryption_key = 'bl_digital_encryption_key' . $salt; // Create the encryption key.
			$mac_key        = 'bl_digital_encryption_mac' . $salt; // Create the MAC key.

			$nonce = random_bytes( 16 ); // Generate a secure nonce (IV).

			$options     = OPENSSL_RAW_DATA;
			$cipher_name = 'aes-256-ctr'; // Specify the encryption cipher.

			$ciphertext = openssl_encrypt( $data, $cipher_name, $encryption_key, $options, $nonce );

			if ( false === $ciphertext ) {
				return false; // Return false if encryption fails.
			}

			// Generate a MAC for integrity verification.
			$mac = hash_hmac( 'sha512', $nonce . $ciphertext, $mac_key, true );

			// Combine the MAC, nonce, and ciphertext into a single encoded string.
			$encrypted_value = base64_encode( $mac . $nonce . $ciphertext ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
		} else {
			// Fallback logic if OpenSSL is not available.
			$encrypted_value = EncryptDB::encrypt( $data, wp_salt( 'nonce' ) );
		}
		return $encrypted_value;
	}

	/**
	 * Decrypts a given encrypted data string using OpenSSL or a fallback mechanism.
	 *
	 * The method first decodes the Base64-encoded input, extracts the MAC,
	 * the nonce (IV), and the ciphertext. It verifies the integrity of the data
	 * using HMAC before decrypting the ciphertext using the aes-256-ctr cipher.
	 * If OpenSSL is unavailable, a fallback decryption method is used.
	 *
	 * @param string $data The Base64-encoded encrypted data string to decrypt.
	 * @return false|string Returns the decrypted string on success, or false on failure (e.g., data corruption or invalid input).
	 */
	public static function decrypt( string $data ): false|string {

		if ( function_exists( 'openssl_encrypt' ) ) {
			// Decode the encrypted data from base64.
			$data_decoded = base64_decode( $data, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode

			if ( false === $data_decoded ) {
				return false; // If base64 decoding fails, return false.
			}

			$mac        = substr( $data_decoded, 0, 64 ); // Extract the MAC from the combined string.
			$nonce      = substr( $data_decoded, 64, 16 ); // Extract the nonce (IV) from the combined string.
			$ciphertext = substr( $data_decoded, 80 ); // Extract the ciphertext from the combined string.

			$salt           = wp_salt( 'nonce' ); // Generate the same secure salt for encryption.
			$encryption_key = 'bl_digital_encryption_key' . $salt; // Create the encryption key.
			$mac_key        = 'bl_digital_encryption_mac' . $salt; // Create the MAC key.

			// Generate a MAC for integrity verification.
			$mac_check = hash_hmac( 'sha512', $nonce . $ciphertext, $mac_key, true );

			// Compare the provided MAC with the generated MAC.
			if ( ! hash_equals( $mac, $mac_check ) ) {
				return false; // Return false if MAC verification fails.
			}

			$options     = OPENSSL_RAW_DATA;
			$cipher_name = 'aes-256-ctr'; // Specify the encryption cipher.

			// Decrypt the ciphertext.
			$decrypted_value = openssl_decrypt( $ciphertext, $cipher_name, $encryption_key, $options, $nonce );

		} else {
			// Fallback logic if OpenSSL is not available.
			$decrypted_value = EncryptDB::decrypt( $data, wp_salt( 'nonce' ) );
		}

		return $decrypted_value;
	}

	/**
	 * Enqueues styles for the plugin's admin page by registering and conditionally loading the plugin page CSS.
	 * The style is registered with a version based on the file's last modification time for cache busting.
	 * The style is enqueued only if the current admin page matches the plugin's slug.
	 *
	 * @return void
	 */
	public function enqueue_scripts(): void {
        $css_plugin_pg_url     = plugins_url( 'includes/css/plugin-page.css', __FILE__ );
        $css_plugin_pg_path    = plugin_dir_path( __FILE__ ) . 'includes/css/plugin-page.css';
        $css_plugin_pg_version = filemtime( $css_plugin_pg_path );
	    wp_register_style( $this->prefix . '_plugin_page', $css_plugin_pg_url, [], $css_plugin_pg_version );

        $js_plugin_pg_url     = plugins_url( 'includes/js/plugin-page.js', __FILE__ );
		$js_plugin_pg_path    = plugin_dir_path( __FILE__ ) . 'includes/js/plugin-page.js';
		$js_plugin_pg_version = filemtime( $js_plugin_pg_path );
		wp_register_script( $this->prefix . '_plugin_page', $js_plugin_pg_url, [ 'jquery' ], $js_plugin_pg_version, true );

        if ( isset( $_GET['page'] ) && sanitize_key( $_GET['page'] ) === $this->slug ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
	        wp_enqueue_style( $this->prefix . '_plugin_page' );
            wp_enqueue_script( $this->prefix . '_plugin_page' );
        }

        $twilio_phone_url     = plugins_url( 'includes/js/twilio-phone.js', __FILE__ );
        $twilio_phone_path    = plugin_dir_path( __FILE__ ) . 'includes/js/twilio-phone.js';
        $twilio_phone_version = filemtime( $twilio_phone_path );
        wp_register_script( $this->prefix . '_twilio_phone', $twilio_phone_url, [ 'jquery' ], $twilio_phone_version, true );
        if ( isset( $_GET['page'] ) && sanitize_key( $_GET['page'] ) === $this->slug && isset( $_GET['tab'] ) && 'phone' === sanitize_key( $_GET['tab'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $twilio_url     = plugins_url( 'includes/js/twilio.min.js', __FILE__ );
            $twilio_path    = plugin_dir_path( __FILE__ ) . 'includes/js/twilio.min.js';
            $twilio_version = filemtime( $twilio_path );

            wp_enqueue_script( 'twilio-client', $twilio_url, [], $twilio_version, true );
            wp_enqueue_script( $this->prefix . '_twilio_phone' );
            wp_add_inline_script(
                $this->prefix . '_twilio_phone',
                sprintf(
	                'const dialpadAjax = { ajax_url: "%s", security: "%s" };',
	                admin_url( 'admin-ajax.php' ),
	                wp_create_nonce( 'get_token_nonce' )
                ),
                'before'
            );
        }
	}
	/**
	 * Add a top-level menu in the WordPress admin.
	 *
	 * @return void
	 */
	public function add_top_level_menu(): void {

		global $menu;

		// if another plugin in our suit is already installed and created the submenu we don't have to.
		if ( in_array( 'gravity_ops', array_column( $menu, 2 ), true ) ) {
			add_submenu_page(
				'gravity_ops',
				$this->short_title,
				$this->short_title,
				'manage_options',
				$this->slug,
				[ $this, 'create_sub_menu' ]
			);

			return;
		}

		$number        = 10;
		$menu_position = '16.' . $number;
		while ( isset( $menu[ $menu_position ] ) ) {
			$number       += 10;
			$menu_position = '16.' . $number;
		}

		add_menu_page(
			'GravityOps',
			'GravityOps',
			'manage_options',
			'gravity_ops',
			[ $this, 'create_top_level_menu' ],
			'', // $this->get_app_menu_icon(),
			$menu_position
		);
		add_submenu_page(
			'gravity_ops',
			$this->short_title,
			$this->short_title,
			'manage_options',
			$this->slug,
			[
				$this,
				'create_sub_menu',
			]
		);
	}
	/**
	 * Create top-level menu content.
	 *
	 * @return void
	 */
	public function create_top_level_menu(): void {
		global $submenu;

		$parent_menu         = $submenu['gravity_ops'];
		$gravity_ops_plugins = [
			'Asana Integration'     => '<a target="_blank" href="https://digital.brightleaf.info/asana-gravity-forms/">Asana Integration for Gravity Forms</a>',
			'Mass Notifications'    => '<a target="_blank" href="https://digital.brightleaf.info/mass-email-notifications-for-gravity-forms/">Mass Email Notifications for Gravity Forms</a>',
			'Recurring Submissions' => '<a target="_blank" href="https://digital.brightleaf.info/recurring-form-submissions-for-gravity-forms/">Recurring Form Submissions for Gravity Forms</a>',
			'Global Variables'      => '<a target="_blank" href="https://digital.brightleaf.info/global-variables-for-gravity-math/">Global Variables for Gravity Math</a>',
		];

		$installed_plugins = array_column( $parent_menu, 0 );
		$this->unset_menu_item( $installed_plugins );
		$not_installed_plugins = $this->get_not_installed_plugins( $gravity_ops_plugins, $installed_plugins );

		if ( ! empty( $not_installed_plugins ) ) {
			echo '<div style="font-size: 1.5em; line-height: 1.5em; padding: 20px;">';
			$this->render_plugins_section( $installed_plugins, $gravity_ops_plugins, 'You already have some of our awesome plugins:', 'Don\'t you want to try the rest?!' );
			$this->render_plugins_section( $not_installed_plugins, $gravity_ops_plugins, '', '', true );
			echo '</div>';
			echo '<p>Or get them all, plus future add-ons, with a <a target="_blank" href="https://checkout.freemius.com/mode/dialog/bundle/16483/plan/27519/">bundle subscription.</a></p>';
		} else {
			echo '<p style="font-size: 1.5em; line-height: 1.5em; padding: 20px;">
               Amazing! You have all our plugins! <br>
               For more information about them, and to keep up to date with changes and new plugins, check out our <a target="_blank" href="https://digital.brightleaf.info">website</a>.
             </p>';
		}
	}
	/**
	 * Unsets a specific item from the installed plugins array.
	 *
	 * @param array $installed_plugins Reference to the array of installed plugins.
	 * @return void
	 */
	private function unset_menu_item( array &$installed_plugins ): void {
		$unset_index = array_search( 'GravityOps', $installed_plugins, true );
		if ( false !== $unset_index ) {
			unset( $installed_plugins[ $unset_index ] );
		}
	}

	/**
	 * Identifies which plugins from the given list of Gravity Ops plugins are not installed.
	 *
	 * @param array $gravity_ops_plugins An associative array of plugin short titles and their full titles.
	 * @param array $installed_plugins An array of short titles of already installed plugins.
	 * @return array An array of short titles of Gravity Ops plugins that are not installed.
	 */
	private function get_not_installed_plugins( array $gravity_ops_plugins, array $installed_plugins ): array {
		$not_installed_plugins = [];
		foreach ( $gravity_ops_plugins as $short_title => $plugin_title ) {
			if ( ! in_array( $short_title, $installed_plugins, true ) ) {
				$not_installed_plugins[] = $short_title;
			}
		}
		return $not_installed_plugins;
	}

	/**
	 * Renders a section displaying a list of plugins with optional introductory and ending text.
	 *
	 * @param array  $plugins List of plugins to display.
	 * @param array  $gravity_ops_plugins Associative array mapping plugin identifiers to their displayable names.
	 * @param string $intro_text Introductory text to display before the list of plugins.
	 * @param string $ending_text Optional. Text to display after the list of plugins. Default is an empty string.
	 * @param bool   $hide_text Optional. Whether to hide the introductory text. Default is false.
	 *
	 * @return void
	 */
	private function render_plugins_section( array $plugins, array $gravity_ops_plugins, string $intro_text, string $ending_text = '', bool $hide_text = false ): void {
		if ( ! $hide_text ) {
			echo esc_textarea( $intro_text );
		}
		echo '<ul style="list-style: disc;">';
		foreach ( $plugins as $plugin ) {
			echo '<li>' . wp_kses(
					$gravity_ops_plugins[ $plugin ],
					[
						'a' => [
							'href'   => [],
							'target' => [],
						],
					]
				) . '</li>';
		}
		echo '</ul>';
		if ( $ending_text ) {
			echo esc_textarea( $ending_text );
		}
	}

    /**
     * Creates a sub-menu for the plugin in the WordPress admin dashboard.
     *
     * @throws RandomException Could theoretically throw an exception if encrypting data while rendering one of the pages and a source of randomness isn't found.
     */
	public function create_sub_menu(): void {

        if ( isset( $_GET['tab'] ) && 'phone' === sanitize_key( $_GET['tab'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $this->render_phone_tab();
            return;
        }

        if ( isset( $_GET['step'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $step = sanitize_key( $_GET['step'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        } else {
            $step = '1';
        }
        match ( $step ) {
            '1' => $this->render_step_one(),
            '2' => $this->render_step_two(),
            '3' => $this->render_step_three(),
            '4' => $this->render_step_four(),
        };
	}

    /**
     * Renders the interface for Step One of the setup process, guiding the user to retrieve
     * and input their Twilio Account SID.
     *
     * @return void
     * @throws RandomException Could theoretically throw an exception if no source of randomness is found.
     */
    private function render_step_one(): void {
        $account_sid_pic = plugins_url( '/includes/images/account-sid.png', __FILE__ );
        $nonce           = wp_create_nonce( 'twilio_phone_setup_part_one' );

        if ( isset( $_POST['twilio-setup-step-one'] ) && 'save' === $_POST['twilio-setup-step-one'] && isset( $_POST['twilio-setup-pt-one-nonce'] ) &&
            wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['twilio-setup-pt-one-nonce'] ) ), 'twilio_phone_setup_part_one' ) &&
            ! empty( $_POST['account_sid'] ) ) {

            $account_sid = sanitize_text_field( wp_unslash( $_POST['account_sid'] ) );

            if ( ! $this::decrypt( $account_sid ) ) {
                $account_sid  = $this::encrypt( $account_sid );
                $connect_info = get_option( 'twilio_connect_info' );
                if ( ! is_array( $connect_info ) ) {
                    $connect_info = [];
                }
                $connect_info['account_sid'] = $account_sid;
                update_option( 'twilio_connect_info', $connect_info );
            }
        }
        $connect_info = get_option( 'twilio_connect_info' );
        $account_sid  = $connect_info['account_sid'] ?? '';
        ?>
            <div class="wrap fs-section fs-full-size-wrapper">
                <h2 class="nav-tab-wrapper" style="display: none;">
                    <a href="<?php echo esc_url( $this->settings_url ); ?>" class='nav-tab fs-tab nav-tab-active home'>Settings</a>
                    <a href="<?php echo esc_url( $this->settings_url ); ?>&tab=phone" class='nav-tab fs-tab'>Twilio Phone</a>
                </h2>
                <div class="twilio-setup-section-content">
                    <h1>Twilio Account SID</h1>
                    <nav class="nav-bar">
                        <a href="<?php echo esc_url( $this->settings_url ); ?>&step=1" class="active-link">Step 1-Get Account SID</a> |
                        <a href="<?php echo esc_url( $this->settings_url ); ?>&step=2">Step 2-Enter API Info</a> |
                        <a href="<?php echo esc_url( $this->settings_url ); ?>&step=3">Step 3-Enter App SID</a> |
                        <a href="<?php echo esc_url( $this->settings_url ); ?>&step=4">Step 4-Enter Phone Number</a>
                    </nav>
                    <p class="twilio-setup-instructions">
                        Go to the <a target="_blank" href="https://www.twilio.com/console">Twilio Console Home Page</a> and copy
                        your Account SID here.
                        You can find it on the bottom of the page in the "Account Info" section.
                    </p>
                    <img src="<?php echo esc_url( $account_sid_pic ); ?>" alt="Twilio Account SID" class="twilio-setup-pic">
                    <form action="" method="post" class="twilio-setup-form">
                        <input type="hidden" name="twilio-setup-pt-one-nonce" value="<?php echo esc_attr( $nonce ); ?>">
                        <label for="account_sid" class="twilio-setup-label">Account SID</label>
                        <input id="account_sid" type="password" name="account_sid"
                                                                value="<?php echo esc_attr( $account_sid ); ?>" required class="twilio-setup-input">
                        <button type="submit" class="twilio-setup-button button" name="twilio-setup-step-one" value="save">Save
                        </button>
                    </form>
                    <a href="<?php echo esc_url( $this->settings_url ); ?>&step=2" class="button">Next</a>
                </div>
            </div>
        <?php
    }

	/**
	 * Renders the second step of the Twilio API setup process.
	 * This method generates a nonce for security, validates form submissions, and processes the provided API Key SID
	 * and Secret. Submitted data is encrypted and stored in the database if validation succeeds.
	 * Additionally, it displays instructional text and images to guide the user on how to obtain API Key credentials
	 * from the Twilio console.
	 *
	 * @return void This method does not return a value.
	 * @throws RandomException Can theoretically throw an exception if source of randomness is not found while encrypting the credentials.
	 */
    private function render_step_two(): void {
        $nonce = wp_create_nonce( 'twilio_phone_setup_part_two' );

        $create_api_button_pic   = plugins_url( '/includes/images/create-api-key-button.png', __FILE__ );
        $create_new_api_key_pic  = plugins_url( '/includes/images/create-new-api-key.png', __FILE__ );
        $api_key_credentials_pic = plugins_url( '/includes/images/api-key-credentials.png', __FILE__ );

        if ( isset( $_POST['twilio-setup-step-two'] ) && 'save' === $_POST['twilio-setup-step-two'] && isset( $_POST['twilio-setup-pt-two-nonce'] ) &&
            wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['twilio-setup-pt-two-nonce'] ) ), 'twilio_phone_setup_part_two' ) &&
            ! empty( $_POST['api_key_sid'] ) && ! empty( $_POST['api_key_secret'] ) ) {

            $api_key_sid    = sanitize_text_field( wp_unslash( $_POST['api_key_sid'] ) );
            $api_key_secret = sanitize_text_field( wp_unslash( $_POST['api_key_secret'] ) );

            $connect_info = get_option( 'twilio_connect_info' );
            if ( ! is_array( $connect_info ) ) {
                $connect_info = [];
            }

            if ( ! $this::decrypt( $api_key_sid ) ) {
                $api_key_sid                 = $this::encrypt( $api_key_sid );
                $connect_info['api_key_sid'] = $api_key_sid;
            }
            if ( ! $this::decrypt( $api_key_secret ) ) {
                $api_key_secret                 = $this::encrypt( $api_key_secret );
                $connect_info['api_key_secret'] = $api_key_secret;
            }
            update_option( 'twilio_connect_info', $connect_info );
        }

        $connect_info   = get_option( 'twilio_connect_info' );
        $api_key_sid    = $connect_info['api_key_sid'] ?? '';
        $api_key_secret = $connect_info['api_key_secret'] ?? '';

        ?>
            <div class="wrap fs-section fs-full-size-wrapper">
                <h2 class="nav-tab-wrapper" style="display: none;">
                    <a href="<?php echo esc_url( $this->settings_url ); ?>" class='nav-tab fs-tab nav-tab-active home'>Settings</a>
                    <a href="<?php echo esc_url( $this->settings_url ); ?>&tab=phone" class='nav-tab fs-tab'>Twilio Phone</a>
                </h2>
                <div class="twilio-setup-section-content">
                    <h1>Enter API Info</h1>
                    <nav class="nav-bar">
                        <a href="<?php echo esc_url( $this->settings_url ); ?>&step=1">Step 1-Get Account SID</a> |
                        <a href="<?php echo esc_url( $this->settings_url ); ?>&step=2" class="active-link">Step 2-Enter API Info</a> |
                        <a href="<?php echo esc_url( $this->settings_url ); ?>&step=3">Step 3-Enter App SID</a> |
                        <a href="<?php echo esc_url( $this->settings_url ); ?>&step=4">Step 4-Enter Phone Number</a>
                    </nav>
                    <p class="twilio-setup-instructions">
                        Navigate to <a target="_blank" href="https://www.twilio.com/console/voice/settings/api-keys">Twilio console > Voice > Settings > API Keys</a>.
                        Click the “Create API Key” button. Enter a name for the friendly name field (such as "Twilio WordPress plugin").
                        Leave the “Key Type” as “Standard”. Click the “Create” button to create the API key.
                        Please realise the API key secret is only shown once, so make sure you copy it down somewhere safe. Then enter the API key SID and secret below.
                    </p>
                    <div class="twilio-setup-images">
                        <img src="<?php echo esc_url( $create_api_button_pic ); ?>" alt="Create API Button" class="twilio-setup-pic">
                        <img src="<?php echo esc_url( $create_new_api_key_pic ); ?>" alt="Create New API Key" class="twilio-setup-pic">
                        <img src="<?php echo esc_url( $api_key_credentials_pic ); ?>" alt="API Key Credentials" class="twilio-setup-pic">
                    </div>
                    <form action="" method="post" class="twilio-setup-form">
                        <input type="hidden" name="twilio-setup-pt-two-nonce" value="<?php echo esc_attr( $nonce ); ?>">
                        <label for="api_key_sid" class="twilio-setup-label">API Key Sid</label>
                        <input id="api_key_sid" type="password" name="api_key_sid" value="<?php echo esc_attr( $api_key_sid ); ?>" required class="twilio-setup-input">
                        <label for="api_key_secret" class="twilio-setup-label">API Key Secret</label>
                        <input id="api_key_secret" type="password" name="api_key_secret" value="<?php echo esc_attr( $api_key_secret ); ?>" required class="twilio-setup-input">
                        <button type="submit" class="twilio-setup-button button" name="twilio-setup-step-two" value="save">Save</button>
                    </form>
                    <a href="<?php echo esc_url( $this->settings_url ); ?>&step=1" class="button">Back</a>
                    <a href="<?php echo esc_url( $this->settings_url ); ?>&step=3" class="button">Next</a>
                </div>
            </div>
        <?php
    }

	/**
	 * Renders the third step of the Twilio setup process in the plugin settings.
	 *
	 * This step allows the user to navigate to the Twilio console, create a TwiML App,
	 * and input its SID into the field provided. The submitted SID is sanitized, validated,
	 * and encrypted before being saved to the database.
	 * Additionally, navigation links for other setup steps and instructional visuals are included.
	 *
	 * @return void
	 * @throws RandomException Can theoretically throw an exception if source of randomness is not found while encrypting the credentials.
     */
	private function render_step_three(): void {
		$nonce = wp_create_nonce( 'twilio_phone_setup_part_three' );

		$create_twimil_app_button_pic = plugins_url( '/includes/images/create-twiml-app-button.png', __FILE__ );
        $create_new_twiml_app_pic     = plugins_url( '/includes/images/create-twiml-app.png', __FILE__ );
        $twiml_app_sid_pic            = plugins_url( '/includes/images/twiml-app-sid.png', __FILE__ );

		if ( isset( $_POST['twilio-setup-step-three'] ) && 'save' === $_POST['twilio-setup-step-three'] && isset( $_POST['twilio-setup-pt-three-nonce'] ) &&
			wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['twilio-setup-pt-three-nonce'] ) ), 'twilio_phone_setup_part_three' ) &&
			! empty( $_POST['app-SID'] ) ) {
			$app_sid = sanitize_text_field( wp_unslash( $_POST['app-SID'] ) );

			if ( ! $this::decrypt( $app_sid ) ) {
				$app_sid      = $this::encrypt( $app_sid );
				$connect_info = get_option( 'twilio_connect_info' );
				if ( ! is_array( $connect_info ) ) {
					$connect_info = [];
				}
				$connect_info['app_sid'] = $app_sid;
				update_option( 'twilio_connect_info', $connect_info );
			}
		}
		$connect_info = get_option( 'twilio_connect_info' );
		$app_sid      = $connect_info['app_sid'] ?? '';

        ?>
            <div class="wrap fs-section fs-full-size-wrapper">
                <h2 class="nav-tab-wrapper" style="display: none;">
                    <a href="<?php echo esc_url( $this->settings_url ); ?>" class='nav-tab fs-tab nav-tab-active home'>Settings</a>
                    <a href="<?php echo esc_url( $this->settings_url ); ?>&tab=phone" class='nav-tab fs-tab'>Twilio Phone</a>
                </h2>
                <div class="twilio-setup-section-content">
                    <h1>Enter App SID</h1>
                    <nav class="nav-bar">
                        <a href="<?php echo esc_url( $this->settings_url ); ?>&step=1">Step 1-Get Account SID</a> |
                        <a href="<?php echo esc_url( $this->settings_url ); ?>&step=2">Step 2-Enter API Info</a> |
                        <a href="<?php echo esc_url( $this->settings_url ); ?>&step=3" class="active-link">Step 3-Enter App SID</a> |
                        <a href="<?php echo esc_url( $this->settings_url ); ?>&step=4">Step 4-Enter Phone Number</a>
                    </nav>
                    <p class="twilio-setup-instructions">
                        Navigate to <a target="_blank" href="https://www.twilio.com/console/voice/twiml/apps">Twilio account Console > Voice > TwiML > TwiML Apps</a>.
                        Click on the “Create new TwiML App” button. Enter a name for the friendly name field (such as "Twilio WordPress plugin").
                        Copy the following link into the Voice Configuration Request URL. <!--TODO--> Leave the other fields empty for now.
                        Click the “Create” button to create the TwiML application. You will be redirected back to the TwiML Apps dashboard.
                        Click on the TwiML App you just created. On the page for this app, select the SID value and copy it into the field below.
                    </p>

                    <div class="twilio-setup-images">
                        <img src="<?php echo esc_url( $create_twimil_app_button_pic ); ?>" alt="Create Twiml App Button" class="twilio-setup-pic">
                        <img src="<?php echo esc_url( $create_new_twiml_app_pic ); ?>" alt="Create New Twiml App" class="twilio-setup-pic">
                        <img src="<?php echo esc_url( $twiml_app_sid_pic ); ?>" alt="Twiml App SID" class="twilio-setup-pic">
                    </div>

                    <form action="" method="post" class="twilio-setup-form">
                        <input type="hidden" name="twilio-setup-pt-three-nonce" value="<?php echo esc_attr( $nonce ); ?>">
                        <label for="app_sid" class="twilio-setup-label">App SID</label>
                        <input id="app_sid" type="password" name="app-SID" value="<?php echo esc_attr( $app_sid ); ?>" required class="twilio-setup-input">
                        <button type="submit" class="twilio-setup-button button" name="twilio-setup-step-three" value="save">Save</button>
                    </form>

                    <a href="<?php echo esc_url( $this->settings_url ); ?>&step=2" class="button">Back</a>
                    <a href="<?php echo esc_url( $this->settings_url ); ?>&step=4" class="button">Next</a>
                </div>
            </div>
        <?php
	}

	/**
	 * Renders the fourth step of the Twilio phone number setup process.
	 *
	 * This step allows users to input their Twilio phone number in E.164 format
	 * and saves it to the Twilio connection settings if the form is correctly submitted
	 * and validated through a nonce.
	 *
	 * @return void
	 */
	private function render_step_four(): void {
        $nonce = wp_create_nonce( 'twilio_phone_setup_part_four' );

        if ( isset( $_POST['twilio-setup-step-four'] ) && 'save' === $_POST['twilio-setup-step-four'] && isset( $_POST['twilio-setup-pt-four-nonce'] ) &&
            wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['twilio-setup-pt-four-nonce'] ) ), 'twilio_phone_setup_part_four' ) &&
            ! empty( $_POST['phone-number'] ) ) {
            $phone_number = sanitize_text_field( wp_unslash( $_POST['phone-number'] ) );

	        $connect_info = get_option( 'twilio_connect_info' );
	        if ( ! is_array( $connect_info ) ) {
		        $connect_info = [];
	        }
	        $connect_info['phone_number'] = $phone_number;
	        update_option( 'twilio_connect_info', $connect_info );
		}

        $connect_info = get_option( 'twilio_connect_info' );
        $phone_number = $connect_info['phone_number'] ?? '';
        ?>
            <div class="wrap fs-section fs-full-size-wrapper">
                <h2 class="nav-tab-wrapper" style="display: none;">
                    <a href="<?php echo esc_url( $this->settings_url ); ?>" class='nav-tab fs-tab nav-tab-active home'>Settings</a>
                    <a href="<?php echo esc_url( $this->settings_url ); ?>&tab=phone" class='nav-tab fs-tab'>Twilio Phone</a>
                </h2>
                <div class="twilio-setup-section-content">
                    <h1>Enter Twilio Phone Number</h1>
                    <nav class="nav-bar">
                        <a href="<?php echo esc_url( $this->settings_url ); ?>&step=1">Step 1-Get Account SID</a> |
                        <a href="<?php echo esc_url( $this->settings_url ); ?>&step=2">Step 2-Enter API Info</a> |
                        <a href="<?php echo esc_url( $this->settings_url ); ?>&step=3">Step 3-Enter App SID</a> |
                        <a href="<?php echo esc_url( $this->settings_url ); ?>&step=4" class="active-link">Step 4-Enter Phone Number</a>
                    </nav>
                    <p class="twilio-setup-instructions">
                        Go to your <a target="_blank" href="https://www.twilio.com/console/phone-numbers/incoming">Twilio account console > Phone Numbers > Manage Numbers > Active Numbers</a>.
                        Select the number you want to use for this plugin. Copy the phone number and paste it into the field below removing spaces but leaving the + sign,
                        ensuring the number is in <a target="_blank" href="https://www.twilio.com/docs/glossary/what-e164">E.164</a> format. <!--TODO configure #-->
                    </p>
                    <div class="twilio-setup-images">

                    </div>
                    <form action="" method="post" class="twilio-setup-form">
                        <input type="hidden" name="twilio-setup-pt-four-nonce" value="<?php echo esc_attr( $nonce ); ?>">
                        <label for="twilio_phone_number" class="twilio-setup-label">Twilio Phone Number</label>
                        <input id="twilio_phone_number" type="tel" pattern="^\+[1-9]\d{1,14}$" name="phone-number" value="<?php echo esc_attr( $phone_number ); ?>" placeholder="+1234567890" required class="twilio-setup-input">
                        <button type="submit" class="twilio-setup-button button" name="twilio-setup-step-four" value="save">Save</button>
                    </form>
                    <a href="<?php echo esc_url( $this->settings_url ); ?>&step=3" class="button">Back</a>
                </div>
            </div>
        <?php
	}

	/**
	 * Renders the Twilio Phone tab content in the plugin's settings page.
	 *
	 * @return void
	 */
	private function render_phone_tab(): void {
        ?>

        <div class="wrap fs-section fs-full-size-wrapper">
            <h2 class="nav-tab-wrapper" style="display: none;">
                <a href="<?php echo esc_url( $this->settings_url ); ?>" class='nav-tab fs-tab home'>Settings</a>
                <a href="<?php echo esc_url( $this->settings_url ); ?>&tab=phone" class='nav-tab nav-tab-active fs-tab'>Twilio Phone</a>
            </h2>
            <div class="twilio-phone-dialer">
                <!-- Text field on top of the dial pad -->
                <label for="number-to-dial"></label>
                <input type="text" id="number-to-dial" readonly/>

                <!-- Dial Pad -->
                <div class="dial-pad">
			        <?php
			        $buttons = [
				        [ '1', '2', '3' ],
				        [ '4', '5', '6' ],
				        [ '7', '8', '9' ],
				        [ '*', '0', '#' ],
				        [ '&#128222;', '+', '&#x21A9;' ],
			        ];
			        foreach ( $buttons as $row ) :
				        ?>
                        <div class="dial-pad-row">
					        <?php foreach ( $row as $button ) : ?>
                                <button class="dial-button"><?php echo esc_html( $button ); ?></button>
					        <?php endforeach; ?>
                        </div>
			        <?php endforeach; ?>
                </div>
            </div>
        </div>
        <?php
	}
}
