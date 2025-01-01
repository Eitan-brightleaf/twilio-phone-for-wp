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

use Random\RandomException;

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
	}

	/**
	 * Enqueues styles for the plugin's admin page by registering and conditionally loading the plugin page CSS.
	 * The style is registered with a version based on the file's last modification time for cache busting.
	 * The style is enqueued only if the current admin page matches the plugin's slug.
	 *
	 * @return void
	 */
	public function enqueue_scripts(): void {
        $plugin_pg_url     = plugins_url( 'css/plugin-page.css', __FILE__ );
        $plugin_pg_path    = plugin_dir_path( __FILE__ ) . 'css/plugin-page.css';
        $plugin_pg_version = filemtime( $plugin_pg_path );
	    wp_register_style( $this->prefix . '_plugin_page', $plugin_pg_url, [], $plugin_pg_version );
        if ( isset( $_GET['page'] ) && sanitize_key( $_GET['page'] ) === $this->slug ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            wp_enqueue_style( $this->prefix . '_plugin_page' );
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

        if ( isset( $_GET['step'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $step = sanitize_key( $_GET['step'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        } else {
            $step = '1'; // $this->determine_step();
        }
        match ( $step ) {
            '1' => $this->render_step_one(),
            '2' => $this->render_step_two(),
            '3' => $this->render_step_three(),
            '4' => $this->render_step_four(),
        };

		?>

        <!-- <form action="" method="post" class="twilio-phone-for-wp-form">
            <a target="_blank" href="https://www.twilio.com/console/voice/twiml/apps">Twilio account Console > Voice > TwiML > TwiML Apps</a>
            <input type="password" name="app_sid" placeholder="App SID" required>
            <input type="text" name="phone_number" placeholder="Phone Number" required>
            <input type="submit" value="Save">
        </form>-->

		<?php
	}

    /**
     * Renders the interface for Step One of the setup process, guiding the user to retrieve
     * and input their Twilio Account SID.
     *
     * @return void
     * @throws RandomException Could theoretically throw an exception if no source of randomness is found.
     */
    private function render_step_one(): void {
        $settings_url    = $this->settings_url;
        $account_sid_pic = plugins_url( '/images/account-sid.png', __FILE__ );
        $nonce           = wp_create_nonce( 'twilio_phone_setup_part_one' );

        if ( isset( $_POST['twilio-setup-step-one'] ) && 'save' === $_POST['twilio-setup-step-one'] && isset( $_POST['twilio-setup-pt-one-nonce'] ) &&
            wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['twilio-setup-pt-one-nonce'] ) ), 'twilio_phone_setup_part_one' ) &&
            ! empty( $_POST['account_sid'] ) ) {

            $sid = sanitize_text_field( wp_unslash( $_POST['account_sid'] ) );

            if ( ! $this::decrypt( $sid ) ) {
                $sid          = $this::encrypt( $sid );
                $connect_info = get_option( 'twilio_connect_info' );
                if ( ! is_array( $connect_info ) ) {
                    $connect_info = [];
                }
                $connect_info['sid'] = $sid;
                update_option( 'twilio_connect_info', $connect_info );
            }
        }
        $connect_info = get_option( 'twilio_connect_info' );
        $sid          = $connect_info['sid'] ?? '';
        ?>
        <h1>Twilio Account SID</h1>
        <nav class="nav-bar">
            <a href="<?php echo esc_url( $settings_url ); ?>&step=1" class="active-link">Step 1-Get Account SID</a> |
            <a href="<?php echo esc_url( $settings_url ); ?>&step=2">Step 2-Enter API Info</a>
        </nav>
        <p class="twilio-setup-instructions">
            Go to the <a target="_blank" href="https://www.twilio.com/console">Twilio Console Home Page</a> and copy your Account SID here.
            You can find it on the bottom of the page in the "Account Info" section.
        </p>
        <img src="<?php echo esc_url( $account_sid_pic ); ?>" alt="Twilio Account SID" class="twilio-setup-pic">
        <form action="" method="post" class="twilio-setup-form">
            <input type="hidden" name="twilio-setup-pt-one-nonce" value="<?php echo esc_attr( $nonce ); ?>">
            <input type="password" name="account_sid" placeholder="Account SID" value="<?php echo esc_attr( $sid ); ?>" required class="twilio-setup-input">
            <button type="submit" class="twilio-setup-button button" name="twilio-setup-step-one" value="save">Save</button>
        </form>
        <a href="<?php echo esc_url( $settings_url ); ?>&step=2" class="button">Next</a>
        <?php
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
     * @throws RandomException
     */
    private function render_step_two() {
        $settings_url = $this->settings_url;
        $nonce        = wp_create_nonce( 'twilio_phone_setup_part_two' );

        $create_api_button_pic   = plugins_url( '/images/create-api-key-button.png', __FILE__ );
        $create_new_api_key_pic  = plugins_url( '/images/create-new-api-key.png', __FILE__ );
        $api_key_credentials_pic = plugins_url( '/images/api-key-credentials.png', __FILE__ );

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
        <h1>Enter API Info</h1>
        <nav class="nav-bar">
            <a href="<?php echo esc_url( $settings_url ); ?>&step=1">Step 1-Get Account SID</a> |
            <a href="<?php echo esc_url( $settings_url ); ?>&step=2" class="active-link">Step 2-Enter API Info</a>
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
            <input type="password" name="api_key_sid" value="<?php echo esc_attr( $api_key_sid ); ?>" placeholder="API Key SID" required class="twilio-setup-input">
            <input type="password" name="api_key_secret" value="<?php echo esc_attr( $api_key_secret ); ?>" placeholder="API Key Secret" required class="twilio-setup-input">
            <button type="submit" class="twilio-setup-button button" name="twilio-setup-step-two" value="save">Save</button>
        </form>
        <a href="<?php echo esc_url( $settings_url ); ?>&step=1" class="button">Back</a>
        <a href="<?php echo esc_url( $settings_url ); ?>&step=3" class="button">Next</a>
        <?php
    }
}
