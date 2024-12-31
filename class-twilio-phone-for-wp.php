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
	 */
	public function create_sub_menu(): void {

		?>

        <form action="" method="post" class="twilio-phone-for-wp-form">
            <input type="password" name="account_sid" placeholder="Account SID" required>
            <input type="password" name="api_key_sid" placeholder="API Key SID" required>
            <input type="password" name="api_key_secret" placeholder="API Key Secret" required>
            <input type="password" name="app_sid" placeholder="App SID" required>
            <input type="text" name="phone_number" placeholder="Phone Number" required>
            <input type="submit" value="Save">
        </form>

		<?php
	}
}
