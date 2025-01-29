<?php

/**
 * The plugin bootstrap file
 *
 * This file is read by WordPress to generate the plugin information in the plugin
 * admin area. This file also includes all of the dependencies used by the plugin,
 * registers the activation and deactivation functions, and defines a function
 * that starts the plugin.
 *
 * @link              https://digital.brightleaf.info
 * @since             1.0.0
 * @package           Twilio_phone_for_wp
 *
 * @wordpress-plugin
 * Plugin Name:       Twilio Phone for WordPress
 * Plugin URI:        https://digital.brightleaf.info
 * Description:       This is a description of the plugin.
 * Version:           1.0.0
 * Author:            Brightleaf Digital
 * Author URI:        https://digital.brightleaf.info/
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 */

// If this file is called directly, abort.
if ( ! defined( 'ABSPATH' ) ) {
	die;
}

if ( ! function_exists( 'tpfwp_fs' ) ) {
	// Create a helper function for easy SDK access.
	function tpfwp_fs() {
		global $tpfwp_fs;

		if ( ! isset( $tpfwp_fs ) ) {
			// Include Freemius SDK.
			require_once __DIR__ . '/freemius/start.php';

			$tpfwp_fs = fs_dynamic_init(
                array(
					'id'             => '17524',
					'slug'           => 'twilio-phone-for-wordpress',
					'type'           => 'plugin',
					'public_key'     => 'pk_23038fb325090576301698980d99d',
					'is_premium'     => false,
					'has_addons'     => false,
					'has_paid_plans' => false,
					'menu'           => array(
						'slug'   => 'twilio-phone-for-wp',
						'parent' => array(
							'slug' => 'gravity_ops',
						),
					),
					'navigation'     => 'tabs',
				)
                );
		}

		return $tpfwp_fs;
	}

	// Init Freemius.
	tpfwp_fs();
	// Signal that SDK was initiated.
	do_action( 'tpfwp_fs_loaded' );
}

define( 'TWILIO_PHONE_FOR_WP_VERSION', '1.0.0' );
define( 'TWILIO_PHONE_FOR_WP_BASENAME', plugin_basename( __FILE__ ) );


/**
 * The core plugin class.
 */
require plugin_dir_path( __FILE__ ) . '/class-twilio-phone-for-wp.php';

/**
 * Begins execution of the plugin.
 *
 * Since everything within the plugin is registered via hooks,
 * then kicking off the plugin from this point in the file does
 * not affect the page life cycle.
 *
 * @since    1.0.0
 */
function run_twilio_phone_for_wp(): void {

	$plugin = new Twilio_Phone_For_WP();
	$plugin->run();
}
run_twilio_phone_for_wp();
