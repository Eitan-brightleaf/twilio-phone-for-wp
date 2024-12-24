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

define( 'TWILIO_PHONE_FOR_WP_VERSION', '1.0.0' );


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
function run_twilio_phone_for_wp(): void
{

	$plugin = new Twilio_phone_for_wp();
	$plugin->run();

}
run_twilio_phone_for_wp();
