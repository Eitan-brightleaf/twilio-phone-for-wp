<?php

/**
 * Define the internationalization functionality
 *
 * Loads and defines the internationalization files for this plugin
 * so that it is ready for translation.
 *
 * @link       https://digital.brightleaf.info
 * @since      1.0.0
 *
 * @package    Twilio_phone_for_wp
 * @subpackage Twilio_phone_for_wp/includes
 */

/**
 * Define the internationalization functionality.
 *
 * Loads and defines the internationalization files for this plugin
 * so that it is ready for translation.
 *
 * @since      1.0.0
 * @package    Twilio_phone_for_wp
 * @subpackage Twilio_phone_for_wp/includes
 * @author     Brightleaf Digital <eitan@brightleafc.com>
 */
class Twilio_phone_for_wp_i18n {


	/**
	 * Load the plugin text domain for translation.
	 *
	 * @since    1.0.0
	 */
	public function load_plugin_textdomain() {

		load_plugin_textdomain(
			'twilio_phone_for_wp',
			false,
			dirname( dirname( plugin_basename( __FILE__ ) ) ) . '/languages/'
		);

	}



}
