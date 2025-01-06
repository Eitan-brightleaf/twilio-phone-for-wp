<?php

use BrightleafDigital\TwilioPhoneForWordPress\Twilio\Exceptions\ConfigurationException;
use BrightleafDigital\TwilioPhoneForWordPress\Twilio\Exceptions\TwilioException;
use BrightleafDigital\TwilioPhoneForWordPress\Twilio\Rest\Client;

if ( ! defined( 'ABSPATH' ) ) {
	die;
}

require './vendor/autoload.php';

$connect_info = get_option( 'twilio_connect_info' );

if ( ! is_array( $connect_info ) ) {
	return;
}

$sid            = $connect_info['account_sid'] ?? null;
$api_key_sid    = $connect_info['api_key_sid'] ?? null;
$api_key_secret = $connect_info['api_key_secret'] ?? null;
$app_sid        = $connect_info['app_sid'] ?? null;
$phone_number   = $connect_info['phone_number'] ?? null;

if ( ! isset( $sid, $api_key_sid, $api_key_secret, $app_sid, $phone_number ) ) {
	return;
}

try {
	$client = new Client( $api_key_sid, $api_key_secret, $sid );
	$call   = $client->calls->create(
		'+972534143424',
		$phone_number,
		[
			'url' => 'https://demo.twilio.com/docs/voice.xml',
		]
	);
} catch ( TwilioException | ConfigurationException $e ) {
	echo "<script>alert('Error: " . esc_js( $e->getMessage() ) . "');</script>";
}
