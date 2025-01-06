jQuery(
    ($) => {
        let device;
        $.post(
            {
                url: dialpadAjax.ajax_url,
                data: {
                    action: 'get_token',
                    security: dialpadAjax.security,
                }
            }
        ).then(
            function ( response ) {
                console.dir( response ); // todo remove
                device = new Twilio.Device(
                    response.data.token,
                    {
						codecPreferences: ["opus", "pcmu"], // Preferred codecs
						allowIncomingWhileBusy : true,
						closeProtection: true,
						enableImprovedSignalingErrorPrecision: true,
                    }
                );

                // Register the device
                device.register();
                device.on(
                    'tokenWillExpire',
                    () => {
						const token = $.post(
                            {
                                url: dialpadAjax.ajax_url,
                                data: {
                                    action: 'get_token',
                                    security: dialpadAjax.security,
                                }
                            }
                        );
						device.updateToken( token );
                    }
                );
            }
        ).catch(
            function ( error ) {
                console.dir( error ); // todo improve
            }
        );
	function make_outgoing_call( number ) {
		const params = {
			To: number,
		};
		device.connect( { params: params } ); // todo improve
	}
        const $dial_field = $( '#number-to-dial' );
        const buttons     = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '*', '#', '+'];
        $( '.dial-button' ).on(
            'click',
            function () {
                const clickedValue = $( this ).text().trim();
                if ( buttons.includes( clickedValue ) ) {
                    $dial_field.val(
							function ( i, text ) {
								return text + clickedValue;
							}
                    );
                } else if ( '↩' === clickedValue ) {
                    $dial_field.val(
                        function ( i, text ) {
                            return text.slice( 0, -1 );
                        }
                    );
                } else if ( '📞' === clickedValue ) {
                    make_outgoing_call( $dial_field.val() );
                }
			}
        );
    }
);