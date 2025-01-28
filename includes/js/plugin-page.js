jQuery( document ).ready(
    function ( $ ) {
        document.querySelector( 'h2.nav-tab-wrapper' ).style.display = 'block';
        let $copy_button = $( '#copy-url' );

        $copy_button.click(
            () => {
                const webhook_url = $copy_button.attr( 'data-clipboard-text' );
				navigator.clipboard.writeText( webhook_url );
				$( '#copy-url-tooltip' ).text( `Copied ${webhook_url}` );
            }
        );

        $copy_button.on(
            'mouseout',
            () => {
				$( '#copy-url-tooltip' ).text( 'Copy to clipboard' );
            }
        );
    }
);