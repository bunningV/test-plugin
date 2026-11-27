/*
 * Draws the authenticator QR code in the browser from the otpauth:// URI in data-caltech-qr.
 * The secret never leaves the page: no QR image service is involved.
 * Depends on assets/qrcode.js (qrcode-generator, MIT).
 */
(function () {
    'use strict';

    function render() {
        if (typeof window.qrcode !== 'function') {
            return;
        }

        var targets = document.querySelectorAll('[data-caltech-qr]');
        for (var i = 0; i < targets.length; i++) {
            var el = targets[i];
            try {
                var qr = window.qrcode(0, 'M');
                qr.addData(el.getAttribute('data-caltech-qr'));
                qr.make();
                el.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 2, scalable: true });
            } catch (e) {
                // The manual key printed next to the code still works.
            }
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', render);
    } else {
        render();
    }
})();
