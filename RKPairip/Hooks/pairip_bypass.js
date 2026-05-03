'use strict';

/*
 * RKPairip — Pairip / Google Play Integrity bypass for frida-gadget.
 *
 * Loaded by libfrida-gadget.so during the application's first class
 * <clinit> (the manifest's `android:appComponentFactory` class). At that
 * point ALL pairip startup code — including VMRunner.invoke and
 * SignatureCheck.verifyIntegrity — has not run yet.
 *
 * Strategy: pairip derives its bytecode-decryption key from the runtime
 * APK signature. Re-signing the APK breaks the key and every method
 * lookup ("DYMBfaYRS8a1t42Z not found"). Instead of trying to patch the
 * native code, we make every Java API that returns the signature lie:
 * we hand back the *original* developer cert DER bytes. Pairip computes
 * the same key the .so was built against, decrypts cleanly, and runs.
 *
 * RKPairip rewrites __ORIGINAL_CERT_B64__ at patch time with the cert
 * extracted from the APK's V2/V3 signing block.
 */

(function () {
    var TAG = '[RKPairip]';
    var ORIGINAL_CERT_B64 = '__ORIGINAL_CERT_B64__';

    var ok = [], fail = [];
    function hook(name, fn) {
        try { fn(); ok.push(name); }
        catch (e) { fail.push(name + ' :: ' + e.message); }
    }

    Java.perform(function () {

        // ----- Decode the baked-in cert and build a Spoofed Signature -----
        var Base64    = Java.use('android.util.Base64');
        var Signature = Java.use('android.content.pm.Signature');
        var origDer   = Base64.decode(ORIGINAL_CERT_B64, 0);   // 0 = DEFAULT
        var Spoofed   = Signature.$new(origDer);

        // ----- Spoof every signature-lookup path we know about -----
        hook('ApplicationPackageManager.getPackageInfo', function () {
            var APM = Java.use('android.app.ApplicationPackageManager');
            APM.getPackageInfo.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var pi = ov.apply(this, arguments);
                    try {
                        if (pi.signatures && pi.signatures.value) {
                            pi.signatures.value = [Spoofed];
                        }
                    } catch (_) {}
                    try {
                        if (pi.signingInfo && pi.signingInfo.value) {
                            // SigningInfo is opaque — its getApkContentsSigners
                            // override below covers reads through it.
                        }
                    } catch (_) {}
                    return pi;
                };
            });
        });

        hook('SigningInfo.getApkContentsSigners', function () {
            var SI = Java.use('android.content.pm.SigningInfo');
            SI.getApkContentsSigners.implementation = function () {
                return Java.array('android.content.pm.Signature', [Spoofed]);
            };
            try {
                SI.getSigningCertificateHistory.implementation = function () {
                    return Java.array('android.content.pm.Signature', [Spoofed]);
                };
            } catch (_) {}
            try {
                SI.hasMultipleSigners.implementation = function () { return false; };
            } catch (_) {}
        });

        // ----- Last-resort fallback: any Signature.toByteArray() returns the
        // original DER. Pairip, SafetyNet shims, and most app-side checks
        // funnel through this one method. -----
        hook('Signature.toByteArray', function () {
            Signature.toByteArray.implementation = function () {
                return origDer;
            };
        });

        // ----- Defensive: explicit pairip class hooks. Even with signature
        // spoofing in place, neutering these shaves attack surface and is
        // free if the classes don't exist. -----
        hook('com.pairip.SignatureCheck.verifyIntegrity', function () {
            var c = Java.use('com.pairip.SignatureCheck');
            c.verifyIntegrity.overloads.forEach(function (ov) {
                ov.implementation = function () { return; };
            });
        });
        hook('com.pairip.SignatureCheck.verifySignatureMatches', function () {
            var c = Java.use('com.pairip.SignatureCheck');
            c.verifySignatureMatches.overloads.forEach(function (ov) {
                ov.implementation = function () { return true; };
            });
        });
        hook('com.pairip.licensecheck3.LicenseClientV3.allowAccess', function () {
            var c = Java.use('com.pairip.licensecheck3.LicenseClientV3');
            c.allowAccess.overloads.forEach(function (ov) { ov.implementation = function () {}; });
        });
        hook('com.pairip.licensecheck3.LicenseClientV3.onError', function () {
            var c = Java.use('com.pairip.licensecheck3.LicenseClientV3');
            c.onError.overloads.forEach(function (ov) { ov.implementation = function () {}; });
        });
        hook('com.pairip.licensecheck3.LicenseClientV3.processResponse', function () {
            var c = Java.use('com.pairip.licensecheck3.LicenseClientV3');
            c.processResponse.overloads.forEach(function (ov) { ov.implementation = function () {}; });
        });
        hook('com.pairip.licensecheck.LicenseClient.allowAccess', function () {
            var c = Java.use('com.pairip.licensecheck.LicenseClient');
            c.allowAccess.overloads.forEach(function (ov) { ov.implementation = function () {}; });
        });

        console.log(TAG + ' installed ' + ok.length + ' hooks (' + fail.length + ' missing)');
        ok.forEach(function (n)   { console.log(TAG + '   ✓ ' + n); });
        fail.forEach(function (n) { console.log(TAG + '   · ' + n); });
    });
})();
