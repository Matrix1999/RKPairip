'use strict';

/*
 * RKPairip — Frida-gadget bypass script for Pairip / Google Play Integrity
 *
 * Loaded by libfrida-gadget.so at app startup, BEFORE pairip's Application
 * attachBaseContext runs. Java.perform completes synchronously while
 * System.loadLibrary("frida-gadget") is still on the stack, so all hooks
 * are installed before pairip can call verifyIntegrity / license checks.
 *
 * Strategy: keep libpairipcore alive (so VMRunner can populate the
 * static Method fields user code reflects through), only neutralize the
 * security gates.
 */

(function () {
    var TAG = '[RKPairip-bypass]';
    var ok = [];
    var fail = [];

    function hook(name, fn) {
        try { fn(); ok.push(name); }
        catch (e) { fail.push(name + ' :: ' + e.message); }
    }

    Java.perform(function () {

        // -------- Core signature / integrity check --------
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

        // -------- License check (V3) --------
        hook('com.pairip.licensecheck3.LicenseClientV3.allowAccess', function () {
            var c = Java.use('com.pairip.licensecheck3.LicenseClientV3');
            c.allowAccess.overloads.forEach(function (ov) { ov.implementation = function () { return; }; });
        });
        hook('com.pairip.licensecheck3.LicenseClientV3.onError', function () {
            var c = Java.use('com.pairip.licensecheck3.LicenseClientV3');
            c.onError.overloads.forEach(function (ov) { ov.implementation = function () { return; }; });
        });
        hook('com.pairip.licensecheck3.LicenseClientV3.processResponse', function () {
            var c = Java.use('com.pairip.licensecheck3.LicenseClientV3');
            c.processResponse.overloads.forEach(function (ov) { ov.implementation = function () { return; }; });
        });

        // -------- License activity (the popup that finishes the app) --------
        hook('com.pairip.licensecheck3.LicenseActivity', function () {
            var c = Java.use('com.pairip.licensecheck3.LicenseActivity');
            c.onCreate.overloads.forEach(function (ov) {
                ov.implementation = function (b) { this.finish(); };
            });
        });

        // -------- Older license check namespace --------
        hook('com.pairip.licensecheck.LicenseClient.allowAccess', function () {
            var c = Java.use('com.pairip.licensecheck.LicenseClient');
            c.allowAccess.overloads.forEach(function (ov) { ov.implementation = function () { return; }; });
        });
        hook('com.pairip.licensecheck.LicenseClient.onError', function () {
            var c = Java.use('com.pairip.licensecheck.LicenseClient');
            c.onError.overloads.forEach(function (ov) { ov.implementation = function () { return; }; });
        });
        hook('com.pairip.licensecheck.LicenseActivity', function () {
            var c = Java.use('com.pairip.licensecheck.LicenseActivity');
            c.onCreate.overloads.forEach(function (ov) {
                ov.implementation = function (b) { this.finish(); };
            });
        });

        // -------- App-level signature comparison fallbacks --------
        hook('android.content.pm.Signature.equals', function () {
            var Signature = Java.use('android.content.pm.Signature');
            // leave equals alone — only override if we see false negatives in logs
        });

        console.log(TAG + ' installed ' + ok.length + ' hooks, ' + fail.length + ' missing');
        ok.forEach(function (n) { console.log(TAG + '   ✓ ' + n); });
        fail.forEach(function (n) { console.log(TAG + '   ✗ ' + n); });
    });
})();
