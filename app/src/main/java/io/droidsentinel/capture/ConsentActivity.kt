package io.droidsentinel.capture

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle

/**
 * Entry point DroidSentinel triggers over adb:
 *   Start:
 *     adb shell am start -n io.droidsentinel.capture/.ConsentActivity \
 *         --es scope_pkg <package, or empty for whole device> \
 *         --es filename  <name>.pcap
 *   Stop:
 *     adb shell am start -n io.droidsentinel.capture/.ConsentActivity \
 *         -a io.droidsentinel.capture.STOP_CAPTURE
 *
 * Stop is routed through this Activity rather than hitting
 * CaptureVpnService directly, because the service requires
 * BIND_VPN_SERVICE -- which blocks ANY external caller, adb included,
 * from starting/stopping it ("am start-service ... STOP" fails with a
 * permission error no matter who calls it over adb). An Activity carries
 * no such restriction; once it's running inside the app's own process,
 * its own call to startService() is exempt from that same check, the
 * same reason the Start flow below already works.
 *
 * VpnService.prepare() only returns a non-null Intent -- and the system
 * only shows the "Allow DSCapture to set up a VPN connection?" dialog --
 * the FIRST time (or after the user revokes it from Settings). Android
 * remembers the grant after that, so every later start from DroidSentinel
 * skips straight to starting the capture service, invisibly, the same way
 * ACBridge's own exporter activity already flashes-and-closes in this
 * project.
 */
class ConsentActivity : Activity() {

    companion object {
        const val ACTION_STOP_CAPTURE = "io.droidsentinel.capture.STOP_CAPTURE"
    }

    private var scopePkg: String = ""
    private var filename: String = "capture.pcap"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        if (intent?.action == ACTION_STOP_CAPTURE) {
            stopCaptureAndFinish()
            return
        }

        scopePkg = intent?.getStringExtra("scope_pkg") ?: ""
        filename = intent?.getStringExtra("filename") ?: "capture.pcap"

        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            @Suppress("DEPRECATION")
            startActivityForResult(prepareIntent, 1)
        } else {
            launchCaptureAndFinish()
        }
    }

    @Suppress("DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode == RESULT_OK) {
            launchCaptureAndFinish()
        } else {
            // User tapped "Deny" -- nothing to capture, just close.
            finish()
        }
    }

    private fun launchCaptureAndFinish() {
        val svc = Intent(this, CaptureVpnService::class.java).apply {
            action = CaptureVpnService.ACTION_START
            putExtra(CaptureVpnService.EXTRA_SCOPE_PKG, scopePkg)
            putExtra(CaptureVpnService.EXTRA_FILENAME, filename)
        }
        startForegroundService(svc)
        finish()
    }

    private fun stopCaptureAndFinish() {
        val svc = Intent(this, CaptureVpnService::class.java).apply {
            action = CaptureVpnService.ACTION_STOP
        }
        startService(svc)
        finish()
    }
}
