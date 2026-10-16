package io.droidsentinel.capture

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.widget.Button
import android.widget.TextView
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Standalone launcher entry point. Lets a human run DSCapture directly on
 * the device -- Start/Stop buttons, no adb needed -- separate from
 * ConsentActivity, which stays in place for DroidSentinel to trigger
 * programmatically over adb later.
 */
class MainActivity : Activity() {

    companion object {
        const val SAVE_DIR = "/storage/emulated/0/dscapture"
        private const val REQ_VPN = 1
        private const val REQ_ALL_FILES = 2
    }

    private lateinit var statusText: TextView
    private lateinit var pathText: TextView
    private lateinit var grantStorageButton: Button
    private lateinit var startButton: Button
    private lateinit var stopButton: Button

    private val handler = Handler(Looper.getMainLooper())
    private var polling = false
    private var currentFilename: String = "capture.pcap"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusText = findViewById(R.id.statusText)
        pathText = findViewById(R.id.pathText)
        grantStorageButton = findViewById(R.id.grantStorageButton)
        startButton = findViewById(R.id.startButton)
        stopButton = findViewById(R.id.stopButton)

        grantStorageButton.setOnClickListener { requestAllFilesAccess() }
        startButton.setOnClickListener { beginCapture() }
        stopButton.setOnClickListener { endCapture() }

        pathText.text = SAVE_DIR
    }

    override fun onResume() {
        super.onResume()
        refreshUiState()
    }

    private fun hasAllFilesAccess(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Environment.isExternalStorageManager()
        } else {
            true // pre-Android 11: handled via the WRITE_EXTERNAL_STORAGE manifest permission
        }
    }

    private fun requestAllFilesAccess() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION).apply {
                data = Uri.parse("package:$packageName")
            }
            startActivityForResult(intent, REQ_ALL_FILES)
        }
    }

    private fun refreshUiState() {
        val granted = hasAllFilesAccess()
        grantStorageButton.visibility = if (granted) android.view.View.GONE else android.view.View.VISIBLE
        startButton.isEnabled = granted
        statusText.text = if (!granted) getString(R.string.status_need_storage) else getString(R.string.status_idle)
    }

    private fun beginCapture() {
        if (!hasAllFilesAccess()) {
            requestAllFilesAccess()
            return
        }
        File(SAVE_DIR).mkdirs()
        val stamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        currentFilename = "capture_$stamp.pcap"

        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            @Suppress("DEPRECATION")
            startActivityForResult(prepareIntent, REQ_VPN)
        } else {
            launchCaptureService()
        }
    }

    @Suppress("DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        when (requestCode) {
            REQ_VPN -> {
                if (resultCode == RESULT_OK) {
                    launchCaptureService()
                } else {
                    statusText.text = getString(R.string.status_need_vpn)
                }
            }
            REQ_ALL_FILES -> refreshUiState()
        }
    }

    private fun launchCaptureService() {
        val svc = Intent(this, CaptureVpnService::class.java).apply {
            action = CaptureVpnService.ACTION_START
            putExtra(CaptureVpnService.EXTRA_SCOPE_PKG, "")
            putExtra(CaptureVpnService.EXTRA_FILENAME, currentFilename)
            putExtra(CaptureVpnService.EXTRA_SAVE_DIR, SAVE_DIR)
        }
        startForegroundService(svc)
        startButton.isEnabled = false
        stopButton.isEnabled = true
        statusText.text = getString(R.string.status_running)
        startPolling()
    }

    private fun endCapture() {
        val svc = Intent(this, CaptureVpnService::class.java).apply {
            action = CaptureVpnService.ACTION_STOP
        }
        startService(svc)
        stopButton.isEnabled = false
        startButton.isEnabled = true
        stopPolling()
        handler.postDelayed({ showFinalStatus() }, 600)
    }

    private fun startPolling() {
        polling = true
        handler.post(pollRunnable)
    }

    private fun stopPolling() {
        polling = false
        handler.removeCallbacks(pollRunnable)
    }

    private val pollRunnable = object : Runnable {
        override fun run() {
            if (!polling) return
            val status = readStatus()
            if (status != null) {
                val packets = status.optInt("packet_count", 0)
                val bytes = status.optLong("byte_count", 0)
                statusText.text = "${getString(R.string.status_running)}\n$packets packets, ${bytes / 1024} KB"
            }
            handler.postDelayed(this, 1500)
        }
    }

    private fun showFinalStatus() {
        val status = readStatus()
        val packets = status?.optInt("packet_count", 0) ?: 0
        val path = status?.optString("pcap_path", "") ?: ""
        statusText.text = "Saved $packets packets\n$path"
    }

    private fun readStatus(): JSONObject? {
        return try {
            val f = File(SAVE_DIR, "status.json")
            if (!f.exists()) return null
            JSONObject(f.readText())
        } catch (e: Exception) {
            null
        }
    }

    override fun onDestroy() {
        stopPolling()
        super.onDestroy()
    }
}
