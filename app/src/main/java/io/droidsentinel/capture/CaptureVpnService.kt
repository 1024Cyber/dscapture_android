package io.droidsentinel.capture

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import org.json.JSONObject
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * VpnService-based packet capture -- no root required.
 *
 * This is NOT a VPN in the "connect to a remote server" sense. It's a
 * local tun interface that DSCapture owns: every packet the device would
 * normally send to the network instead arrives here first. We
 *   1. write a copy of it to a pcap file (this IS the feature), and
 *   2. relay it on to its real destination via our own "protected" socket
 *      (protect() exempts that socket from being routed back into this
 *      same tun, which would otherwise be an infinite loop) so the device
 *      keeps working normally while capture is running.
 *
 * Relay covers TCP and UDP (the overwhelming majority of app traffic,
 * including virtually all beaconing/C2 and DNS). Other protocols (ICMP,
 * etc.) are captured to the pcap but not relayed -- a bounded, deliberate
 * v1 scope rather than a full user-space IP stack.
 *
 * Stopping capture (STOP intent, or the notification's stop action) tears
 * the tun down immediately and the OS restores normal routing on its own
 * -- that's an Android platform guarantee of VpnService, not something
 * this code has to get right to avoid leaving the device off-network.
 */
class CaptureVpnService : VpnService() {

    companion object {
        private const val TAG = "DSCapture"
        const val ACTION_START = "io.droidsentinel.capture.START"
        const val ACTION_STOP = "io.droidsentinel.capture.STOP"
        const val EXTRA_SCOPE_PKG = "scope_pkg"   // empty/absent = whole device
        const val EXTRA_FILENAME = "filename"
        const val EXTRA_SAVE_DIR = "save_dir"  // defaults to /storage/emulated/0/dscapture
        const val DEFAULT_SAVE_DIR = "/storage/emulated/0/dscapture"
        private const val NOTIF_CHANNEL = "dscapture"
        private const val NOTIF_ID = 4571
        private const val IDLE_TIMEOUT_MS = 120_000L // drop relay sessions idle this long
    }

    private var tunFd: ParcelFileDescriptor? = null
    private var pcap: PcapWriter? = null
    private val running = AtomicBoolean(false)
    private var selector: Selector? = null
    private var readerThread: Thread? = null
    private var selectorThread: Thread? = null
    private val udpSessions = ConcurrentHashMap<String, UdpSession>()
    private val tcpSessions = ConcurrentHashMap<String, TcpSession>()
    private var packetsOut: FileOutputStream? = null
    private var statusFile: File? = null
    private var pcapFile: File? = null
    private var startedAt: Long = 0

    // The tun's own synthetic address (must match Builder.addAddress below).
    // Packets are relayed using this address -- it's what the real sockets
    // and the OS expect -- but rewritten to realLocalAddr before they're
    // written to the pcap, so the exported file shows the device's actual
    // IP instead of an address that only exists inside this VpnService.
    private val tunAddr = InetAddress.getByName("10.0.0.2")
    private var realLocalAddr: InetAddress? = null

    /** Device's real local IP (WiFi/mobile), read before the VPN tun goes
     * up -- once establish() runs, the tun itself becomes part of the
     * routing picture, so this has to happen first to see past it. Returns
     * null (never crashes) if nothing suitable is found; callers then just
     * leave the synthetic tun address in the pcap, same as before this
     * feature existed. */
    private fun detectRealLocalAddress(): InetAddress? {
        return try {
            java.util.Collections.list(java.net.NetworkInterface.getNetworkInterfaces())
                .asSequence()
                .filter { it.isUp && !it.isLoopback && !it.name.startsWith("tun") && !it.name.startsWith("ppp") }
                .flatMap { java.util.Collections.list(it.inetAddresses).asSequence() }
                .firstOrNull { it is java.net.Inet4Address && !it.isLoopbackAddress && !it.isLinkLocalAddress }
        } catch (e: Exception) {
            Log.w(TAG, "Could not detect the device's real local IP -- pcap will show the internal capture address instead", e)
            null
        }
    }

    private class UdpSession(val channel: DatagramChannel, val devAddr: InetAddress, val devPort: Int,
                              val dstAddr: InetAddress, val dstPort: Int) {
        var lastActive = System.currentTimeMillis()
    }

    private class TcpSession(val channel: SocketChannel, val devAddr: InetAddress, val devPort: Int,
                              val dstAddr: InetAddress, val dstPort: Int) {
        var ourSeq: Long = 1000
        var deviceNextSeq: Long = 0
        var established = false
        var lastActive = System.currentTimeMillis()
        // The real connect() to the destination can take longer than the
        // local tun round-trip, so the device may send data before our
        // socket finishes connecting. Buffer it instead of writing to a
        // not-yet-connected channel and falsely ACKing data that was never
        // actually sent -- flushed once finishTcpConnect() completes.
        val pendingOut = java.io.ByteArrayOutputStream()
        var pendingAckUpTo: Long = 0
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopCapture()
                stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                val scopePkg = intent?.getStringExtra(EXTRA_SCOPE_PKG) ?: ""
                val filename = intent?.getStringExtra(EXTRA_FILENAME) ?: "capture.pcap"
                val saveDir = intent?.getStringExtra(EXTRA_SAVE_DIR) ?: DEFAULT_SAVE_DIR
                startCapture(scopePkg, filename, saveDir)
            }
        }
        return START_STICKY
    }

    private fun startCapture(scopePkg: String, filename: String, saveDir: String) {
        if (running.get()) return

        // Preferred: the shared, human-browsable location (needs All Files
        // Access on Android 11+, granted from MainActivity). Fall back to
        // the app-private external dir if that write isn't actually usable
        // -- better a capture that lands somewhere than one that crashes.
        var dir = File(saveDir)
        if (!dir.mkdirs() && !dir.isDirectory) {
            Log.w(TAG, "Could not use $saveDir, falling back to app-private storage")
            dir = getExternalFilesDir(null) ?: filesDir
            dir.mkdirs()
        } else if (!dir.canWrite()) {
            Log.w(TAG, "$saveDir not writable (All Files Access not granted?), falling back")
            dir = getExternalFilesDir(null) ?: filesDir
            dir.mkdirs()
        }
        pcapFile = File(dir, filename)
        statusFile = File(dir, "status.json")
        startedAt = System.currentTimeMillis()

        // Must be called unconditionally, immediately, whenever the service
        // was entered via startForegroundService() (which ConsentActivity
        // always uses) -- Android kills the process a few seconds later if
        // startForeground() never happens, including on a failure path.
        startForeground(NOTIF_ID, buildNotification())

        // Read the device's real IP *before* establish() brings the tun up --
        // see detectRealLocalAddress() for why the order matters.
        realLocalAddr = detectRealLocalAddress()
        Log.i(TAG, "pcap will show real device IP: ${realLocalAddr?.hostAddress ?: "unavailable, falling back to $tunAddr"}")

        val builder = Builder()
            .setSession("DSCapture")
            .addAddress("10.0.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("8.8.8.8")
            .addDnsServer("1.1.1.1")
            .setMtu(1500)
            .setBlocking(false)

        if (scopePkg.isNotBlank()) {
            try {
                builder.addAllowedApplication(scopePkg)
            } catch (e: Exception) {
                Log.w(TAG, "Could not scope to $scopePkg, falling back to whole-device capture", e)
            }
        }

        val fd = builder.establish()
        if (fd == null) {
            Log.e(TAG, "establish() returned null -- VPN permission not granted?")
            writeStatus(running = false, error = "VPN permission not granted")
            stopForeground(true)
            stopSelf()
            return
        }
        tunFd = fd
        pcap = PcapWriter(pcapFile!!)

        selector = Selector.open()
        running.set(true)
        writeStatus(running = true, error = null)

        packetsOut = FileOutputStream(tunFd!!.fileDescriptor)
        val packetsIn = FileInputStream(tunFd!!.fileDescriptor)

        readerThread = Thread({ tunReadLoop(packetsIn) }, "dscapture-tun-reader").apply { start() }
        selectorThread = Thread({ selectorLoop() }, "dscapture-selector").apply { start() }
        Log.i(TAG, "Capture started -> ${pcapFile?.absolutePath}")
    }

    private fun stopCapture() {
        if (!running.getAndSet(false)) return
        try { selector?.wakeup() } catch (_: Exception) {}
        try { readerThread?.interrupt() } catch (_: Exception) {}
        Thread.sleep(50)
        udpSessions.values.forEach { try { it.channel.close() } catch (_: Exception) {} }
        tcpSessions.values.forEach { try { it.channel.close() } catch (_: Exception) {} }
        udpSessions.clear(); tcpSessions.clear()
        try { selector?.close() } catch (_: Exception) {}
        try { packetsOut?.close() } catch (_: Exception) {}
        try { tunFd?.close() } catch (_: Exception) {}
        pcap?.flush(); pcap?.close()
        writeStatus(running = false, error = null, finished = true)
        stopForeground(true)
        Log.i(TAG, "Capture stopped -> ${pcap?.packetCount} packets")
    }

    override fun onDestroy() {
        stopCapture()
        super.onDestroy()
    }

    override fun onRevoke() {
        // User revoked VPN permission from system settings / another VPN took over.
        stopCapture()
        super.onRevoke()
    }

    // ── tun -> (pcap + relay) ────────────────────────────────────────
    private fun tunReadLoop(packetsIn: FileInputStream) {
        val buf = ByteArray(32767)
        while (running.get()) {
            try {
                val len = packetsIn.read(buf)
                if (len <= 0) { Thread.sleep(2); continue }
                writeToPcap(buf, len)
                handleOutboundPacket(buf.copyOf(len), len)
            } catch (e: Exception) {
                if (running.get()) Log.w(TAG, "tun read error", e)
            }
        }
    }

    private fun handleOutboundPacket(data: ByteArray, len: Int) {
        val pkt = ParsedPacket.parse(data, len)
        if (!pkt.valid) return
        when (pkt.protocol) {
            ParsedPacket.PROTO_UDP -> handleOutboundUdp(pkt)
            ParsedPacket.PROTO_TCP -> handleOutboundTcp(pkt)
            // ICMP/other: captured above, not relayed in v1.
        }
    }

    private fun key(devAddr: InetAddress, devPort: Int, dstAddr: InetAddress, dstPort: Int) =
        "${devAddr.hostAddress}:$devPort-${dstAddr.hostAddress}:$dstPort"

    private fun handleOutboundUdp(pkt: ParsedPacket) {
        val k = key(pkt.srcAddr, pkt.srcPort, pkt.dstAddr, pkt.dstPort)
        var session = udpSessions[k]
        if (session == null) {
            val ch = DatagramChannel.open()
            protect(ch.socket())
            ch.configureBlocking(false)
            ch.connect(InetSocketAddress(pkt.dstAddr, pkt.dstPort))
            session = UdpSession(ch, pkt.srcAddr, pkt.srcPort, pkt.dstAddr, pkt.dstPort)
            udpSessions[k] = session
            synchronized(selector!!) {
                selector!!.wakeup()
                ch.register(selector, SelectionKey.OP_READ, session)
            }
        }
        session.lastActive = System.currentTimeMillis()
        try {
            if (pkt.payloadLen > 0) {
                session.channel.write(ByteBuffer.wrap(pkt.raw, pkt.payloadOffset, pkt.payloadLen))
            }
        } catch (e: Exception) {
            Log.w(TAG, "UDP relay write failed", e)
        }
    }

    private fun handleOutboundTcp(pkt: ParsedPacket) {
        val k = key(pkt.srcAddr, pkt.srcPort, pkt.dstAddr, pkt.dstPort)
        val isSyn = (pkt.tcpFlags and ParsedPacket.TCP_SYN) != 0 && (pkt.tcpFlags and ParsedPacket.TCP_ACK) == 0
        val isRst = (pkt.tcpFlags and ParsedPacket.TCP_RST) != 0
        val isFin = (pkt.tcpFlags and ParsedPacket.TCP_FIN) != 0

        if (isSyn) {
            val ch = SocketChannel.open()
            protect(ch.socket())
            ch.configureBlocking(false)
            val session = TcpSession(ch, pkt.srcAddr, pkt.srcPort, pkt.dstAddr, pkt.dstPort)
            session.deviceNextSeq = pkt.tcpSeq + 1
            tcpSessions[k] = session
            try {
                ch.connect(InetSocketAddress(pkt.dstAddr, pkt.dstPort))
                synchronized(selector!!) {
                    selector!!.wakeup()
                    ch.register(selector, SelectionKey.OP_CONNECT, session)
                }
            } catch (e: Exception) {
                Log.w(TAG, "TCP connect failed for ${pkt.dstAddr}:${pkt.dstPort}", e)
                tcpSessions.remove(k)
            }
            return
        }

        val session = tcpSessions[k] ?: return
        session.lastActive = System.currentTimeMillis()

        if (isRst) {
            try { session.channel.close() } catch (_: Exception) {}
            tcpSessions.remove(k)
            return
        }
        if (isFin) {
            session.deviceNextSeq = pkt.tcpSeq + 1
            sendTcp(session, ParsedPacket.TCP_FIN or ParsedPacket.TCP_ACK, ByteArray(0))
            session.ourSeq += 1
            try { session.channel.close() } catch (_: Exception) {}
            tcpSessions.remove(k)
            return
        }
        if (pkt.payloadLen > 0) {
            val payload = pkt.raw.copyOfRange(pkt.payloadOffset, pkt.payloadOffset + pkt.payloadLen)
            if (!session.established) {
                // Real socket isn't connected yet -- buffer rather than ack
                // data we haven't actually relayed anywhere. The device's
                // own TCP stack will retransmit if we stay quiet for too
                // long, which is fine; finishTcpConnect() flushes this and
                // acks it for real once the socket is ready.
                session.pendingOut.write(payload)
                session.pendingAckUpTo = pkt.tcpSeq + pkt.payloadLen
                return
            }
            try {
                session.channel.write(ByteBuffer.wrap(payload))
                session.deviceNextSeq = pkt.tcpSeq + pkt.payloadLen
                sendTcp(session, ParsedPacket.TCP_ACK, ByteArray(0))
            } catch (e: Exception) {
                Log.w(TAG, "TCP relay write failed -- not acking, device will retransmit", e)
            }
        }
    }

    // ── real sockets -> (pcap + tun) ─────────────────────────────────
    private fun selectorLoop() {
        while (running.get()) {
            try {
                val sel = selector ?: break
                val n = sel.select(1000)
                if (n == 0) { reapIdleSessions(); continue }
                val it = sel.selectedKeys().iterator()
                while (it.hasNext()) {
                    val k = it.next(); it.remove()
                    if (!k.isValid) continue
                    try {
                        when {
                            k.attachment() is UdpSession && k.isReadable -> readUdpReply(k)
                            k.attachment() is TcpSession && k.isConnectable -> finishTcpConnect(k)
                            k.attachment() is TcpSession && k.isReadable -> readTcpReply(k)
                        }
                    } catch (e: Exception) {
                        Log.w(TAG, "selector event error", e)
                    }
                }
            } catch (e: Exception) {
                if (running.get()) Log.w(TAG, "selector loop error", e)
            }
        }
    }

    private fun readUdpReply(k: SelectionKey) {
        val session = k.attachment() as UdpSession
        val buf = ByteBuffer.allocate(16384)
        val n = session.channel.read(buf)
        if (n <= 0) return
        buf.flip()
        val payload = ByteArray(n); buf.get(payload)
        val reply = ParsedPacket.buildUdp(session.dstAddr, session.dstPort, session.devAddr, session.devPort, payload)
        writeToTun(reply)
    }

    private fun finishTcpConnect(k: SelectionKey) {
        val session = k.attachment() as TcpSession
        try {
            if (session.channel.finishConnect()) {
                session.established = true
                sendTcp(session, ParsedPacket.TCP_SYN or ParsedPacket.TCP_ACK, ByteArray(0))
                session.ourSeq += 1
                // Flush anything the device sent while the real connect was
                // still in flight (see the pendingOut comment on TcpSession).
                val buffered = session.pendingOut.toByteArray()
                if (buffered.isNotEmpty()) {
                    session.channel.write(ByteBuffer.wrap(buffered))
                    session.deviceNextSeq = session.pendingAckUpTo
                    sendTcp(session, ParsedPacket.TCP_ACK, ByteArray(0))
                    session.pendingOut.reset()
                }
                k.interestOps(SelectionKey.OP_READ)
            }
        } catch (e: Exception) {
            Log.w(TAG, "TCP connect to ${session.dstAddr}:${session.dstPort} failed", e)
            try { session.channel.close() } catch (_: Exception) {}
        }
    }

    private fun readTcpReply(k: SelectionKey) {
        val session = k.attachment() as TcpSession
        val buf = ByteBuffer.allocate(16384)
        val n = try { session.channel.read(buf) } catch (e: Exception) { -1 }
        if (n < 0) {
            // remote closed -> send FIN to device, drop session
            sendTcp(session, ParsedPacket.TCP_FIN or ParsedPacket.TCP_ACK, ByteArray(0))
            session.ourSeq += 1
            try { session.channel.close() } catch (_: Exception) {}
            return
        }
        if (n == 0) return
        buf.flip()
        var offset = 0
        while (offset < n) {
            val chunkLen = minOf(1400, n - offset)
            val chunk = ByteArray(chunkLen)
            buf.get(chunk, 0, chunkLen)
            sendTcp(session, ParsedPacket.TCP_ACK or ParsedPacket.TCP_PSH, chunk)
            session.ourSeq += chunkLen
            offset += chunkLen
        }
    }

    private fun sendTcp(session: TcpSession, flags: Int, payload: ByteArray) {
        val reply = ParsedPacket.buildTcp(
            session.dstAddr, session.dstPort, session.devAddr, session.devPort,
            session.ourSeq, session.deviceNextSeq, flags, 65535, payload
        )
        writeToTun(reply)
    }

    private fun writeToTun(packet: ByteArray) {
        val out = packetsOut ?: return
        synchronized(out) {
            try {
                out.write(packet)
                writeToPcap(packet, packet.size)
            } catch (e: Exception) {
                Log.w(TAG, "tun write failed", e)
            }
        }
    }

    /** Every packet that reaches the pcap goes through here: rewritten to
     * show the device's real local IP in place of the internal 10.0.0.2
     * tun address when we have one, otherwise written through unchanged
     * (the old behavior). This only affects what's written to the file --
     * relaying/session logic upstream of this always keeps using the
     * actual tun address, since that's what the OS and our sockets expect. */
    private fun writeToPcap(data: ByteArray, len: Int) {
        val real = realLocalAddr
        val forPcap = if (real != null) ParsedPacket.rewriteAddressForPcap(data, len, tunAddr, real)
                      else if (data.size == len) data else data.copyOf(len)
        pcap?.writePacket(forPcap, forPcap.size)
    }

    private fun reapIdleSessions() {
        val now = System.currentTimeMillis()
        udpSessions.entries.removeIf { (_, s) ->
            val idle = now - s.lastActive > IDLE_TIMEOUT_MS
            if (idle) try { s.channel.close() } catch (_: Exception) {}
            idle
        }
        tcpSessions.entries.removeIf { (_, s) ->
            val idle = now - s.lastActive > IDLE_TIMEOUT_MS
            if (idle) try { s.channel.close() } catch (_: Exception) {}
            idle
        }
        writeStatus(running = true, error = null)
    }

    // ── status file -- read by DroidSentinel over `adb shell cat`,
    // same convention ACBridge already uses for its own plain-file output. ──
    private fun writeStatus(running: Boolean, error: String?, finished: Boolean = false) {
        try {
            val f = statusFile ?: return
            val j = JSONObject()
            j.put("running", running)
            j.put("finished", finished)
            j.put("started_at", startedAt)
            j.put("packet_count", pcap?.packetCount ?: 0)
            j.put("byte_count", pcap?.byteCount ?: 0)
            j.put("pcap_path", pcapFile?.absolutePath ?: "")
            j.put("tcp_sessions", tcpSessions.size)
            j.put("udp_sessions", udpSessions.size)
            j.put("device_ip", realLocalAddr?.hostAddress ?: "")
            if (error != null) j.put("error", error)
            f.writeText(j.toString())
        } catch (e: Exception) {
            Log.w(TAG, "could not write status file", e)
        }
    }

    private fun buildNotification(): Notification {
        val mgr = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(NOTIF_CHANNEL, getString(R.string.notif_channel), NotificationManager.IMPORTANCE_LOW)
        mgr.createNotificationChannel(channel)
        val stopIntent = Intent(this, CaptureVpnService::class.java).setAction(ACTION_STOP)
        val stopPending = PendingIntent.getService(
            this, 0, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, NOTIF_CHANNEL)
            .setContentTitle(getString(R.string.notif_title))
            .setSmallIcon(android.R.drawable.ic_menu_report_image)
            .setOngoing(true)
            .addAction(0, "Stop", stopPending)
            .build()
    }
}
