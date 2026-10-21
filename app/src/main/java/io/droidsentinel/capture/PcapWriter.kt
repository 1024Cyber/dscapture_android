package io.droidsentinel.capture

import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Minimal, dependency-free writer for the classic pcap (libpcap) file
 * format -- the format Wireshark has read natively since version 1.0.
 *
 * Packets read off the VPN tun are raw IP packets (no Ethernet header),
 * so this uses LINKTYPE_RAW (101), which Wireshark decodes directly as
 * "Raw IP" -- no fake Ethernet framing needed or wanted.
 *
 * File layout (all little-endian, this device's native order):
 *   global header (24 bytes), then one (16-byte record header + payload)
 *   per packet. See https://wiki.wireshark.org/Development/LibpcapFileFormat
 */
class PcapWriter(outFile: File) {
    companion object {
        private const val PCAP_MAGIC = 0xa1b2c3d4.toInt()
        private const val VERSION_MAJOR: Short = 2
        private const val VERSION_MINOR: Short = 4
        private const val LINKTYPE_RAW = 101
        private const val SNAPLEN = 65535
    }

    private val out = BufferedOutputStream(FileOutputStream(outFile))
    @Volatile var packetCount: Long = 0
        private set
    @Volatile var byteCount: Long = 0
        private set

    init {
        val header = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN)
        header.putInt(PCAP_MAGIC)
        header.putShort(VERSION_MAJOR)
        header.putShort(VERSION_MINOR)
        header.putInt(0)          // thiszone
        header.putInt(0)          // sigfigs
        header.putInt(SNAPLEN)
        header.putInt(LINKTYPE_RAW)
        out.write(header.array())
    }

    @Synchronized
    fun writePacket(data: ByteArray, length: Int) {
        val nowMicros = System.currentTimeMillis() * 1000L
        val tsSec = (nowMicros / 1_000_000L).toInt()
        val tsUsec = (nowMicros % 1_000_000L).toInt()
        val captureLen = minOf(length, SNAPLEN)

        val rec = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
        rec.putInt(tsSec)
        rec.putInt(tsUsec)
        rec.putInt(captureLen)
        rec.putInt(length)
        out.write(rec.array())
        out.write(data, 0, captureLen)

        packetCount++
        byteCount += captureLen
    }

    @Synchronized
    fun flush() = out.flush()

    @Synchronized
    fun close() {
        try { out.flush() } catch (_: Exception) {}
        try { out.close() } catch (_: Exception) {}
    }
}
