package io.droidsentinel.capture

import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Parsed view of one IPv4 packet read off the tun -- just enough fields
 * to run a minimal NAT/relay (source/dest, protocol, and for TCP/UDP the
 * ports + TCP flags/sequence numbers). Not a general-purpose IP stack. */
class ParsedPacket(val raw: ByteArray, val length: Int) {
    var valid = false
    var version = 0
    var ihl = 0
    var protocol = 0
    lateinit var srcAddr: InetAddress
    lateinit var dstAddr: InetAddress
    var ipHeaderLen = 0

    // transport (TCP=6 / UDP=17 only)
    var srcPort = 0
    var dstPort = 0
    var tcpSeq = 0L
    var tcpAck = 0L
    var tcpFlags = 0
    var tcpWindow = 0
    var payloadOffset = 0
    var payloadLen = 0

    companion object {
        const val PROTO_TCP = 6
        const val PROTO_UDP = 17
        const val PROTO_ICMP = 1

        const val TCP_FIN = 0x01
        const val TCP_SYN = 0x02
        const val TCP_RST = 0x04
        const val TCP_PSH = 0x08
        const val TCP_ACK = 0x10

        fun parse(buf: ByteArray, len: Int): ParsedPacket {
            val p = ParsedPacket(buf, len)
            if (len < 20) return p
            val versionIhl = buf[0].toInt() and 0xFF
            p.version = versionIhl shr 4
            if (p.version != 4) return p // IPv6 raw capture is written to pcap as-is elsewhere; NAT here is v4-only
            p.ihl = versionIhl and 0x0F
            p.ipHeaderLen = p.ihl * 4
            if (len < p.ipHeaderLen) return p
            p.protocol = buf[9].toInt() and 0xFF
            p.srcAddr = InetAddress.getByAddress(buf.copyOfRange(12, 16))
            p.dstAddr = InetAddress.getByAddress(buf.copyOfRange(16, 20))

            val off = p.ipHeaderLen
            when (p.protocol) {
                PROTO_UDP -> {
                    if (len < off + 8) return p
                    p.srcPort = ((buf[off].toInt() and 0xFF) shl 8) or (buf[off + 1].toInt() and 0xFF)
                    p.dstPort = ((buf[off + 2].toInt() and 0xFF) shl 8) or (buf[off + 3].toInt() and 0xFF)
                    p.payloadOffset = off + 8
                    p.payloadLen = maxOf(0, len - p.payloadOffset)
                }
                PROTO_TCP -> {
                    if (len < off + 20) return p
                    p.srcPort = ((buf[off].toInt() and 0xFF) shl 8) or (buf[off + 1].toInt() and 0xFF)
                    p.dstPort = ((buf[off + 2].toInt() and 0xFF) shl 8) or (buf[off + 3].toInt() and 0xFF)
                    p.tcpSeq = readU32(buf, off + 4)
                    p.tcpAck = readU32(buf, off + 8)
                    val dataOffByte = buf[off + 12].toInt() and 0xFF
                    val tcpHeaderLen = (dataOffByte shr 4) * 4
                    p.tcpFlags = buf[off + 13].toInt() and 0x3F
                    p.tcpWindow = ((buf[off + 14].toInt() and 0xFF) shl 8) or (buf[off + 15].toInt() and 0xFF)
                    p.payloadOffset = off + tcpHeaderLen
                    p.payloadLen = maxOf(0, len - p.payloadOffset)
                }
            }
            p.valid = true
            return p
        }

        private fun readU32(buf: ByteArray, off: Int): Long {
            return ((buf[off].toLong() and 0xFF) shl 24) or
                   ((buf[off + 1].toLong() and 0xFF) shl 16) or
                   ((buf[off + 2].toLong() and 0xFF) shl 8) or
                   (buf[off + 3].toLong() and 0xFF)
        }

        /** Builds a reply IPv4+UDP packet (srcAddr:srcPort -> dstAddr:dstPort) carrying `payload`. */
        fun buildUdp(srcAddr: InetAddress, srcPort: Int, dstAddr: InetAddress, dstPort: Int, payload: ByteArray): ByteArray {
            val udpLen = 8 + payload.size
            val totalLen = 20 + udpLen
            val buf = ByteBuffer.allocate(totalLen).order(ByteOrder.BIG_ENDIAN)
            writeIpHeader(buf, srcAddr, dstAddr, PROTO_UDP, totalLen)
            buf.putShort(srcPort.toShort())
            buf.putShort(dstPort.toShort())
            buf.putShort(udpLen.toShort())
            buf.putShort(0) // checksum optional over IPv4, 0 = not computed
            buf.put(payload)
            val arr = buf.array()
            fixIpChecksum(arr)
            return arr
        }

        /** Builds a reply IPv4+TCP packet with the given seq/ack/flags and optional payload. */
        fun buildTcp(
            srcAddr: InetAddress, srcPort: Int, dstAddr: InetAddress, dstPort: Int,
            seq: Long, ack: Long, flags: Int, window: Int, payload: ByteArray
        ): ByteArray {
            val tcpHeaderLen = 20
            val totalLen = 20 + tcpHeaderLen + payload.size
            val buf = ByteBuffer.allocate(totalLen).order(ByteOrder.BIG_ENDIAN)
            writeIpHeader(buf, srcAddr, dstAddr, PROTO_TCP, totalLen)
            val tcpStart = buf.position()
            buf.putShort(srcPort.toShort())
            buf.putShort(dstPort.toShort())
            buf.putInt(seq.toInt())
            buf.putInt(ack.toInt())
            buf.put(((tcpHeaderLen / 4) shl 4).toByte()) // data offset, no options
            buf.put((flags and 0xFF).toByte())
            buf.putShort(window.toShort())
            buf.putShort(0) // checksum, fixed below
            buf.putShort(0) // urgent pointer
            buf.put(payload)

            val arr = buf.array()
            fixIpChecksum(arr)
            fixTcpChecksum(arr, tcpStart, tcpHeaderLen + payload.size, srcAddr, dstAddr)
            return arr
        }

        /**
         * Returns a copy of this raw IPv4 packet with every occurrence of
         * `from` (our synthetic tun address, 10.0.0.2) swapped for `to`
         * (the device's real local IP), IP/TCP/UDP checksums fixed up so
         * the result still verifies cleanly in Wireshark.
         *
         * This is purely cosmetic for what lands in the pcap file -- the
         * relay path (sessions, the tun fd itself) keeps using the
         * original synthetic address throughout, since that's the address
         * the OS and our relay sockets actually expect; only the bytes we
         * hand to PcapWriter are rewritten. If `from` doesn't appear in
         * this packet (nothing to rewrite) or the packet isn't a plain
         * IPv4 header we recognize, the original bytes are returned as-is.
         */
        fun rewriteAddressForPcap(buf: ByteArray, len: Int, from: InetAddress, to: InetAddress): ByteArray {
            if (len < 20) return buf.copyOf(len)
            val fromBytes = from.address
            val toBytes = to.address
            if (fromBytes.size != 4 || toBytes.size != 4) return buf.copyOf(len)

            val arr = buf.copyOf(len)
            val versionIhl = arr[0].toInt() and 0xFF
            if (versionIhl shr 4 != 4) return arr // not IPv4 -- left untouched
            val ihl = (versionIhl and 0x0F) * 4
            if (len < ihl) return arr

            var changed = false
            if (arr.copyOfRange(12, 16).contentEquals(fromBytes)) {
                toBytes.copyInto(arr, 12); changed = true
            }
            if (arr.copyOfRange(16, 20).contentEquals(fromBytes)) {
                toBytes.copyInto(arr, 16); changed = true
            }
            if (!changed) return arr

            fixIpChecksum(arr, ihl)
            val proto = arr[9].toInt() and 0xFF
            val srcAddr = InetAddress.getByAddress(arr.copyOfRange(12, 16))
            val dstAddr = InetAddress.getByAddress(arr.copyOfRange(16, 20))
            when (proto) {
                PROTO_TCP -> if (len >= ihl + 20) fixTcpChecksum(arr, ihl, len - ihl, srcAddr, dstAddr)
                PROTO_UDP -> if (len >= ihl + 8) fixUdpChecksum(arr, ihl, len - ihl, srcAddr, dstAddr)
                // ICMP/other: addresses are swapped above, checksum doesn't
                // cover IP addresses for those protocols so nothing else to fix.
            }
            return arr
        }

        private fun writeIpHeader(buf: ByteBuffer, src: InetAddress, dst: InetAddress, proto: Int, totalLen: Int) {
            buf.put((0x45).toByte())       // version=4, IHL=5
            buf.put(0)                     // DSCP/ECN
            buf.putShort(totalLen.toShort())
            buf.putShort(0)                // identification
            buf.putShort(0x4000.toShort()) // flags=DF, no fragment offset
            buf.put(64)                    // TTL
            buf.put(proto.toByte())
            buf.putShort(0)                // header checksum, fixed up after
            buf.put(src.address)
            buf.put(dst.address)
        }

        private fun fixIpChecksum(arr: ByteArray, ihl: Int = 20) {
            // header checksum lives at bytes 10-11; covers the whole IP
            // header, which is 20 bytes unless options are present (ihl > 20).
            arr[10] = 0; arr[11] = 0
            val sum = checksum16(arr, 0, ihl)
            arr[10] = (sum shr 8).toByte()
            arr[11] = (sum and 0xFF).toByte()
        }

        private fun fixUdpChecksum(arr: ByteArray, udpStart: Int, udpLen: Int, src: InetAddress, dst: InetAddress) {
            arr[udpStart + 6] = 0; arr[udpStart + 7] = 0
            // pseudo-header: src(4) + dst(4) + zero(1) + proto(1) + udpLen(2)
            val pseudo = ByteBuffer.allocate(12 + udpLen).order(ByteOrder.BIG_ENDIAN)
            pseudo.put(src.address); pseudo.put(dst.address)
            pseudo.put(0); pseudo.put(PROTO_UDP.toByte())
            pseudo.putShort(udpLen.toShort())
            pseudo.put(arr, udpStart, udpLen)
            var sum = checksum16(pseudo.array(), 0, pseudo.array().size)
            // A computed value of 0 means "no checksum" on the wire for UDP;
            // real stacks send the one's-complement-of-zero form (0xFFFF)
            // instead so the checksum is never mistaken for "disabled".
            if (sum == 0) sum = 0xFFFF
            arr[udpStart + 6] = (sum shr 8).toByte()
            arr[udpStart + 7] = (sum and 0xFF).toByte()
        }

        private fun fixTcpChecksum(arr: ByteArray, tcpStart: Int, tcpLen: Int, src: InetAddress, dst: InetAddress) {
            arr[tcpStart + 16] = 0; arr[tcpStart + 17] = 0
            // pseudo-header: src(4) + dst(4) + zero(1) + proto(1) + tcpLen(2)
            val pseudo = ByteBuffer.allocate(12 + tcpLen).order(ByteOrder.BIG_ENDIAN)
            pseudo.put(src.address); pseudo.put(dst.address)
            pseudo.put(0); pseudo.put(PROTO_TCP.toByte())
            pseudo.putShort(tcpLen.toShort())
            pseudo.put(arr, tcpStart, tcpLen)
            val sum = checksum16(pseudo.array(), 0, pseudo.array().size)
            arr[tcpStart + 16] = (sum shr 8).toByte()
            arr[tcpStart + 17] = (sum and 0xFF).toByte()
        }

        /** Standard one's-complement 16-bit internet checksum (RFC 1071). */
        private fun checksum16(data: ByteArray, offset: Int, len: Int): Int {
            var sum = 0L
            var i = offset
            val end = offset + len
            while (i < end - 1) {
                sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
                i += 2
            }
            if (i < end) sum += (data[i].toInt() and 0xFF) shl 8
            while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
            return (sum.inv() and 0xFFFF).toInt()
        }
    }
}
