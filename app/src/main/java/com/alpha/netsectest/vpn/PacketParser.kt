package com.alpha.netsectest.vpn

import java.nio.ByteBuffer

data class ParsedPacket(
    val protocol: Int,
    val srcIp: String,
    val dstIp: String,
    val srcPort: Int,
    val dstPort: Int,
    val payloadLength: Int,
    val tcpFlags: Int = 0
)

object PacketParser {

    fun parse(buf: ByteBuffer): ParsedPacket? {
        if (buf.remaining() < 20) return null
        val start = buf.position()
        val verIhl = buf.get(start).toInt() and 0xFF
        val version = verIhl shr 4
        if (version != 4) return null
        val ihl = (verIhl and 0x0F) * 4
        val protocol = buf.get(start + 9).toInt() and 0xFF
        val srcIp = ipString(buf, start + 12)
        val dstIp = ipString(buf, start + 16)
        val totalLen = ((buf.get(start + 2).toInt() and 0xFF) shl 8) or
                       (buf.get(start + 3).toInt() and 0xFF)

        var srcPort = 0; var dstPort = 0; var flags = 0
        if (protocol == 6 || protocol == 17) {
            if (buf.remaining() < ihl + 4) return null
            srcPort = ((buf.get(start + ihl).toInt() and 0xFF) shl 8) or
                      (buf.get(start + ihl + 1).toInt() and 0xFF)
            dstPort = ((buf.get(start + ihl + 2).toInt() and 0xFF) shl 8) or
                      (buf.get(start + ihl + 3).toInt() and 0xFF)
            if (protocol == 6 && buf.remaining() >= ihl + 14) {
                flags = buf.get(start + ihl + 13).toInt() and 0xFF
            }
        }
        val payload = (totalLen - ihl - if (protocol == 6) 20 else if (protocol == 17) 8 else 0)
        return ParsedPacket(protocol, srcIp, dstIp, srcPort, dstPort, payload, flags)
    }

    private fun ipString(b: ByteBuffer, off: Int): String =
        "${b.get(off).toInt() and 0xFF}.${b.get(off+1).toInt() and 0xFF}." +
        "${b.get(off+2).toInt() and 0xFF}.${b.get(off+3).toInt() and 0xFF}"
}
