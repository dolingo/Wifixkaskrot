package com.alpha.netsectest.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.alpha.netsectest.model.CapturedConnection
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap

class PacketCaptureService : VpnService() {

    companion object {
        const val ACTION_START = "com.alpha.netsectest.START"
        const val ACTION_STOP  = "com.alpha.netsectest.STOP"
        const val CHANNEL_ID = "sentinelnet_capture"
        const val NOTIF_ID = 4242

        @Volatile var isRunning: Boolean = false
        val capturedConnections = mutableListOf<CapturedConnection>()
    }

    private var tun: ParcelFileDescriptor? = null
    private var job: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val udpSockets = ConcurrentHashMap<String, DatagramSocket>()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> { stopCapture(); return START_NOT_STICKY }
            else -> startCapture()
        }
        return START_STICKY
    }

    private fun startCapture() {
        if (isRunning) return
        createNotificationChannel()
        startForeground(NOTIF_ID, buildNotification())

        val builder = Builder()
            .setSession("SentinelNet Capture")
            .setMtu(1500)
            .addAddress("10.8.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")
            .addDnsServer("8.8.8.8")
            .setBlocking(true)

        try {
            tun = builder.establish()
            isRunning = true
            job = scope.launch { loop() }
        } catch (e: Exception) {
            stopCapture()
        }
    }

    private fun loop() {
        val fd = tun ?: return
        val input = FileInputStream(fd.fileDescriptor)
        val buffer = ByteArray(32767)

        while (isRunning) {
            try {
                val n = input.read(buffer)
                if (n <= 0) continue
                val bb = ByteBuffer.wrap(buffer, 0, n)
                val pkt = PacketParser.parse(bb) ?: continue
                logPacket(pkt)

                when (pkt.protocol) {
                    6  -> forwardTcp(pkt, buffer.copyOfRange(0, n))
                    17 -> forwardUdp(pkt, buffer.copyOfRange(0, n))
                    else -> { }
                }
            } catch (_: Exception) {
                if (!isRunning) break
            }
        }
    }

    private fun logPacket(p: ParsedPacket) {
        val proto = when (p.protocol) { 6 -> "TCP"; 17 -> "UDP"; else -> "IP" }
        val entry = CapturedConnection(
            System.currentTimeMillis(), p.srcIp, p.srcPort, p.dstIp, p.dstPort,
            proto, p.payloadLength, null
        )
        synchronized(capturedConnections) {
            capturedConnections += entry
            if (capturedConnections.size > 5000) capturedConnections.removeAt(0)
        }
    }

    private fun forwardUdp(p: ParsedPacket, raw: ByteArray) {
        try {
            val key = "${p.dstIp}:${p.dstPort}"
            val sock = udpSockets.getOrPut(key) {
                DatagramSocket().also { protect(it) }
            }
            val ihl = (raw[0].toInt() and 0x0F) * 4
            val payloadOffset = ihl + 8
            if (raw.size <= payloadOffset) return
            val payload = raw.copyOfRange(payloadOffset, raw.size)
            val addr = InetAddress.getByName(p.dstIp)
            sock.send(DatagramPacket(payload, payload.size, InetSocketAddress(addr, p.dstPort)))
        } catch (_: Exception) { }
    }

    private fun forwardTcp(p: ParsedPacket, raw: ByteArray) {
        if ((p.tcpFlags and 0x02) != 0) {
            try {
                val sock = Socket()
                protect(sock)
                sock.connect(InetSocketAddress(p.dstIp, p.dstPort), 2000)
                sock.close()
            } catch (_: Exception) { }
        }
    }

    private fun stopCapture() {
        isRunning = false
        try { job?.cancel() } catch (_: Exception) { }
        try { tun?.close() } catch (_: Exception) { }
        tun = null
        udpSockets.values.forEach { runCatching { it.close() } }
        udpSockets.clear()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() { stopCapture(); super.onRevoke() }
    override fun onDestroy() { scope.cancel(); stopCapture(); super.onDestroy() }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val ch = NotificationChannel(CHANNEL_ID, "SentinelNet Capture",
                NotificationManager.IMPORTANCE_LOW)
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(ch)
        }
    }

    private fun buildNotification(): Notification =
        NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("SentinelNet capturing")
            .setContentText("Packet capture is active")
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setOngoing(true)
            .build()
}
