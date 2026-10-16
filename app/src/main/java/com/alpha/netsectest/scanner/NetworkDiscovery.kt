package com.alpha.netsectest.scanner

import com.alpha.netsectest.model.Device
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

object NetworkDiscovery {

    suspend fun discoverSubnet(subnetPrefix: String, timeoutMs: Int = 800): List<Device> =
        coroutineScope {
            val jobs = (1..254).map { last ->
                async(Dispatchers.IO) {
                    val ip = "$subnetPrefix.$last"
                    probeHost(ip, timeoutMs)
                }
            }
            jobs.awaitAll().filterNotNull().sortedBy { it.ip.ipToLong() }
        }

    private fun probeHost(ip: String, timeoutMs: Int): Device? {
        val start = System.currentTimeMillis()
        return try {
            val addr = InetAddress.getByName(ip)
            if (addr.isReachable(timeoutMs)) {
                val latency = System.currentTimeMillis() - start
                val hostname = try {
                    addr.canonicalHostName.takeIf { it != ip }
                } catch (_: Exception) { null }
                return Device(ip, null, hostname, latency)
            }
            if (tcpProbe(ip, listOf(80, 443, 22, 445, 8080), timeoutMs)) {
                Device(ip, null, null, System.currentTimeMillis() - start)
            } else null
        } catch (_: Exception) { null }
    }

    private fun tcpProbe(ip: String, ports: List<Int>, timeoutMs: Int): Boolean {
        for (p in ports) {
            try {
                Socket().use { s ->
                    s.connect(InetSocketAddress(ip, p), timeoutMs)
                    return true
                }
            } catch (_: Exception) { }
        }
        return false
    }

    private fun String.ipToLong(): Long =
        split('.').fold(0L) { acc, s -> (acc shl 8) or (s.toLongOrNull() ?: 0) }
}
