package com.alpha.netsectest.scanner

import com.alpha.netsectest.model.PortResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.net.InetSocketAddress
import java.net.Socket

object PortScanner {

    val TOP_100 = listOf(
        21,22,23,25,53,80,110,111,135,139,143,161,162,179,199,443,445,465,514,515,
        548,554,587,631,636,646,873,990,993,995,1025,1026,1027,1028,1029,1080,1110,
        1352,1433,1434,1521,1701,1723,1755,1812,1900,2000,2049,2121,2222,2323,2375,
        2483,3000,3128,3260,3306,3389,3689,3690,4000,4444,4848,5000,5060,5222,5269,
        5353,5432,5555,5632,5800,5900,5984,6000,6379,6666,7001,7002,7070,8000,8008,
        8009,8080,8081,8086,8088,8090,8180,8443,8888,9000,9001,9090,9100,9200,9300,
        9999,10000,11211,27017,50000
    )

    suspend fun scan(
        host: String,
        ports: List<Int>,
        timeoutMs: Int = 700,
        concurrency: Int = 120
    ): List<PortResult> = coroutineScope {
        val sem = Semaphore(concurrency)
        ports.map { port ->
            async(Dispatchers.IO) {
                sem.withPermit { scanOne(host, port, timeoutMs) }
            }
        }.awaitAll().filter { it.open }
    }

    private fun scanOne(host: String, port: Int, timeoutMs: Int): PortResult {
        return try {
            val sock = Socket()
            sock.connect(InetSocketAddress(host, port), timeoutMs)
            val banner = grabBanner(sock, port)
            sock.close()
            PortResult(port, true, banner, ServiceDetector.identify(port, banner))
        } catch (_: Exception) {
            PortResult(port, false)
        }
    }

    private fun grabBanner(sock: Socket, port: Int): String? {
        return try {
            sock.soTimeout = 400
            if (port in listOf(80, 8080, 8000, 8888, 8008, 8081)) {
                sock.getOutputStream().write("HEAD / HTTP/1.0\r\n\r\n".toByteArray())
                sock.getOutputStream().flush()
            }
            val buf = ByteArray(256)
            val n = sock.getInputStream().read(buf)
            if (n > 0) String(buf, 0, n).trim().take(200) else null
        } catch (_: Exception) { null }
    }
}
