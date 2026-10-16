package com.alpha.netsectest.report

import android.content.Context
import com.alpha.netsectest.model.ScanSession
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object ReportGenerator {

    fun writeHtml(ctx: Context, session: ScanSession): File {
        val dir = File(ctx.getExternalFilesDir(null), "reports").apply { mkdirs() }
        val stamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        val file = File(dir, "sentinelnet_$stamp.html")

        val sb = StringBuilder()
        sb.append("<!doctype html><html><head><meta charset='utf-8'>")
        sb.append("<title>SentinelNet Report</title>")
        sb.append("<style>")
        sb.append("body{font-family:system-ui,Segoe UI,Arial;background:#0d1117;color:#c9d1d9;padding:24px}")
        sb.append("h1,h2{color:#58a6ff}table{width:100%;border-collapse:collapse;margin:16px 0}")
        sb.append("th,td{border:1px solid #30363d;padding:8px;text-align:left;font-size:14px}")
        sb.append("th{background:#161b22}.CRITICAL{color:#ff7b72;font-weight:bold}")
        sb.append(".HIGH{color:#ffa657}.MEDIUM{color:#d29922}.LOW{color:#79c0ff}.INFO{color:#8b949e}")
        sb.append("</style></head><body>")
        sb.append("<h1>SentinelNet Report</h1>")
        sb.append("<p><b>Target:</b> ${esc(session.target)}<br>")
        sb.append("<b>Started:</b> ${Date(session.startTime)}<br>")
        sb.append("<b>Generated:</b> ${Date()}</p>")

        sb.append("<h2>Devices (${session.devices.size})</h2><table>")
        sb.append("<tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Latency</th></tr>")
        session.devices.forEach {
            sb.append("<tr><td>${esc(it.ip)}</td><td>${esc(it.mac ?: "-")}</td>")
            sb.append("<td>${esc(it.hostname ?: "-")}</td><td>${it.latencyMs}ms</td></tr>")
        }
        sb.append("</table>")

        sb.append("<h2>Open Ports (${session.ports.size})</h2><table>")
        sb.append("<tr><th>Port</th><th>Service</th><th>Banner</th></tr>")
        session.ports.forEach {
            sb.append("<tr><td>${it.port}</td><td>${esc(it.service ?: "-")}</td>")
            sb.append("<td>${esc(it.banner ?: "-")}</td></tr>")
        }
        sb.append("</table>")

        sb.append("<h2>Vulnerabilities (${session.vulns.size})</h2><table>")
        sb.append("<tr><th>Severity</th><th>Host</th><th>Port</th><th>Title</th><th>Detail</th></tr>")
        session.vulns.sortedBy { it.severity.ordinal }.reversed().forEach {
            sb.append("<tr><td class='${it.severity}'>${it.severity}</td>")
            sb.append("<td>${esc(it.host)}</td><td>${it.port}</td>")
            sb.append("<td>${esc(it.title)}</td><td>${esc(it.detail)}</td></tr>")
        }
        sb.append("</table>")

        sb.append("<h2>Captured Connections (${session.connections.size})</h2><table>")
        sb.append("<tr><th>Time</th><th>Src</th><th>Dst</th><th>Proto</th><th>Bytes</th></tr>")
        session.connections.takeLast(500).forEach {
            sb.append("<tr><td>${Date(it.timestamp)}</td>")
            sb.append("<td>${it.srcIp}:${it.srcPort}</td>")
            sb.append("<td>${it.dstIp}:${it.dstPort}</td>")
            sb.append("<td>${it.protocol}</td><td>${it.length}</td></tr>")
        }
        sb.append("</table>")

        sb.append("</body></html>")
        file.writeText(sb.toString())
        return file
    }

    private fun esc(s: String): String =
        s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
}
