package com.alpha.netsectest

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.alpha.netsectest.databinding.ActivityMainBinding
import com.alpha.netsectest.model.ScanSession
import com.alpha.netsectest.report.ReportGenerator
import com.alpha.netsectest.scanner.NetworkDiscovery
import com.alpha.netsectest.scanner.PortScanner
import com.alpha.netsectest.scanner.VulnerabilityScanner
import com.alpha.netsectest.vpn.PacketCaptureService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.Inet4Address
import java.net.NetworkInterface

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var session: ScanSession

    private val vpnPermLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { res ->
        if (res.resultCode == RESULT_OK) startCaptureService()
        else toast("VPN permission denied")
    }

    private val notifPermLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            notifPermLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }

        session = ScanSession(target = "unknown", startTime = System.currentTimeMillis())
        binding.etTarget.setText(currentSubnet())
        binding.etPorts.setText("top100")

        binding.btnDiscover.setOnClickListener { runDiscovery() }
        binding.btnPortScan.setOnClickListener { runPortScan() }
        binding.btnVulnScan.setOnClickListener { runVulnScan() }
        binding.btnCapture.setOnClickListener { toggleCapture() }
        binding.btnExport.setOnClickListener { exportReport() }
    }

    private fun runDiscovery() {
        val subnet = binding.etTarget.text.toString().trim().removeSuffix(".")
        if (subnet.isEmpty()) { toast("Enter subnet like 192.168.1"); return }
        log(">> Discovering hosts on $subnet.0/24 ...")
        session.target = subnet
        lifecycleScope.launch {
            val start = System.currentTimeMillis()
            val devices = NetworkDiscovery.discoverSubnet(subnet)
            session.devices.clear(); session.devices.addAll(devices)
            log(">> Found ${devices.size} device(s) in ${System.currentTimeMillis() - start} ms")
            devices.forEach { d ->
                log("  - ${d.ip}  ${d.hostname ?: ""}  ${if (d.latencyMs >= 0) "${d.latencyMs}ms" else ""}")
            }
        }
    }

    private fun runPortScan() {
        val host = binding.etTarget.text.toString().trim().substringBeforeLast(".", "")
            .let { if (it.isEmpty()) binding.etTarget.text.toString().trim() else binding.etTarget.text.toString().trim() }
        val targets = if (session.devices.isNotEmpty()) session.devices.map { it.ip } else listOf(host)
        val portSpec = binding.etPorts.text.toString().trim()
        val ports = parsePorts(portSpec)

        log(">> Scanning ports on ${targets.size} host(s), ${ports.size} port(s) each ...")
        lifecycleScope.launch {
            session.ports.clear()
            for (t in targets) {
                val open = PortScanner.scan(t, ports)
                session.ports.addAll(open)
                log("  - $t -> ${open.size} open")
                open.forEach { log("      ${it.port}  ${it.service ?: ""}  ${it.banner?.take(60) ?: ""}") }
            }
            log(">> Port scan complete: ${session.ports.size} open total")
        }
    }

    private fun runVulnScan() {
        if (session.ports.isEmpty()) { toast("Run port scan first"); return }
        log(">> Analyzing ${session.ports.size} open port(s) for vulnerabilities ...")
        lifecycleScope.launch {
            session.vulns.clear()
            val host = session.devices.firstOrNull()?.ip
                ?: binding.etTarget.text.toString().trim()
            val v = VulnerabilityScanner.analyze(host, session.ports)
            session.vulns.addAll(v)
            v.forEach { log("  [${it.severity}] ${it.title} - ${it.detail}") }
            log(">> Vulnerability scan complete: ${v.size} finding(s)")
        }
    }

    private fun toggleCapture() {
        if (PacketCaptureService.isRunning) {
            startService(Intent(this, PacketCaptureService::class.java)
                .setAction(PacketCaptureService.ACTION_STOP))
            log(">> Capture stopped")
            return
        }
        val prep = VpnService.prepare(this)
        if (prep != null) vpnPermLauncher.launch(prep)
        else startCaptureService()
    }

    private fun startCaptureService() {
        ContextCompat.startForegroundService(
            this,
            Intent(this, PacketCaptureService::class.java)
                .setAction(PacketCaptureService.ACTION_START)
        )
        log(">> Capture started - traffic metadata logging active")
        lifecycleScope.launch {
            while (PacketCaptureService.isRunning) {
                val snapshot = synchronized(PacketCaptureService.capturedConnections) {
                    PacketCaptureService.capturedConnections.toList()
                }
                session.connections.clear(); session.connections.addAll(snapshot)
                kotlinx.coroutines.delay(2000)
            }
            log(">> Capture ended. ${session.connections.size} connection(s) logged.")
        }
    }

    private fun exportReport() {
        lifecycleScope.launch {
            val f = withContext(Dispatchers.IO) { ReportGenerator.writeHtml(this@MainActivity, session) }
            log(">> Report saved: ${f.absolutePath}")
            toast("Report: ${f.name}")
        }
    }

    private fun log(s: String) {
        runOnUiThread { binding.tvLog.append("$s\n") }
    }

    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_SHORT).show()

    private fun parsePorts(spec: String): List<Int> {
        return when {
            spec.equals("top100", true) -> PortScanner.TOP_100
            spec.equals("all", true) -> (1..1024).toList()
            spec.contains("-") -> {
                val (a, b) = spec.split("-").map { it.trim().toInt() }
                (a..b).toList()
            }
            else -> spec.split(",").mapNotNull { it.trim().toIntOrNull() }
        }
    }

    private fun currentSubnet(): String {
        return try {
            val ifaces = NetworkInterface.getNetworkInterfaces().toList()
            for (nif in ifaces) {
                for (addr in nif.inetAddresses) {
                    if (!addr.isLoopbackAddress && addr is Inet4Address) {
                        val ip = addr.hostAddress ?: continue
                        val parts = ip.split(".")
                        if (parts.size == 4) return "${parts[0]}.${parts[1]}.${parts[2]}"
                    }
                }
            }
            "192.168.1"
        } catch (_: Exception) { "192.168.1" }
    }
                    }
