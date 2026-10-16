package com.alpha.netsectest.model

data class Device(
    val ip: String,
    val mac: String? = null,
    val hostname: String? = null,
    val latencyMs: Long = -1
)

data class PortResult(
    val port: Int,
    val open: Boolean,
    val banner: String? = null,
    val service: String? = null
)

data class Vulnerability(
    val host: String,
    val port: Int,
    val severity: Severity,
    val title: String,
    val detail: String
)

enum class Severity { INFO, LOW, MEDIUM, HIGH, CRITICAL }

data class CapturedConnection(
    val timestamp: Long,
    val srcIp: String,
    val srcPort: Int,
    val dstIp: String,
    val dstPort: Int,
    val protocol: String,
    val length: Int,
    val payloadPreview: String? = null
)

data class ScanSession(
    val target: String,
    val startTime: Long,
    val devices: MutableList<Device> = mutableListOf(),
    val ports: MutableList<PortResult> = mutableListOf(),
    val vulns: MutableList<Vulnerability> = mutableListOf(),
    val connections: MutableList<CapturedConnection> = mutableListOf()
)
