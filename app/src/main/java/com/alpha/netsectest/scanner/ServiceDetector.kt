package com.alpha.netsectest.scanner

object ServiceDetector {

    private val MAP = mapOf(
        21 to "ftp", 22 to "ssh", 23 to "telnet", 25 to "smtp", 53 to "dns",
        80 to "http", 110 to "pop3", 111 to "rpcbind", 135 to "msrpc", 139 to "netbios",
        143 to "imap", 161 to "snmp", 443 to "https", 445 to "smb", 465 to "smtps",
        514 to "syslog", 587 to "smtp-sub", 631 to "ipp", 873 to "rsync",
        993 to "imaps", 995 to "pop3s", 1080 to "socks", 1433 to "mssql",
        1521 to "oracle", 1723 to "pptp", 2049 to "nfs", 2375 to "docker",
        3306 to "mysql", 3389 to "rdp", 5432 to "postgres", 5900 to "vnc",
        5984 to "couchdb", 6379 to "redis", 8080 to "http-alt", 8443 to "https-alt",
        9200 to "elasticsearch", 11211 to "memcached", 27017 to "mongodb"
    )

    fun identify(port: Int, banner: String?): String {
        val base = MAP[port] ?: "unknown"
        val b = banner?.lowercase() ?: return base
        return when {
            b.contains("ssh") -> "ssh"
            b.contains("http") && b.contains("apache") -> "apache"
            b.contains("http") && b.contains("nginx") -> "nginx"
            b.contains("http") -> "http"
            b.contains("ftp") -> "ftp"
            b.contains("smtp") -> "smtp"
            b.contains("mysql") -> "mysql"
            b.contains("redis") -> "redis"
            b.contains("mongo") -> "mongodb"
            b.contains("telnet") -> "telnet"
            else -> base
        }
    }
}
