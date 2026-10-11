package com.blocker

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.io.*
import java.net.*
import java.nio.ByteBuffer

class BlockerVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false

    companion object {
        val BLOCKLIST = setOf(
            "pornhub.com", "xvideos.com", "xnxx.com",
            "xhamster.com", "redtube.com", "youporn.com",
            "tube8.com", "spankbang.com", "eporner.com", "beeg.com"
        )
        const val DNS_PORT = 5353
        const val REAL_DNS = "8.8.8.8"
    }

    override fun onStartCommand(
        intent: android.content.Intent?,
        flags: Int, startId: Int
    ): Int {
        startForegroundNotification()
        Thread { startDnsProxy() }.start()
        setupVpn()
        isRunning = true
        return START_STICKY
    }

    private fun startForegroundNotification() {
        val channelId = "focus_guard"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                channelId, "Focus Guard",
                NotificationManager.IMPORTANCE_LOW
            )
            getSystemService(NotificationManager::class.java)
                .createNotificationChannel(channel)
        }
        val notification = Notification.Builder(this, channelId)
            .setContentTitle("Focus Guard Active")
            .setContentText("Blocking adult content")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .build()
        startForeground(1, notification)
    }

    private fun startDnsProxy() {
        try {
            val serverSocket = DatagramSocket(DNS_PORT,
                InetAddress.getByName("127.0.0.1"))
            val buffer = ByteArray(4096)

            while (isRunning) {
                try {
                    val packet = DatagramPacket(buffer, buffer.size)
                    serverSocket.receive(packet)
                    val data = packet.data.copyOf(packet.length)
                    val domain = extractDomainFromDns(data)

                    if (domain != null && isBlocked(domain)) {
                        val response = buildNxDomainResponse(data)
                        val responsePacket = DatagramPacket(
                            response, response.size,
                            packet.address, packet.port
                        )
                        serverSocket.send(responsePacket)
                    } else {
                        forwardAndRespond(data, packet, serverSocket)
                    }
                } catch (e: Exception) {
                    e.printStackTrace()
                }
            }
            serverSocket.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun forwardAndRespond(
        dnsQuery: ByteArray,
        originalPacket: DatagramPacket,
        serverSocket: DatagramSocket
    ) {
        try {
            val forwardSocket = DatagramSocket()
            protect(forwardSocket)
            forwardSocket.soTimeout = 3000
            val request = DatagramPacket(
                dnsQuery, dnsQuery.size,
                InetAddress.getByName(REAL_DNS), 53
            )
            forwardSocket.send(request)
            val responseBuffer = ByteArray(4096)
            val response = DatagramPacket(responseBuffer, responseBuffer.size)
            forwardSocket.receive(response)
            forwardSocket.close()
            val responsePacket = DatagramPacket(
                responseBuffer, response.length,
                originalPacket.address, originalPacket.port
            )
            serverSocket.send(responsePacket)
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun setupVpn() {
        vpnInterface = Builder()
            .addAddress("10.0.0.2", 32)
            .addDnsServer("127.0.0.1")
            .addRoute("0.0.0.0", 0)
            .setSession("FocusGuard")
            .establish()
    }

    private fun extractDomainFromDns(dns: ByteArray): String? {
        return try {
            val sb = StringBuilder()
            var i = 12
            while (i < dns.size && dns[i] != 0.toByte()) {
                val len = dns[i].toInt() and 0xFF
                if (len == 0) break
                i++
                if (i + len > dns.size) break
                if (sb.isNotEmpty()) sb.append('.')
                sb.append(String(dns, i, len, Charsets.UTF_8))
                i += len
            }
            sb.toString().lowercase().takeIf { it.isNotEmpty() }
        } catch (e: Exception) { null }
    }

    private fun isBlocked(domain: String): Boolean {
        return BLOCKLIST.any { blocked ->
            domain == blocked || domain.endsWith(".$blocked")
        }
    }

    private fun buildNxDomainResponse(query: ByteArray): ByteArray {
        val response = query.copyOf()
        response[2] = (response[2].toInt() or 0x80).toByte()
        response[3] = 0x83.toByte()
        return response
    }

    override fun onDestroy() {
        isRunning = false
        vpnInterface?.close()
        super.onDestroy()
    }
}