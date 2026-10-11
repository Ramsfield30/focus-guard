package com.blocker

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.io.*
import java.net.*

class BlockerVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false

    companion object {
        val BLOCKLIST = setOf(
            "pornhub.com", "xvideos.com", "xnxx.com",
            "xhamster.com", "redtube.com", "youporn.com",
            "tube8.com", "spankbang.com", "eporner.com", "beeg.com"
        )
    }

    override fun onStartCommand(
        intent: android.content.Intent?,
        flags: Int, startId: Int
    ): Int {
        startForegroundNotification()
        setupVpn()
        isRunning = true
        Thread { runVpnLoop() }.start()
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

    private fun setupVpn() {
        vpnInterface = Builder()
            .addAddress("10.0.0.2", 32)
            .addDnsServer("10.0.0.2")
            .addRoute("10.0.0.2", 32) // Only DNS traffic through VPN
            .setSession("FocusGuard")
            .establish()
    }

    private fun runVpnLoop() {
        val inputStream = FileInputStream(vpnInterface!!.fileDescriptor)
        val outputStream = FileOutputStream(vpnInterface!!.fileDescriptor)
        val packet = ByteArray(32767)

        while (isRunning) {
            try {
                val length = inputStream.read(packet)
                if (length <= 0) continue
                val response = processPacket(packet, length)
                if (response != null) outputStream.write(response)
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }

    private fun processPacket(packet: ByteArray, length: Int): ByteArray? {
        if (length < 28) return null
        if (packet[9].toInt() and 0xFF != 17) return null // UDP only
        val ipHeaderLen = (packet[0].toInt() and 0x0F) * 4
        val destPort = ((packet[ipHeaderLen + 2].toInt() and 0xFF) shl 8) or
                (packet[ipHeaderLen + 3].toInt() and 0xFF)
        if (destPort != 53) return null // DNS only
        val dnsOffset = ipHeaderLen + 8
        val dnsLength = length - dnsOffset
        if (dnsLength < 12) return null
        val dnsData = packet.copyOfRange(dnsOffset, dnsOffset + dnsLength)
        val domain = extractDomain(dnsData)
        return if (domain != null && isBlocked(domain)) {
            buildNxDomainResponse(packet, dnsData, ipHeaderLen)
        } else {
            forwardToRealDns(packet, dnsData, ipHeaderLen)
        }
    }

    private fun extractDomain(dns: ByteArray): String? {
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

    private fun forwardToRealDns(
        packet: ByteArray,
        dnsQuery: ByteArray,
        ipHeaderLen: Int
    ): ByteArray? {
        return try {
            val socket = DatagramSocket()
            protect(socket) // Bypasses VPN — goes directly to internet
            socket.soTimeout = 3000
            val request = DatagramPacket(
                dnsQuery, dnsQuery.size,
                InetAddress.getByName("8.8.8.8"), 53
            )
            socket.send(request)
            val responseBuffer = ByteArray(4096)
            val response = DatagramPacket(responseBuffer, responseBuffer.size)
            socket.receive(response)
            socket.close()
            buildUdpIpPacket(packet, responseBuffer.copyOf(response.length), ipHeaderLen)
        } catch (e: Exception) { null }
    }

    private fun buildNxDomainResponse(
        packet: ByteArray,
        dnsQuery: ByteArray,
        ipHeaderLen: Int
    ): ByteArray {
        val dnsResponse = dnsQuery.copyOf()
        dnsResponse[2] = (dnsResponse[2].toInt() or 0x80).toByte()
        dnsResponse[3] = 0x83.toByte()
        return buildUdpIpPacket(packet, dnsResponse, ipHeaderLen)
    }

    private fun buildUdpIpPacket(
        originalPacket: ByteArray,
        dnsPayload: ByteArray,
        ipHeaderLen: Int
    ): ByteArray {
        val totalLen = ipHeaderLen + 8 + dnsPayload.size
        val response = ByteArray(totalLen)
        System.arraycopy(originalPacket, 0, response, 0, ipHeaderLen)
        System.arraycopy(originalPacket, 12, response, 16, 4)
        System.arraycopy(originalPacket, 16, response, 12, 4)
        response[2] = (totalLen shr 8).toByte()
        response[3] = (totalLen and 0xFF).toByte()
        response[6] = 0; response[7] = 0
        response[ipHeaderLen] = originalPacket[ipHeaderLen + 2]
        response[ipHeaderLen + 1] = originalPacket[ipHeaderLen + 3]
        response[ipHeaderLen + 2] = originalPacket[ipHeaderLen]
        response[ipHeaderLen + 3] = originalPacket[ipHeaderLen + 1]
        val udpLen = 8 + dnsPayload.size
        response[ipHeaderLen + 4] = (udpLen shr 8).toByte()
        response[ipHeaderLen + 5] = (udpLen and 0xFF).toByte()
        response[ipHeaderLen + 6] = 0
        response[ipHeaderLen + 7] = 0
        System.arraycopy(dnsPayload, 0, response, ipHeaderLen + 8, dnsPayload.size)
        calculateIpChecksum(response, ipHeaderLen)
        return response
    }

    private fun calculateIpChecksum(packet: ByteArray, headerLen: Int) {
        packet[10] = 0; packet[11] = 0
        var sum = 0
        for (i in 0 until headerLen step 2) {
            sum += ((packet[i].toInt() and 0xFF) shl 8) or
                    (packet[i + 1].toInt() and 0xFF)
        }
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        val checksum = sum.inv() and 0xFFFF
        packet[10] = (checksum shr 8).toByte()
        packet[11] = (checksum and 0xFF).toByte()
    }

    override fun onDestroy() {
        isRunning = false
        vpnInterface?.close()
        super.onDestroy()
    }
}