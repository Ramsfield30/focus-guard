package com.blocker

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer

class BlockerVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false

    companion object {
        val BLOCKLIST = setOf(
            "pornhub.com",
            "xvideos.com",
            "xnxx.com",
            "xhamster.com",
            "redtube.com",
            "youporn.com",
            "tube8.com",
            "spankbang.com",
            "eporner.com",
            "beeg.com"
        )
    }

    override fun onStartCommand(
        intent: android.content.Intent?,
        flags: Int,
        startId: Int
    ): Int {
        startForeground()
        setupVpn()
        isRunning = true
        Thread { runVpnLoop() }.start()
        return START_STICKY
    }

    private fun startForeground() {
        val channelId = "focus_guard"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                channelId,
                "Focus Guard",
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
            .addDnsServer("8.8.8.8")
            .addRoute("0.0.0.0", 0)
            .setSession("FocusGuard")
            .establish()
    }

    private fun runVpnLoop() {
        val input = FileInputStream(vpnInterface!!.fileDescriptor)
        val output = FileOutputStream(vpnInterface!!.fileDescriptor)
        val buffer = ByteBuffer.allocate(32767)

        while (isRunning) {
            buffer.clear()
            val length = input.read(buffer.array())
            if (length > 0) {
                buffer.limit(length)
                val domain = extractDomain(buffer)
                if (domain != null && isBlocked(domain)) {
                    // Drop the packet — blocked domain gets no response
                    continue
                }
                output.write(buffer.array(), 0, buffer.limit())
            }
        }
    }

    private fun extractDomain(buffer: ByteBuffer): String? {
        return try {
            val bytes = buffer.array()
            // DNS queries start at byte 12
            var i = 12
            val domain = StringBuilder()
            while (i < bytes.size && bytes[i] != 0.toByte()) {
                val len = bytes[i].toInt()
                i++
                val part = String(bytes, i, len)
                if (domain.isNotEmpty()) domain.append(".")
                domain.append(part)
                i += len
            }
            domain.toString().lowercase()
        } catch (e: Exception) {
            null
        }
    }

    private fun isBlocked(domain: String): Boolean {
        return BLOCKLIST.any { blocked ->
            domain == blocked || domain.endsWith(".$blocked")
        }
    }

    override fun onDestroy() {
        isRunning = false
        vpnInterface?.close()
        super.onDestroy()
    }
}