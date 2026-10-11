package com.blocker

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {

    private lateinit var statusText: TextView
    private lateinit var toggleButton: Button
    private lateinit var setPinButton: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        try {
            setContentView(R.layout.activity_main)
            statusText = findViewById(R.id.statusText)
            toggleButton = findViewById(R.id.toggleButton)
            setPinButton = findViewById(R.id.setPinButton)

            toggleButton.setOnClickListener {
                try {
                    if (PinManager.isPinSet(this)) {
                        PinManager.showPinDialog(this) { correct ->
                            if (correct) toggleVpn()
                        }
                    } else {
                        toggleVpn()
                    }
                } catch (e: Exception) {
                    Toast.makeText(this, "Error: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }

            setPinButton.setOnClickListener {
                try {
                    PinManager.showSetPinDialog(this)
                } catch (e: Exception) {
                    Toast.makeText(this, "Error: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }

        } catch (e: Exception) {
            Toast.makeText(this, "Startup error: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun toggleVpn() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            startActivityForResult(intent, 1)
        } else {
            startVpn()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 1 && resultCode == RESULT_OK) {
            startVpn()
        }
    }

    private fun startVpn() {
        try {
            val intent = Intent(this, BlockerVpnService::class.java)
            startService(intent)
            statusText.text = "Focus Guard is Active"
            toggleButton.text = "Disable Protection"
        } catch (e: Exception) {
            Toast.makeText(this, "VPN Error: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }
}