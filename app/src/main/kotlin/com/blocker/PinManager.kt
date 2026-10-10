package com.blocker

import android.app.AlertDialog
import android.content.Context
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.Toast

object PinManager {

    private const val PREFS_NAME = "focus_guard_prefs"
    private const val PIN_KEY = "pin_hash"

    fun isPinSet(context: Context): Boolean {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getString(PIN_KEY, null) != null
    }

    fun showSetPinDialog(context: Context) {
        val input = EditText(context)
        input.hint = "Enter a PIN for your trusted friend"
        input.inputType = android.text.InputType.TYPE_CLASS_NUMBER or
                android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD

        val layout = LinearLayout(context)
        layout.setPadding(50, 20, 50, 20)
        layout.addView(input)

        AlertDialog.Builder(context)
            .setTitle("Set PIN")
            .setMessage("This PIN will be needed to disable Focus Guard")
            .setView(layout)
            .setPositiveButton("Save") { _, _ ->
                val pin = input.text.toString()
                if (pin.length < 4) {
                    Toast.makeText(context, 
                        "PIN must be at least 4 digits", 
                        Toast.LENGTH_SHORT).show()
                } else {
                    savePin(context, pin)
                    Toast.makeText(context,
                        "PIN saved successfully",
                        Toast.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    fun showPinDialog(context: Context, onResult: (Boolean) -> Unit) {
        val input = EditText(context)
        input.hint = "Enter PIN to disable"
        input.inputType = android.text.InputType.TYPE_CLASS_NUMBER or
                android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD

        val layout = LinearLayout(context)
        layout.setPadding(50, 20, 50, 20)
        layout.addView(input)

        AlertDialog.Builder(context)
            .setTitle("PIN Required")
            .setMessage("Enter the PIN to disable Focus Guard")
            .setView(layout)
            .setPositiveButton("Confirm") { _, _ ->
                val entered = input.text.toString()
                val correct = checkPin(context, entered)
                if (!correct) {
                    Toast.makeText(context,
                        "Wrong PIN",
                        Toast.LENGTH_SHORT).show()
                }
                onResult(correct)
            }
            .setNegativeButton("Cancel") { _, _ ->
                onResult(false)
            }
            .show()
    }

    private fun savePin(context: Context, pin: String) {
        val hash = pin.hashCode().toString()
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(PIN_KEY, hash)
            .apply()
    }

    private fun checkPin(context: Context, pin: String): Boolean {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val saved = prefs.getString(PIN_KEY, null)
        return saved == pin.hashCode().toString()
    }
}