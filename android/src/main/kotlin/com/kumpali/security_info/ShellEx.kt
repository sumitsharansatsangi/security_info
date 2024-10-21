package com.kumpali.security_info

import android.util.Log
import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.InputStreamReader
import java.io.OutputStreamWriter

class ShellEx {

    enum class SHELL_CMD(val command: Array<String>) {
        CHECK_SU_BINARY(arrayOf("/system/xbin/which", "su")),
        CHECK_DAEMON_SU(arrayOf("ps", "daemonsu")),
        RUN_SU(arrayOf("su")),
        CHECK_SU(arrayOf("ps", "|", "grep", "su"))
    }

    fun executeCommand(shellCmd: SHELL_CMD): List<String>? {
        val fullResponse = mutableListOf<String>()
        val localProcess: Process?
        return try {
            localProcess = Runtime.getRuntime().exec(shellCmd.command)
            val out = BufferedWriter(OutputStreamWriter(localProcess.outputStream))
            val `in` = BufferedReader(InputStreamReader(localProcess.inputStream))
            var line: String?
            while (`in`.readLine().also { line = it } != null) {
                fullResponse.add(line!!)
            }
            Log.d("RootInspector", "--> Full response was: $fullResponse")
            fullResponse
        } catch (e: Exception) {
            null
        }
    }

    fun executeCommandSU(shellCmd: SHELL_CMD): Boolean {
        return try {
            val localProcess = Runtime.getRuntime().exec(shellCmd.command)
            true
        } catch (e: Exception) {
            false
        }
    }
}

