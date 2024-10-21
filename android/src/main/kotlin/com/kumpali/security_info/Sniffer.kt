package com.kumpali.security_info

import android.app.Service
import android.content.Intent
import android.os.IBinder
import java.io.BufferedReader
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.InputStreamReader

class Sniffer : Service() {

    private val blackListedMountPaths = arrayOf("magisk", "core/mirror", "core/img")

    override fun onBind(intent: Intent?): IBinder {
        return mBinder
    }

    private val mBinder = object : IIsolatedService.Stub() {
        override fun isMagiskPresent(): Boolean {
            var isMagiskPresent = false
            val file = File("/proc/self/mounts")

            try {
                val fis = FileInputStream(file)
                val reader = BufferedReader(InputStreamReader(fis))
                var str: String?
                var count = 0
                while (reader.readLine().also { str = it } != null && count == 0) {
                    for (path in blackListedMountPaths) {
                        if (str!!.contains(path)) {
                            count++
                            break
                        }
                    }
                }
                reader.close()
                fis.close()
                isMagiskPresent = count > 0 || Native.isMagiskPresentNative()
            } catch (e: IOException) {
                e.printStackTrace()
            }
            return isMagiskPresent
        }
    }
}

