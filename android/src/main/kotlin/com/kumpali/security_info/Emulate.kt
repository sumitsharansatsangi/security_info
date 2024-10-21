package com.kumpali.security_info

import android.annotation.SuppressLint
import android.os.Build
import java.io.File

object Emulate {

    private val paths = listOf(
        "/dev/socket/genyd",
        "/dev/socket/baseband_genyd",
        "/dev/socket/qemud",
        "/dev/qemu_pipe",
        "ueventd.android_x86.rc",
        "x86.prop",
        "ueventd.ttVM_x86.rc",
        "init.ttVM_x86.rc",
        "fstab.ttVM_x86",
        "fstab.vbox86",
        "init.vbox86.rc",
        "ueventd.vbox86.rc",
        "fstab.andy",
        "ueventd.andy.rc",
        "fstab.nox",
        "init.nox.rc",
        "ueventd.nox.rc"
    )

    fun isEmulator(): Boolean {
        val knownEmulatorKeywords = listOf(
            "generic", "unknown", "google_sdk", "Emulator", "Android SDK built for x86",
            "Genymotion", "waydroid", "bluestacks", "nox", "ldplayer", "memu", "anbox",
            "android_x86", "droid4x", "andy", "koplayer", "windroy", "sdk_gphone",
            "ranchu", "goldfish", "vbox86", "simulator", "qemu"
        )
//        val props = listOf(
//            "ro.kernel.qemu",          // 1 if running in emulator, 0 otherwise
//            "ro.hardware",
//            "ro.product.device",
//            "ro.product.model",
//            "ro.product.brand",
//            "ro.product.manufacturer"
//        )
        return (Build.FINGERPRINT.startsWith("generic") ||
                Build.FINGERPRINT.contains("unknown") ||
                knownEmulatorKeywords.any { keyword ->
                    Build.MODEL.contains(keyword, ignoreCase = true) ||
                            Build.MANUFACTURER.contains(keyword, ignoreCase = true) ||
                            Build.BRAND.contains(keyword, ignoreCase = true) ||
                            Build.DEVICE.contains(keyword, ignoreCase = true) ||
                            Build.PRODUCT.contains(keyword, ignoreCase = true) ||
                            Build.HARDWARE.contains(keyword, ignoreCase = true) ||
                            Build.HOST.contains(keyword, ignoreCase = true)
                } ||
                getSystemProperty() =="1" ||
                Build.HARDWARE.contains("ranchu") ||
                Build.HARDWARE.contains("goldfish") ||
                Build.HOST.contains("qemu") ||
                Build.HOST.contains("localhost") ||
                Build.BOARD.contains("QC_Reference_Phone", ignoreCase = true) ||
                Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"))
    }

    @SuppressLint("PrivateApi")
    fun getSystemProperty(): String? {
        return try {
            val clazz = Class.forName("android.os.SystemProperties")
            val method = clazz.getMethod("get", String::class.java)
            method.invoke(clazz, "ro.kernel.qemu") as String
        } catch (e: Exception) {
            null
        }
    }

    fun isEmulator2(): Boolean {
        return try {
            for (path in paths) {
                val file = File(path)
                if (file.exists()) {
                    return true
                }
            }
            false
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }
}

