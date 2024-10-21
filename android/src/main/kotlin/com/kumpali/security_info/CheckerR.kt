package com.kumpali.security_info

import android.app.ActivityManager
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import java.io.File

class CheckerR {

    private lateinit var pm: PackageManager
    private lateinit var manager: ActivityManager

    fun checkRootMethod0(): Boolean {
        val buildTags = Build.TAGS
        return buildTags != null && buildTags.contains("test-keys")
    }

    fun checkRootMethod1(): Boolean {
        return try {
            val file = File("/system/app/Superuser.apk")
            file.exists()
        } catch (e: Exception) {
            false
        }
    }

    fun checkRootMethod2(): Boolean {
        val result = ShellEx().executeCommand(ShellEx.SHELL_CMD.CHECK_SU_BINARY)
        return result != null
    }

    fun checkRootMethod3(): Boolean {
        return try {
            val file = File("/system/xbin/su")
            file.exists()
        } catch (e: Exception) {
            false
        }
    }

    fun checkRootMethod4(): Boolean {
        return try {
            val file = File("/system/bin/su")
            file.exists()
        } catch (e: Exception) {
            false
        }
    }

    fun checkRootMethod5(): Boolean {
        val packages: List<ApplicationInfo> = pm.getInstalledApplications(PackageManager.GET_META_DATA)

        for (packageInfo in packages) {
            if (packageInfo.packageName.contains("supersu") || packageInfo.packageName.contains("superuser")) {
                return true
            }
        }

        return false
    }

    fun checkRootMethod7(): Boolean {
        val result = ShellEx().executeCommand(ShellEx.SHELL_CMD.CHECK_DAEMON_SU)
        if (result != null) {
            for (tempString in result) {
                if (tempString.contains("daemonsu")) return true
            }
        }
        return false
    }

    fun checkRootMethod8(): Boolean {
        return ShellEx().executeCommandSU(ShellEx.SHELL_CMD.RUN_SU)
    }

    fun checkRootMethod9(): Boolean {
        val result = ShellEx().executeCommand(ShellEx.SHELL_CMD.CHECK_SU)
        if (result != null) {
            for (tempString in result) {
                if (tempString.endsWith("su")) return true
            }
        }
        return false
    }
}

