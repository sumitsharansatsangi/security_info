package com.kumpali.security_info

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.location.LocationManager
import android.os.Build
import android.os.Environment
import android.os.IBinder
import android.os.RemoteException
import android.provider.Settings
import com.kumpali.security_info.Constdata.superUserPath
import com.kumpali.security_info.Native.AntiFridaNativeLoader_checkFridaByPort
import com.kumpali.security_info.Native.isMagiskPresentNative
import com.scottyab.rootbeer.RootBeer
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.io.BufferedReader
import java.io.File
import java.io.FileInputStream
import java.io.InputStreamReader
import java.util.Scanner

/** SecurityInfoPlugin */
class SecurityInfoPlugin : FlutterPlugin, MethodCallHandler {
    /// The MethodChannel that will the communication between Flutter and native Android
    ///
    /// This local reference serves to register the plugin with the Flutter Engine and unregister it
    /// when the Flutter Engine is detached from the Activity
    private lateinit var channel: MethodChannel
    private val PLATFORM_CHANNEL = "security_info"
    private lateinit var context: Context
    private var bServiceBound: Boolean = false
    private lateinit var serviceBinder: IIsolatedService
    private val ONEPLUS = "oneplus"
    private val MOTO = "moto"
    private val XIAOMI = "Xiaomi"


    override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, PLATFORM_CHANNEL)
        channel.setMethodCallHandler(this)
        context = flutterPluginBinding.applicationContext
        val intent = Intent(context.applicationContext, Sniffer::class.java)
        context.applicationContext.bindService(
            intent,
            mIsolatedServiceConnection,
            Context.BIND_AUTO_CREATE
        )
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        try {
            val intent = Intent(context.applicationContext, Sniffer::class.java)
            context.applicationContext.bindService(
                intent,
                mIsolatedServiceConnection,
                Context.BIND_AUTO_CREATE
            )

            if (call.method == "runprog") {
                var detected = false
                val rootBeer = RootBeer(context)

                if (Build.BRAND.contains(ONEPLUS) || Build.BRAND.contains(MOTO) || Build.BRAND.contains(
                        XIAOMI
                    )
                ) {
                    if (rootBeer.isRooted) {
                        detected = true
                    }
                } else {
                    if (rootBeer.isRootedWithBusyBoxCheck) {
                        detected = true
                    }
                }

                try {
                    if (isPathExist("su") ||
                        isSUExist() ||
                        isTestBuildKey() ||
                        isHaveRootHideApps() ||
                        isHaveDangerousApps() ||
                        isHaveRootManagementApps() ||
                        isHaveDangerousProperties() ||
                        isHaveReadWritePermission()
                    ) {
                        detected = true
                    }
                } catch (e: Exception) {
                    e.printStackTrace()
                }

                try {
                    if (checkRootMethod8() || checkRootMethod9()) {
                        detected = true
                    }
                } catch (e: Exception) {
                    e.printStackTrace()
                }

                result.success(detected)

            } else if (call.method == "runprog2") {
                var detected = false

                if (Emulate.isEmulator() || Emulate.isEmulator2()) {
                    detected = true
                }

                result.success(detected)
            } else if (call.method == "runprog3") {
                result.success(
                    Settings.Secure.getInt(
                        context.contentResolver,
                        Settings.Global.ADB_ENABLED,
                        0
                    ) == 1 || AntiFridaNativeLoader_checkFridaByPort()
                )
            } else if (call.method == "runprog4") {
                var detected = false
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    try {
                        if (bServiceBound) {
                            detected = serviceBinder.isMagiskPresent()
                        }
                    } catch (e: RemoteException) {
                        throw RuntimeException(e)
                    }
                } else {
                    detected = isMagisk()
                }

                result.success(detected)
            } else if (call.method == "isDeveloperMode") {
                result.success(isDeveloperMode())
            } else if (call.method == "isUSBDebugging") {
                result.success(isUSBDebugging())
            }
            else if (call.method == "isOnExternalStorage") {
                result.success(isOnExternalStorage())
            } else if (call.method == "isMockLocationEnabled") {
                result.success(isMockLocationEnabled())
            }
            else {
                result.notImplemented()
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun isDeveloperMode(): Boolean {
        return Settings.Global.getInt(
            context.contentResolver,
            Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0
        ) != 0
    }

    private fun isUSBDebugging(): Boolean {
        return Settings.Global.getInt(
            context.contentResolver,
            Settings.Global.ADB_ENABLED, 0
        ) != 0
    }


    private fun isOnExternalStorage(): Boolean? {
        val pm = context.packageManager
        try {
            val pi = pm.getPackageInfo(context.packageName, 0)
            val ai = pi.applicationInfo
            return ai?.flags?.and(ApplicationInfo.FLAG_EXTERNAL_STORAGE) == ApplicationInfo.FLAG_EXTERNAL_STORAGE
        } catch (e: PackageManager.NameNotFoundException) {
            // ignore
        }

        try {
            val filesDir: String = context.filesDir.absolutePath
            return when {
                filesDir.startsWith("/data/") -> false
                filesDir.contains("/mnt/") || filesDir.contains(Environment.getExternalStorageDirectory().path) -> true
                else -> null
            }
        } catch (e: Throwable) {
            // ignore
        }
        return false
    }

    fun isMockLocationEnabled(): Boolean {
        val locationManager = context.getSystemService(Context.LOCATION_SERVICE) as LocationManager
        val location = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            locationManager.getLastKnownLocation(LocationManager.FUSED_PROVIDER)
        } else {
            locationManager.getLastKnownLocation(LocationManager.GPS_PROVIDER)
        }
        return when {
            location == null -> false
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> location.isMock
            else -> location.isFromMockProvider
        }
    }

    private fun isMagisk(): Boolean {
        var isMagiskPresent = false

        try {
            val blackListedMountPaths = arrayOf(
                "magisk", "core/mirror", "core/img",
                "/su/bin/",
                "/system/bin/failsafe/",
                "/system/usr/we-need-root/",
                "/su"
            )

            val file = File("/proc/self/mounts")
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

            if (count > 0) {
                isMagiskPresent = true
            }
            if (count > 0) {
                isMagiskPresent = isMagiskPresentNative()
            }

        } catch (e: Exception) {
            // ignore
        }
        return isMagiskPresent
    }

    private val mIsolatedServiceConnection = object : ServiceConnection {
        override fun onServiceConnected(componentName: ComponentName, iBinder: IBinder) {
            serviceBinder = IIsolatedService.Stub.asInterface(iBinder)
            bServiceBound = true
        }

        override fun onServiceDisconnected(componentName: ComponentName) {
            bServiceBound = false
        }
    }

    private fun isPathExist(ext: String): Boolean {
        for (path in superUserPath) {
            val file = File(path, ext)
            if (file.exists()) {
                return true
            }
        }
        return false
    }

    private fun isSUExist(): Boolean {
        var process: Process? = null
        return try {
            process = Runtime.getRuntime().exec(arrayOf("/system/xbin/which", "su"))
            val inReader = BufferedReader(InputStreamReader(process.inputStream))
            inReader.readLine() != null
        } catch (e: Exception) {
            false
        } finally {
            process?.destroy()
        }
    }

    private fun isTestBuildKey(): Boolean {
        val buildTags = Build.TAGS
        return buildTags != null && buildTags.contains("test-keys")
    }

    private fun isHaveDangerousApps(): Boolean {
        val packages = ArrayList<String>().apply {
            addAll(Constdata.dangerousListApps.toList())
        }
        return isAnyPackageFromListInstalled(packages)
    }

    private fun isHaveRootManagementApps(): Boolean {
        val packages = ArrayList<String>().apply {
            addAll(Constdata.rootsAppPackage.toList())
        }
        return isAnyPackageFromListInstalled(packages)
    }

    private fun isHaveRootHideApps(): Boolean {
        val packages = ArrayList<String>().apply {
            addAll(Constdata.rootCloakingApps.toList())
        }
        return isAnyPackageFromListInstalled(packages)
    }

    //check dangerous properties
    private fun isHaveDangerousProperties(): Boolean {
        val dangerousProps = mapOf(
            "ro.debuggable" to "1",
            "ro.secure" to "0"
        )

        var result = false
        val lines = commander("getprop") ?: return false
        for (line in lines) {
            for ((key, badValue) in dangerousProps) {
                if (line.contains(key)) {
                    val formattedBadValue = "[$badValue]"
                    if (line.contains(formattedBadValue)) {
                        result = true
                    }
                }
            }
        }
        return result
    }

    private fun isHaveReadWritePermission(): Boolean {
        var result = false
        val lines = commander("mount")
        if (lines != null) {
            for (line in lines) {
                val args = line.split(" ")
                if (args.size < 4) {
                    continue
                }
                val mountPoint = args[1]
                val mountOptions = args[3]

                for (path in Constdata.notWritablePath) {
                    if (mountPoint.equals(path, ignoreCase = true)) {
                        for (opt in mountOptions.split(",")) {
                            if (opt.equals("rw", ignoreCase = true)) {
                                result = true
                                break
                            }
                        }
                    }
                }
            }
        }

        return result
    }


    private fun commander(command: String): Array<String>? {
        return try {
            val inputStream = Runtime.getRuntime().exec(command).inputStream
            inputStream?.let {
                val propVal = Scanner(it).useDelimiter("\\A").next()
                propVal.split("\n").toTypedArray()
            }
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    private fun isAnyPackageFromListInstalled(pkg: ArrayList<String>): Boolean {
        val pm = context.packageManager
        for (packageName in pkg) {
            try {
                pm.getPackageInfo(packageName, 0)
                return true
            } catch (e: Exception) {
                // Ignored
            }
        }
        return false
    }

    fun checkRootMethod7(): Boolean {
        val result = ShellEx().executeCommand(ShellEx.SHELL_CMD.CHECK_DAEMON_SU)
        result?.let {
            for (tempString in it) {
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
        result?.let {
            for (tempString in it) {
                if (tempString.endsWith("su")) return true
            }
        }
        return false
    }


    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }
}
