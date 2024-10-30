package com.kumpali.security_info

import android.Manifest
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.SharedPreferences
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.hardware.fingerprint.FingerprintManager
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
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Log
import android.widget.Toast
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.core.app.ActivityCompat
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.google.crypto.tink.Aead
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.aead.AeadKeyTemplates
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import com.google.crypto.tink.subtle.Base64
import com.kumpali.security_info.utils.Pbkdf2Factory
import com.kumpali.security_info.utils.Salt
import com.kumpali.security_info.utils.StorageKey
import java.security.KeyStore
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import androidx.core.content.ContextCompat
import javax.crypto.spec.GCMParameterSpec
import java.util.Base64 as b
import kotlin.Boolean

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
    private val ANDROID_KEYSTORE = "AndroidKeyStore"
    private lateinit var sharedPreferences: SharedPreferences
    private lateinit var aead: Aead

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
        sharedPreferences = createEncryptedSharedPreferences(context)
        aead = getKeyHandle()
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
                    if (checkRootMethod7() || checkRootMethod8() || checkRootMethod9()) {
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
            } else if (call.method == "isOnExternalStorage") {
                result.success(isOnExternalStorage())
            } else if (call.method == "isMockLocationEnabled") {
                result.success(isMockLocationEnabled())
            } else if (call.method == "hasHardwareSecurity") {
                result.success(hasHardwareSecurity())
            } else if (call.method == "hasStrongBox") {
                result.success(hasStrongBox())
            } else if (call.method == "generateSecureKey") {
                val alias: String = call.argument<String>("alias").toString()
                result.success(generateSecureKey(alias).toString())
            } else if (call.method == "deleteKey") {
                val alias: String = call.argument<String>("alias").toString()
                result.success(deleteKey(alias))
            } else if (call.method == "saveData") {
                val alias: String = call.argument<String>("alias").toString()
                val pin: String = call.argument<String>("pin").toString()
                val key: String = call.argument<String>("key").toString()
                val plainText: String = call.argument<String>("plainText").toString()
                result.success(saveData(alias, pin, key, plainText))
            } else if (call.method == "savePin") {
                val pin: String = call.argument<String>("pin").toString()
                result.success(savePin(pin))
            }
//         else if (call.method == "encrypterDecrypter") {
//                val data: String = call.argument<String>("data").toString()
//            result.success(encrypterDecrypter(data))
//        }
        else if (call.method == "getData") {
                val alias: String = call.argument<String>("alias").toString()
                val pin: String = call.argument<String>("pin").toString()
                val key: String = call.argument<String>("key").toString()
                result.success(getData(alias, pin, key))
            } else {
                result.notImplemented()
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun getEnrolledFingerprints(context: Context): Boolean {
        val fingerprintManager =
            ContextCompat.getSystemService(context, FingerprintManager::class.java)
        fingerprintManager?.let {
            return it.hasEnrolledFingerprints()
        }
        return false
    }

    private fun generateSecureKey(alias: String): SecretKey? {
        val packageManager = context.packageManager
        val keyGenParameterSpecBuilder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            keyGenParameterSpecBuilder.setUnlockedDeviceRequired(true)
        }

        if ((packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT))) {
            val biometricManager = BiometricManager.from(context)
            if (biometricManager.canAuthenticate(BIOMETRIC_STRONG or DEVICE_CREDENTIAL) == BiometricManager.BIOMETRIC_SUCCESS) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    if (packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
                        keyGenParameterSpecBuilder.setIsStrongBoxBacked(true)
                    }
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    keyGenParameterSpecBuilder.setInvalidatedByBiometricEnrollment(true)
                }
            } else if (biometricManager.canAuthenticate(BIOMETRIC_STRONG or DEVICE_CREDENTIAL or BIOMETRIC_WEAK) == BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED) {
                // Prompt the user to create credentials
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    val enrollIntent = Intent(Settings.ACTION_BIOMETRIC_ENROLL).apply {
                        putExtra(
                            Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED,
                            BIOMETRIC_STRONG or DEVICE_CREDENTIAL
                        )
                    }
                    context.startActivity(enrollIntent)
                }
            }
        }
        val hasEnrolledFingerprints = getEnrolledFingerprints(context)
        if (hasEnrolledFingerprints) {
            keyGenParameterSpecBuilder.setUserAuthenticationRequired(true)
        }
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )
        try {
            keyGenerator.init(keyGenParameterSpecBuilder.build())
            return keyGenerator.generateKey()
        } catch (e: Exception) {
            Log.e("KeyGen", "Error generating key", e)
            // Fall back to TEE if StrongBox is not available
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                try {
                    keyGenParameterSpecBuilder.setIsStrongBoxBacked(false)
                    keyGenerator.init(keyGenParameterSpecBuilder.build())
                    return keyGenerator.generateKey()
                } catch (ex: Exception) {
                    Log.e("KeyGen", "Error generating key with TEE fallback", ex)
                    Toast.makeText(
                        context,
                        "Error generating key: ${ex.message}",
                        Toast.LENGTH_SHORT
                    ).show()
                }
            }
        }
        return keyGenerator.generateKey()
    }

    private fun getSecretKey(alias: String): SecretKey? {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return keyStore.getKey(alias, null) as? SecretKey
    }

    fun deleteKey(alias: String) {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        keyStore.deleteEntry(alias)
    }

    //    private fun getCipher(): Cipher {
    //        return Cipher.getInstance(
    //            KeyProperties.KEY_ALGORITHM_AES + "/"
    //                    + KeyProperties.BLOCK_MODE_GCM + "/"
    //                    + KeyProperties.ENCRYPTION_PADDING_NONE
    //        )
    //    }

    fun createEncryptedSharedPreferences(context: Context): SharedPreferences {
        val masterKeyAlias =
            MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
        return EncryptedSharedPreferences.create(
            context,
            "EncryptedSharedPreferences",
            masterKeyAlias,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    private fun getKeyHandle(): Aead {
        val keysetName = "pin_secured_keyset"
        val prefFileName = "pin_secured_key_preference"
        val masterKeyUri = "android-keystore://pin_secured_key"

        val keysetHandle = AndroidKeysetManager.Builder()
            .withSharedPref(
                context,
                keysetName,
                prefFileName
            )
            .withKeyTemplate(AeadKeyTemplates.AES256_GCM)
            .withMasterKeyUri(masterKeyUri)
            .build()
            .keysetHandle
        AeadConfig.register()
        return keysetHandle.getPrimitive(Aead::class.java)
    }


    private fun getSalt(): ByteArray? {
        return Base64.decode(sharedPreferences.getString(StorageKey.SALT, null))
    }


    private fun pinIsValid(pin: String): Boolean {
        val encodedSalt = sharedPreferences.getString(StorageKey.SALT, null)
        val encodedPin = sharedPreferences.getString(StorageKey.PIN, null)

        val salt = Base64.decode(encodedSalt, Base64.DEFAULT)
        val storedPin = Base64.decode(encodedPin, Base64.DEFAULT)

        val enteredPin = Pbkdf2Factory.createKey(pin.toCharArray(), salt)
        return storedPin contentEquals enteredPin.encoded
    }

    private fun savePin(pin: String): Boolean {
        try {
            val salt = Salt.generate()
            val secretKey = Pbkdf2Factory.createKey(pin.toCharArray(), salt)
            val encodedKey = Base64.encodeToString(secretKey.encoded, Base64.DEFAULT)
            val encodedSalt = Base64.encodeToString(salt, Base64.DEFAULT)

            sharedPreferences.edit()
                .putString(StorageKey.PIN, encodedKey)
                .putString(StorageKey.SALT, encodedSalt)
                .putBoolean(StorageKey.PIN_IS_ENABLED, true)
                .apply()
            return true
        } catch (e: Exception) {
            return false
        }
    }
//
//    private fun encryptData(alias: String, data: ByteArray): ByteArray {
//        val secretKey = getSecretKey(alias)
//        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
//        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
//        val iv = cipher.iv
//        val encryptedData = cipher.doFinal(data)
//        return iv + encryptedData // Prepend IV to the encrypted data
//    }
//
//    private fun decryptData(alias: String, encryptedData: ByteArray): String {
//        val secretKey = getSecretKey(alias)
//        val iv = encryptedData.copyOfRange(0, 12) // First 12 bytes are the IV
//        val data = encryptedData.copyOfRange(12, encryptedData.size)
//        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
//        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
//        val decrypted = String(cipher.doFinal(data), Charsets.UTF_8)
//        return decrypted
//    }

    private fun saveData(alias: String, pin: String, key: String, plainText: String): Boolean {
        try {
            if (pinIsValid(pin)) {
                val encryptedData = encrypt(alias, plainText)
                val salt = getSalt()
                if (salt != null) {
                    val secretKey = Pbkdf2Factory.createKey(pin.toCharArray(), salt)
                    val encryptedToken = aead.encrypt(encryptedData.toByteArray(Charsets.UTF_8), secretKey.encoded)
                    val encryptedBase64Token = Base64.encodeToString(encryptedToken, Base64.DEFAULT)
                    sharedPreferences.edit()
                        .putString(key, encryptedBase64Token)
                        .apply()
                    return true
                }
            }
            return false
        } catch (e: Exception) {
            return false
        }
    }

    private fun getData(alias: String, pin: String, key: String): String? {
        if (pinIsValid(pin)) {
            val encryptedData = sharedPreferences.getString(key, null)
            if (encryptedData != null) {
                val decodedData = Base64.decode(encryptedData, Base64.DEFAULT)
                val salt = getSalt()
                if (salt != null) {
                    val secretKey = Pbkdf2Factory.createKey(pin.toCharArray(), salt)
                    val bytes = aead.decrypt(decodedData, secretKey.encoded)
                    val d = decrypt(alias, String(bytes, Charsets.UTF_8))
                    return d
                }
            }
        }
        return null
    }

//    private fun encrypterDecrypter(data: String):String {
//        // Generate key
////        val keyGen = KeyGenerator.getInstance("AES")
////        keyGen.init(256)
////        val secretKey = keyGen.generateKey()
//
//        // Define the plaintext with Unicode characters
////        val plainText = "Sensitive data with Unicode characters: !@#\$%^&*()_+äöüß"
//
//        // Encrypt
//        val cipherText = encrypt("summy",data,)
//        println("Encrypted: $cipherText")
//
//        // Decrypt
//        val decryptedText = decrypt("summy",cipherText,)
//        println("Decrypted: $decryptedText")
//        return decryptedText
//    }

    fun encrypt(alias: String, plainText: String): String {
        //        val secretKey = getSecretKey(alias)
//        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
//        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
//        val iv = cipher.iv
//        val encryptedData = cipher.doFinal(data)
//        return iv + encryptedData // Prepend IV to the encrypted data
        val secretKey = getSecretKey(alias)
//        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
//        val iv = ByteArray(16)

//        SecureRandom().nextBytes(iv)
//        val ivSpec = IvParameterSpec(iv)
//        val spec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv
        val cipherText = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))

//        val cipherTextWithIv = ByteArray(iv.size + cipherText.size)
//        System.arraycopy(iv, 0, cipherTextWithIv, 0, iv.size)
//        System.arraycopy(cipherText, 0, cipherTextWithIv, iv.size, cipherText.size)
        val cipherTextWithIv = iv + cipherText
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            b.getEncoder().encodeToString(cipherTextWithIv)
        } else {
            Base64.encodeToString(cipherTextWithIv, Base64.DEFAULT)
        }
    }

    fun decrypt(alias:String, cipherText: String): String {
        val secretKey = getSecretKey(alias)
        val cipherTextWithIv = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            b.getDecoder().decode(cipherText)
        } else {
            Base64.decode(cipherText, Base64.DEFAULT)
        }

        val iv = cipherTextWithIv.copyOfRange(0, 12)
        val cipherBytes = cipherTextWithIv.copyOfRange(12, cipherTextWithIv.size)

//        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
//        val ivSpec = IvParameterSpec(iv)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)

        val plainTextBytes = cipher.doFinal(cipherBytes)
        return String(plainTextBytes, Charsets.UTF_8)
    }


    fun hasHardwareSecurity() = keyGeneratorGeneric(
        UUID.randomUUID().toString()
    ).generateKey().run {
        val keyInfo = SecretKeyFactory.getInstance(algorithm)
            .getKeySpec(this, KeyInfo::class.java) as KeyInfo
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            .deleteEntry(keyInfo.keystoreAlias)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
            when (keyInfo.securityLevel) {
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> true

                else -> false
            }
        else keyInfo.isInsideSecureHardware
    }

    fun hasStrongBox() = try {
        val alias = UUID.randomUUID().toString()
        keyGeneratorStrongBox(alias).generateKey()
        KeyStore.getInstance(ANDROID_KEYSTORE)
            .apply { load(null) }
            .deleteEntry(alias)
        true
    } catch (exception: Exception) {
        false
    }


    private fun keyGeneratorGeneric(alias: String) =
        KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE
        ).apply {
            init(
                KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                ).run {
                    setKeySize(256)
                    setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    build()
                }
            )
        }


    private fun keyGeneratorStrongBox(alias: String) =
        KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE
        ).apply {
            init(
                KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                ).run {
                    setKeySize(256)
                    setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        setIsStrongBoxBacked(true)
                    }
                    build()
                }
            )
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
            Toast.makeText(context, e.toString(), Toast.LENGTH_SHORT).show()
        }

        try {
            val filesDir: String = context.filesDir.absolutePath
            return when {
                filesDir.startsWith("/data/") -> false
                filesDir.contains("/mnt/") || filesDir.contains(Environment.getExternalStorageDirectory().path) -> true
                else -> null
            }
        } catch (e: Throwable) {
            Toast.makeText(context, e.toString(), Toast.LENGTH_SHORT).show()
        }
        return false
    }

    fun isMockLocationEnabled(): Boolean {
        val locationManager = context.getSystemService(Context.LOCATION_SERVICE) as LocationManager
        val location = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            if (ActivityCompat.checkSelfPermission(
                    context,
                    Manifest.permission.ACCESS_FINE_LOCATION
                ) != PackageManager.PERMISSION_GRANTED && ActivityCompat.checkSelfPermission(
                    context,
                    Manifest.permission.ACCESS_COARSE_LOCATION
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                Toast.makeText(context, "Permission not granted", Toast.LENGTH_SHORT).show()
            }
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
