package com.kumpali.security_info

import android.app.ZygotePreload
import android.content.pm.ApplicationInfo
import android.os.Build
import androidx.annotation.RequiresApi

@RequiresApi(Build.VERSION_CODES.Q)
class AppZygotePreload : ZygotePreload {
    override fun doPreload(appInfo: ApplicationInfo) {
        System.loadLibrary("native-lib")
    }
}

