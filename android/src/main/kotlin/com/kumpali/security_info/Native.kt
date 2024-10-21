package com.kumpali.security_info

object Native {

    init {
        System.loadLibrary("native-lib")
    }

    external fun isMagiskPresentNative(): Boolean
    external fun AntiFridaNativeLoader_checkFridaByPort(): Boolean
}

