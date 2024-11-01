import 'security_info_platform_interface.dart';

class SecurityInfo {
  static Future<bool?> amICompromised() async {
    return await SecurityInfoPlatform.instance.amICompromised();
  }

  static Future<bool?> amIEmulator() async {
    return await SecurityInfoPlatform.instance.amIEmulator();
  }

  static Future<bool?> amIDebugged() async {
    return await SecurityInfoPlatform.instance.amIDebugged();
  }

  static Future<bool?> isDeveloperMode() async {
    return await SecurityInfoPlatform.instance.isDeveloperMode();
  }

  static Future<bool?> isUsbDebugging() async {
    return await SecurityInfoPlatform.instance.isUsbDebugging();
  }

  static Future<bool?> isOnExternalStorage() async {
    return await SecurityInfoPlatform.instance.isOnExternalStorage();
  }

  static Future<bool?> isMockLocationEnabled() async {
    return await SecurityInfoPlatform.instance.isMockLocationEnabled();
  }

  static Future<bool?> hasHardwareSecurity() async {
    return await SecurityInfoPlatform.instance.hasHardwareSecurity();
  }

  static Future<bool?> hasStrongBox() async {
    return await SecurityInfoPlatform.instance.hasStrongBox();
  }

  // static Future<String?> getSecureKey(String alias) async {
  //   return await SecurityInfoPlatform.instance.getSecureKey(alias);
  // }

  static Future<String?> generateSecureKey(String alias) async {
    return await SecurityInfoPlatform.instance.generateSecureKey(alias);
  }

  static Future<bool?> savePin(String pin) async {
    return await SecurityInfoPlatform.instance.savePin(pin);
  }

  static Future<bool?> saveData(
      String alias, String pin, String key, String plainText) async {
    return await SecurityInfoPlatform.instance
        .saveData(alias, pin, key, plainText);
  }

  //  static Future<String?> encrpterDecrypter(String data) async {
  //   return await SecurityInfoPlatform.instance.encrypterDecrypter(data);
  // }

  // static Future<bool?> saveBoolean(
  //     String alias, String pin, String key, bool data) async {
  //   return await SecurityInfoPlatform.instance
  //       .saveBoolean(alias, pin, key, data);
  // }

  // static Future<bool?> saveInteger(
  //     String alias, String pin, String key, int data) async {
  //   return await SecurityInfoPlatform.instance
  //       .saveInteger(alias, pin, key, data);
  // }

  // static Future<bool?> saveDouble(
  //     String alias, String pin, String key, double data) async {
  //   return await SecurityInfoPlatform.instance
  //       .saveDouble(alias, pin, key, data);
  // }

  static Future<String?> getData(String alias, String pin, String key) async {
    return await SecurityInfoPlatform.instance.getData(alias, pin, key);
  }

  // static Future<bool?> getBoolean(String alias, String pin, String key) async {
  //   return await SecurityInfoPlatform.instance.getBoolean(alias, pin, key);
  // }
  //spa1468tyty

  // static Future<int?> getInteger(String alias, String pin, String key) async {
  //   return await SecurityInfoPlatform.instance.getInteger(alias, pin, key);
  // }

  // static Future<double?> getDouble(String alias, String pin, String key) async {
  //   return await SecurityInfoPlatform.instance.getDouble(alias, pin, key);
  // }

  // static Future<int?> testENC() async {
  //   return await SecurityInfoPlatform.instance.testENC();
  // }
}
