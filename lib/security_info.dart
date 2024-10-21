// You have generated a new plugin project without specifying the `--platforms`
// flag. A plugin project with no platform support was generated. To add a
// platform, run `flutter create -t plugin --platforms <platforms> .` under the
// same directory. You can also find a detailed instruction on how to add
// platforms in the `pubspec.yaml` at
// https://flutter.dev/to/pubspec-plugin-platforms.

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
}
