import 'dart:typed_data';

import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'security_info_method_channel.dart';

abstract class SecurityInfoPlatform extends PlatformInterface {
  /// Constructs a SecurityInfoPlatform.
  SecurityInfoPlatform() : super(token: _token);

  static final Object _token = Object();

  static SecurityInfoPlatform _instance = MethodChannelSecurityInfo();

  /// The default instance of [SecurityInfoPlatform] to use.
  ///
  /// Defaults to [MethodChannelSecurityInfo].
  static SecurityInfoPlatform get instance => _instance;

  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [SecurityInfoPlatform] when
  /// they register themselves.
  static set instance(SecurityInfoPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<bool?> amICompromised() async {
    throw UnimplementedError('amICompromised() has not been implemented.');
  }

  Future<bool?> amIEmulator() async {
    throw UnimplementedError('amIEmulator() has not been implemented.');
  }

  Future<bool?> amIDebugged() async {
    throw UnimplementedError('amIDebugged() has not been implemented.');
  }

  Future<bool?> isDeveloperMode() async {
    throw UnimplementedError('isDeveloperMode() has not been implemented.');
  }

  Future<bool?> isUsbDebugging() async {
    throw UnimplementedError('isUSBDebugging() has not been implemented.');
  }

  Future<bool?> isOnExternalStorage() async {
    throw UnimplementedError('isOnExternalStorage() has not been implemented.');
  }

  Future<bool?> isMockLocationEnabled() async {
    throw UnimplementedError(
        'isMockLocationEnabled() has not been implemented.');
  }

  Future<String?> generateSecureKey(String alias) async {
    throw UnimplementedError('generateSecureKey() has not been implemented.');
  }

  // Future<String?> getSecureKey(String alias) async {
  //   throw UnimplementedError('getSecureKey() has not been implemented.');
  // }

  Future<bool?> hasHardwareSecurity() async {
    throw UnimplementedError('hasHardwareSecurity() has not been implemented.');
  }

  Future<bool?> hasStrongBox() async {
    throw UnimplementedError('hasStrongBox() has not been implemented.');
  }

  Future<bool?> savePin(String pin) async {
    throw UnimplementedError('savePin() has not been implemented.');
  }

  Future<bool?> saveData(
      String alias, String pin, String key, Uint8List data) async {
    throw UnimplementedError('saveData() has not been implemented.');
  }

  Future<String?> getData(String alias, String pin, String key) async {
    throw UnimplementedError('getData() has not been implemented.');
  }

  // Future<bool?> saveBoolean(
  //     String alias, String pin, String key, bool data) async {
  //   throw UnimplementedError('saveBoolean() has not been implemented.');
  // }

  // Future<bool?> saveInteger(
  //     String alias, String pin, String key, int data) async {
  //   throw UnimplementedError('saveInteger() has not been implemented.');
  // }

  // Future<bool?> saveDouble(
  //     String alias, String pin, String key, double data) async {
  //   throw UnimplementedError('saveDouble() has not been implemented.');
  // }

  // Future<bool?> getBoolean(String alias, String pin, String key) async {
  //   throw UnimplementedError('getBoolean() has not been implemented.');
  // }

  // Future<int?> getInteger(String alias, String pin, String key) async {
  //   throw UnimplementedError('getInteger() has not been implemented.');
  // }

  // Future<double?> getDouble(String alias, String pin, String key) async {
  //   throw UnimplementedError('getDouble() has not been implemented.');
  // }

  // Future<int?> testENC() async {
  //   throw UnimplementedError('testENC() has not been implemented.');
  // }
}
