import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
// import 'package:security_info/security_info.dart';
import 'package:security_info/security_info_platform_interface.dart';
import 'package:security_info/security_info_method_channel.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockSecurityInfoPlatform
    with MockPlatformInterfaceMixin
    implements SecurityInfoPlatform {
  @override
  Future<bool?> amICompromised() {
    throw UnimplementedError();
  }

  @override
  Future<bool?> amIEmulator() {
    throw UnimplementedError();
  }

  @override
  Future<bool?> amIDebugged() {
    throw UnimplementedError();
  }

  @override
  Future<bool?> isDeveloperMode() {
    throw UnimplementedError();
  }

  @override
  Future<bool?> isUsbDebugging() {
    throw UnimplementedError();
  }

  @override
  Future<bool?> isMockLocationEnabled() {
    throw UnimplementedError();
  }

  @override
  Future<bool?> isOnExternalStorage() {
    throw UnimplementedError();
  }

  // @override
  // Future<String?> getSecureKey(String alias) {
  //   throw UnimplementedError();
  // }

  @override
  Future<String?> generateSecureKey(String alias) {
    throw UnimplementedError();
  }

  @override
  Future<bool?> hasStrongBox() {
    throw UnimplementedError();
  }

  @override
  Future<bool?> hasHardwareSecurity() {
    throw UnimplementedError();
  }

  @override
  Future<bool?> savePin(String pin) {
    throw UnimplementedError();
  }

  // @override
  // Future<bool?> saveBoolean(String alias, String pin, String key, bool data) {
  //   throw UnimplementedError();
  // }

  // @override
  // Future<bool?> saveDouble(String alias, String pin, String key, double data) {
  //   throw UnimplementedError();
  // }

  // @override
  // Future<bool?> saveInteger(String alias, String pin, String key, int data) {
  //   throw UnimplementedError();
  // }

  // @override
  // Future<bool?> getBoolean(String alias, String pin, String key) {
  //   throw UnimplementedError();
  // }

  // @override
  // Future<double?> getDouble(String alias, String pin, String key) {
  //   throw UnimplementedError();
  // }

  // @override
  // Future<int?> getInteger(String alias, String pin, String key) {
  //   throw UnimplementedError();
  // }

  @override
  Future<String?> getData(String alias, String pin, String key) {
    throw UnimplementedError();
  }
  
  @override
  Future<bool?> saveData(String alias, String pin, String key, Uint8List data) {
    throw UnimplementedError();
  }

  // @override
  // Future<int?> testENC() {
  //   throw UnimplementedError();
  // }
}

void main() {
  final SecurityInfoPlatform initialPlatform = SecurityInfoPlatform.instance;

  test('$MethodChannelSecurityInfo is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelSecurityInfo>());
  });

  test('getPlatformVersion', () async {
    // SecurityInfo securityInfoPlugin = SecurityInfo();
    MockSecurityInfoPlatform fakePlatform = MockSecurityInfoPlatform();
    SecurityInfoPlatform.instance = fakePlatform;

    // expect(await securityInfoPlugin.getPlatformVersion(), '42');
  });
}
