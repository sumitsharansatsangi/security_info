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
