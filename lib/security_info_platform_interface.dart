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
}
