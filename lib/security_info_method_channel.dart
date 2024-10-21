import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'security_info_platform_interface.dart';

/// An implementation of [SecurityInfoPlatform] that uses method channels.
class MethodChannelSecurityInfo extends SecurityInfoPlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('security_info');

  @override
  Future<bool?> amICompromised() async {
    final compromised = await methodChannel.invokeMethod<bool>('runprog');

    if (compromised == false && Platform.isAndroid) {
      final magisk = await methodChannel.invokeMethod<bool>('runprog4');
      return magisk;
    } else {
      return compromised;
    }
  }

  @override
  Future<bool?> amIEmulator() async {
    final emulator = await methodChannel.invokeMethod<bool>('runprog2');
    return emulator;
  }

  @override
  Future<bool?> amIDebugged() async {
    final debugged = await methodChannel.invokeMethod<bool>('runprog3');
    return debugged;
  }

  @override
  Future<bool?> isDeveloperMode() async {
    final developerMode =
        await methodChannel.invokeMethod<bool>('isDeveloperMode');
    return developerMode;
  }

  @override
  Future<bool?> isUsbDebugging() async {
    final usbDebugging =
        await methodChannel.invokeMethod<bool>('isUSBDebugging');
    return usbDebugging;
  }

  @override
  Future<bool?> isOnExternalStorage() async {
    final externalStorage =
        await methodChannel.invokeMethod<bool>('isOnExternalStorage');
    return externalStorage;
  }

  @override
  Future<bool?> isMockLocationEnabled() async {
    final mockLocationEnabled =
        await methodChannel.invokeMethod<bool>('isMockLocationEnabled');
    return mockLocationEnabled;
  }
}
