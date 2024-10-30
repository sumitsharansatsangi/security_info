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

  // @override
  // Future<String?> getSecureKey(String alias) async {
  //   final secureKey = await methodChannel
  //       .invokeMethod<String>('getSecretKey', {"alias": alias});
  //   return secureKey;
  // }

  @override
  Future<String?> generateSecureKey(String alias) async {
    final mockLocationEnabled = await methodChannel
        .invokeMethod<String>('generateSecureKey', {"alias": alias});
    return mockLocationEnabled;
  }

  @override
  Future<bool?> hasHardwareSecurity() async {
    final hardwareSecurity =
        await methodChannel.invokeMethod<bool>('hasHardwareSecurity');
    return hardwareSecurity;
  }

  @override
  Future<bool?> hasStrongBox() async {
    final strongBox = await methodChannel.invokeMethod<bool>('hasStrongBox');
    return strongBox;
  }

  @override
  Future<bool?> savePin(String pin) async {
    return await methodChannel.invokeMethod<bool>('savePin', {"pin": pin});
  }

  @override
  Future<bool?> saveData(
      String alias, String pin, String key, String plainText) async {
    return await methodChannel.invokeMethod<bool>(
        'saveData', {"alias": alias, "pin": pin, "key": key, "plainText": plainText});
  }

// @override
//   Future<String?> encrypterDecrypter(String data) async {
//     return await methodChannel.invokeMethod<String>(
//         'encrypterDecrypter', {"data": data});
//   }



  // @override
  // Future<bool?> saveBoolean(
  //     String alias, String pin, String key, bool data) async {
  //   return await methodChannel.invokeMethod<bool>(
  //       'saveBoolean', {"alias": alias, "pin": pin, "key": key, "data": data});
  // }

  // @override
  // Future<bool?> saveInteger(
  //     String alias, String pin, String key, int data) async {
  //   return await methodChannel.invokeMethod<bool>(
  //       'saveInteger', {"alias": alias, "pin": pin, "key": key, "data": data});
  // }

  // @override
  // Future<bool?> saveDouble(
  //     String alias, String pin, String key, double data) async {
  //   return await methodChannel.invokeMethod<bool>(
  //       'saveDouble', {"alias": alias, "pin": pin, "key": key, "data": data});
  // }

  @override
  Future<String?> getData(String alias, String pin, String key) async {
    return await methodChannel.invokeMethod<String>(
        'getData', {"alias": alias, "pin": pin, "key": key});
  }

  // @override
  // Future<bool?> getBoolean(String alias, String pin, String key) async {
  //   return await methodChannel.invokeMethod<bool>('decryptBoolean', {
  //     "alias": alias,
  //     "pin": pin,
  //     "key": key,
  //   });
  // }

  // @override
  // Future<int?> getInteger(String alias, String pin, String key) async {
  //   return await methodChannel.invokeMethod<int>(
  //       'decryptInt', {"alias": alias, "pin": pin, "key": key});
  // }

  // @override
  // Future<double?> getDouble(String alias, String pin, String key) async {
  //   return await methodChannel.invokeMethod<double>(
  //       'decryptDouble', {"alias": alias, "pin": pin, "key": key});
  // }

  // @override
  // Future<int?> testENC() async {
  //   return await methodChannel.invokeMethod<int>('testENC');
  // }
}
