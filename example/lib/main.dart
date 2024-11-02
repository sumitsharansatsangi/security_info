// import 'dart:convert';

import 'dart:convert';

import 'package:flutter/material.dart';
import 'dart:async';
import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:flutter/services.dart';
import 'package:permission_handler/permission_handler.dart';
// import 'package:security_info/rsa_gen.dart';
import 'package:security_info/security_info.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> with WidgetsBindingObserver {
  bool _amICompromised = false;
  bool _amIEmulator = false;
  bool _amIDebugged = false;
  bool _isDeveloperMode = false;
  bool _isUsbDebugging = false;
  bool _isOnExternalStorage = false;
  bool _isMockLocationEnabled = false;
  bool _hasHardwareSecurity = false;
  bool _hasSecuredBox = false;
  // String _getSecureKey = "";
  String _generateSecureKey = "";
  bool _isPinSaved = false;
  bool _isStringSaved = false;
  // bool _isBoolSaved = false;
  // bool _isIntSaved = false;
  // bool _isFloatSaved = false;
  String _getString = "";
  // String _encrypterDecrypter = "";
  // int _getInt = 0;
  // bool _getBoolean = true;
  // double _getDouble = 4.0;
  // int _testENC = 0;
// List<int> floatBytes = Float32List(1)..[0] = d.toFloat().buffer.asUint8List();

  @override
  void initState() {
    super.initState();
    requestLocationPermission();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  // @override
  // void didChangeAppLifecycleState(AppLifecycleState state) {
  //   switch (state) {
  //     case AppLifecycleState.resumed:
  //       requestLocationPermission();
  //       break;
  //     case AppLifecycleState.paused:
  //       break;
  //     case AppLifecycleState.inactive:
  //       break;
  //     case AppLifecycleState.detached:
  //       break;
  //     case AppLifecycleState.hidden:
  //       break;
  //   }
  // }

  // Platform messages are asynchronous, so we initialize in an async method.
  Future<void> initPlatformState() async {
    // await SecurityInfo.testENC();
    bool amICompromised = false;
    bool amIEmulator = false;
    bool amIDebugged = false;
    bool isDeveloperMode = false;
    bool isUSBDebugging = false;
    bool isOnExternalStorage = false;
    bool isMockLocationEnabled = false;
    bool hasHardwareSecurity = false;
    bool hasSecuredBox = false;
    String generateSecureKey = "";
    bool isPinSaved = false;
    bool isStringSaved = false;
    // bool isBoolSaved = false;
    // bool isIntSaved = false;
    // bool isFloatSaved = false;
    String getString = "";
    // String encrypterDecrypter = "";
    // int getInt = 0;
    // bool getBoolean = true;
    // double getDouble = 4.0;
    // int testENC = 0;
    // String getSecureKey = "";
    // Platform messages may fail, so we use a try/catch PlatformException.
    // We also handle the message potentially returning null.
    //  final aesKey = encrypt.Key.fromSecureRandom(32);
    try {
      amICompromised = await SecurityInfo.amICompromised() ?? false;
      amIEmulator = await SecurityInfo.amIEmulator() ?? false;
      amIDebugged = await SecurityInfo.amIDebugged() ?? false;
      isDeveloperMode = await SecurityInfo.isDeveloperMode() ?? false;
      isUSBDebugging = await SecurityInfo.isUsbDebugging() ?? false;
      isOnExternalStorage = await SecurityInfo.isOnExternalStorage() ?? false;
      isMockLocationEnabled =
          await SecurityInfo.isMockLocationEnabled() ?? false;
      hasHardwareSecurity = await SecurityInfo.hasHardwareSecurity() ?? false;
      hasSecuredBox = await SecurityInfo.hasStrongBox() ?? false;
      generateSecureKey = await SecurityInfo.generateSecureKey("summy") ?? "";
      // getSecureKey = await SecurityInfo.getSecureKey("summy") ?? "";
      isPinSaved = await SecurityInfo.savePin("674534") ?? false;
      isStringSaved = await SecurityInfo.saveData("summy", "674534", "abort",
              "jvjdjkvhbdjलक्ष्मीपुर, जमुई, बिहार  राजस्व कर्मचारी  भूषण प्रसाद बरनवाल ") ??
          false;
      //   false;
      // isBoolSaved = await SecurityInfo.saveBoolean(
      //         "summy", "674534", "abortBoolean", false) ??
      //     false;
      // isIntSaved =
      //     await SecurityInfo.saveInteger("summy", "674534", "abortInt", 9876) ??
      //         false;
      //  isFloatSaved=  await SecurityInfo.saveDouble("summy", "674534", "abortFloat", 89.08) ?? false;
      var getUint = await SecurityInfo.getData("summy", "674534", "abort");
      if (getUint != null) {
        getString = getUint;
        //  getString =aesGcmDecrypt(getUint,aesKey);
      }
      // encrypterDecrypter = await SecurityInfo.encrpterDecrypter("gjhghjgh5756gySensitivejvjdjkvhbdjलक्ष्मीपुर, जमुई, बिहार  राजस्व कर्मचारी  भूषण प्रसाद बरनवाल data with Unicode characters: !@#\$%^&*()_+äöüß") ?? "";
      // getInt =await SecurityInfo.getInteger("summy", "674534", "abortInt") ?? 0;
      // getBoolean = await SecurityInfo.getBoolean("summy", "674534", "abortBoolean") ?? false;
      // testENC =  await SecurityInfo.testENC() ?? 0;
      // getDouble = await SecurityInfo.getDouble("summy", "674534", "abortFloat") ?? 0.0;
    } on PlatformException catch (e) {
      debugPrint(e.toString());
      //platform call failed
    }

    // If the widget was removed from the tree while the asynchronous platform
    // message was in flight, we want to discard the reply rather than calling
    // setState to update our non-existent appearance.
    if (!mounted) return;

    setState(() {
      _amICompromised = amICompromised;
      _amIEmulator = amIEmulator;
      _amIDebugged = amIDebugged;
      _isDeveloperMode = isDeveloperMode;
      _isUsbDebugging = isUSBDebugging;
      _isOnExternalStorage = isOnExternalStorage;
      _isMockLocationEnabled = isMockLocationEnabled;
      _hasHardwareSecurity = hasHardwareSecurity;
      _hasSecuredBox = hasSecuredBox;
      _generateSecureKey = generateSecureKey;
      _isPinSaved = isPinSaved;
      _isStringSaved = isStringSaved;
      // _isBoolSaved = isBoolSaved;
      // _isFloatSaved = isFloatSaved;
      // _isIntSaved = isIntSaved;
      _getString = getString;
      // _encrypterDecrypter = encrypterDecrypter;
      // _getInt = getInt;
      // _getDouble = getDouble;
      // _getBoolean = getBoolean;
      // _testENC = testENC;
      // _getSecureKey = getSecureKey;
    });
  }

  Future<void> requestLocationPermission() async {
    var status = await Permission.location.status;
    if (status.isDenied || status.isPermanentlyDenied) {
      if (await Permission.location.request().isGranted) {
        await initPlatformState();
        // await mainReady();
        debugPrint("Location permission granted.");
      } else {
        await Permission.location.request();
        await initPlatformState();
        // await mainReady();
      }
    } else {
      await Permission.location.request();
      await initPlatformState();
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        body: Center(
          child: ListView(
            children: [
              const SizedBox(
                height: 150,
              ),
              Text('Am I Compromised: $_amICompromised\n'),
              Text('Am I Emulator: $_amIEmulator\n'),
              Text('Am I Debugged: $_amIDebugged\n'),
              Text('Is Developer Mode On: $_isDeveloperMode\n'),
              Text('Is Usb debugging On: $_isUsbDebugging\n'),
              Text('Is on External Storage: $_isOnExternalStorage\n'),
              Text('Is Mock Location Enabled: $_isMockLocationEnabled\n'),
              Text('Is hardware Security: $_hasHardwareSecurity\n'),
              Text('Is SecuredBox: $_hasSecuredBox\n'),
              Text(_generateSecureKey),
              Text('Is Pin Saved: $_isPinSaved\n'),
              Text('Is String Saved: $_isStringSaved\n'),
              // Text('Is Bool Saved: $_isBoolSaved\n'),
              // Text('Is Int Saved: $_isIntSaved\n'),
              // Text('Is Float Saved: $_isFloatSaved\n'),
              Text('String Saved: $_getString\n'),
              // Text("encrypterDecrypter: $_encrypterDecrypter"),
              // Text('Bool Saved: $_getBoolean\n'),
              // Text('Int Saved: $_getInt\n'),
              // Text('Double Saved: $_getDouble\n'),
              // Text("Float Saved: $_isFloatSaved"),
              // Text("Test ENC: $_testENC")
              // Text(_getSecureKey),
            ],
          ),
        ),
        // floatingActionButton: FloatingActionButton(onPressed: mainReady, child:Icon(Icons.add)),
      ),
    );
  }

  Uint8List aesGcmEncrypt(String plaintext, encrypt.Key aesKey) {
    final iv = encrypt.IV.fromSecureRandom(12); // GCM requires 12-byte IV
    final encrypter =
        encrypt.Encrypter(encrypt.AES(aesKey, mode: encrypt.AESMode.gcm));
    final encrypted = encrypter.encrypt(plaintext, iv: iv);
    // print("aesGcmEncrypt encrypted String");
    // print(iv.base64 + encrypted.base64);
    return base64Decode(iv.base64 + encrypted.base64);
  }

// Decrypt data with AES-GCM
  String aesGcmDecrypt(String encryptedData, encrypt.Key aesKey) {
    // print("aesGcmDecrypt encrypted String");
    final iv = encrypt.IV.fromUtf8(encryptedData.substring(0, 12));
    final encrypter =
        encrypt.Encrypter(encrypt.AES(aesKey, mode: encrypt.AESMode.gcm));
    // print(encryptedData);
    return encrypter.decrypt64(encryptedData.substring(12), iv: iv);
  }
}
