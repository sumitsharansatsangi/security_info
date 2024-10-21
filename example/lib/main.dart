import 'package:flutter/material.dart';
import 'dart:async';

import 'package:flutter/services.dart';
import 'package:permission_handler/permission_handler.dart';
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

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    switch (state) {
      case AppLifecycleState.resumed:
        requestLocationPermission();
        break;
      case AppLifecycleState.paused:
        break;
      case AppLifecycleState.inactive:
        break;
      case AppLifecycleState.detached:
        break;
      case AppLifecycleState.hidden:
        break;
    }
  }

  // Platform messages are asynchronous, so we initialize in an async method.
  Future<void> initPlatformState() async {
    bool amICompromised = false;
    bool amIEmulator = false;
    bool amIDebugged = false;
    bool isDeveloperMode = false;
    bool isUSBDebugging = false;
    bool isOnExternalStorage = false;
    bool isMockLocationEnabled = false;
    // Platform messages may fail, so we use a try/catch PlatformException.
    // We also handle the message potentially returning null.
    try {
      amICompromised = await SecurityInfo.amICompromised() ?? false;
      amIEmulator = await SecurityInfo.amIEmulator() ?? false;
      amIDebugged = await SecurityInfo.amIDebugged() ?? false;
      isDeveloperMode = await SecurityInfo.isDeveloperMode() ?? false;
      isUSBDebugging = await SecurityInfo.isUsbDebugging() ?? false;
      isOnExternalStorage = await SecurityInfo.isOnExternalStorage() ?? false;
      isMockLocationEnabled =
          await SecurityInfo.isMockLocationEnabled() ?? false;
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
    });
  }

   Future<void> requestLocationPermission() async {
    var status = await Permission.location.status;
    if (status.isDenied || status.isPermanentlyDenied) {
      if (await Permission.location.request().isGranted) {
        initPlatformState();
        debugPrint("Location permission granted.");
      } else {
        // Permission denied
        debugPrint("Location permission denied.");
      }
    }
  }


  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Plugin example app'),
        ),
        body: Column(children: [
          Center(
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              crossAxisAlignment: CrossAxisAlignment.center,
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
              ],
            ),
          )
        ]),
      ),
    );
  }
}
