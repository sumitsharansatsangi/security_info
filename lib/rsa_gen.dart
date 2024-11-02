// import 'dart:math';
// import 'dart:typed_data';
// import 'package:encrypt/encrypt.dart';
// import "package:pointycastle/export.dart";
// import "package:asn1lib/asn1lib.dart";
// import 'package:security_info/security_info.dart';

// // Function to generate secure random values
// FortunaRandom generateSecureRandom(int length) {
//   final secureRandom = FortunaRandom();
//   final seedSource = Random.secure();
//   final seeds = List<int>.generate(length, (_) => seedSource.nextInt(255));
//   secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));
//   return secureRandom;
// }

// // Function to generate RSA key pair
// AsymmetricKeyPair<PublicKey, PrivateKey> generateRSAKeyPair() {
//   final keyGen = RSAKeyGenerator()
//     ..init(ParametersWithRandom(
//         RSAKeyGeneratorParameters(BigInt.parse('65537'), 2048, 12),
//         generateSecureRandom(32)));
//   return keyGen.generateKeyPair();
// }

// // Function to store key securely
// Future<void> storeKey(
//     String alias, String pin, String key, Uint8List value) async {
//   await SecurityInfo.saveData(alias, pin, key, value);
// }

// // Function to retrieve key securely
// Future<String?> retrieveKey(String alias, String pin, String key) async {
//   return await SecurityInfo.getData(alias, pin, key);
// }

// Uint8List rsaEncrypt(Uint8List dataToEncrypt, RSAPublicKey myPublic) {
//   final encryptor = OAEPEncoding(RSAEngine())
//     ..init(true, PublicKeyParameter<RSAPublicKey>(myPublic)); // true=encrypt
//   return _processInBlocks(encryptor, dataToEncrypt);
// }

// Future<Uint8List?> rsaDecrypt(String key, RSAPrivateKey myPrivate) async {
//   final encryptedText = await retrieveKey("summy", "674534", key);
//   final decryptor = OAEPEncoding(RSAEngine())
//     ..init(false, PrivateKeyParameter<RSAPrivateKey>(myPrivate));
//   if (encryptedText != null) {
//     return _processInBlocks(decryptor, encryptedText);
//   }
//   return null;
// }

// Uint8List _processInBlocks(AsymmetricBlockCipher engine, String input) {
//   final numBlocks = input.length ~/ engine.inputBlockSize +
//       ((input.length % engine.inputBlockSize != 0) ? 1 : 0);

//   final output = Uint8List(numBlocks * engine.outputBlockSize);

//   var inputOffset = 0;
//   var outputOffset = 0;
//   while (inputOffset < input.length) {
//     final chunkSize = (inputOffset + engine.inputBlockSize <= input.length)
//         ? engine.inputBlockSize
//         : input.length - inputOffset;

//     outputOffset += engine.processBlock(
//         input, inputOffset, chunkSize, output, outputOffset);

//     inputOffset += chunkSize;
//   }

//   return (output.length == outputOffset)
//       ? output
//       : output.sublist(0, outputOffset);
// }

// // Encrypt data with AES-GCM before storage
// Uint8List aesGcmEncrypt(String plaintext, Key aesKey) {
//   final iv = IV.fromSecureRandom(12); // GCM requires 12-byte IV
//   final encrypter = Encrypter(AES(aesKey, mode: AESMode.gcm));
//   final encrypted = encrypter.encrypt(plaintext, iv: iv);
//   return Uint8List.fromList(iv.bytes + encrypted.bytes);
// }

// // Decrypt data with AES-GCM
// String aesGcmDecrypt(String encryptedData, Key aesKey) {
//   final iv = IV.fromUtf8(encryptedData.substring(0, 12));
//   final encrypter = Encrypter(AES(aesKey, mode: AESMode.gcm));
//   return encrypter.decrypt64(encryptedData.substring(12), iv: iv);
// }
// Uint8List rsaPrivateKeyToBytes(RSAPrivateKey privateKey) {
//  var algorithmSeq = ASN1Sequence()
//     ..add(ASN1Object.fromBytes(Uint8List.fromList([0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1])))
//     ..add(ASN1Object.fromBytes(Uint8List.fromList([0x5, 0x0])));

//   var privateKeySeq = ASN1Sequence()
//     ..add(ASN1Integer(privateKey.modulus!))
//     ..add(ASN1Integer(privateKey.privateExponent!))
//     ..add(ASN1Integer(privateKey.p!))
//     ..add(ASN1Integer(privateKey.q!))
//     ..add(ASN1Integer(privateKey.privateExponent! % (privateKey.p! - BigInt.one)))
//     ..add(ASN1Integer(privateKey.privateExponent! % (privateKey.q! - BigInt.one)))
//     ..add(ASN1Integer(privateKey.q!.modInverse(privateKey.p!)));

//   var privateKeyInfo = ASN1Sequence()
//     ..add(ASN1Integer(BigInt.from(0)))
//     ..add(algorithmSeq)
//     ..add(ASN1OctetString(privateKeySeq.encodedBytes));

//   return Uint8List.fromList(privateKeyInfo.encodedBytes);
// }

// BigInt bytesToBigInt(Uint8List? bytes) {
//   if (bytes == null) {
//     throw ArgumentError("Bytes cannot be null");
//   }
//   return BigInt.parse(bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join(), radix: 16);
// }

// RSAPrivateKey bytesToRSAPrivateKey(Uint8List bytes) {
//   var asn1Parser = ASN1Parser(bytes);
//   var topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;
//   var octetString = topLevelSeq.elements[2] as ASN1OctetString;
//   var privateKeyInfoBytes = octetString.octets;

//   var privateKeyInfo = ASN1Parser(privateKeyInfoBytes);
//   var privateKeySeq = privateKeyInfo.nextObject() as ASN1Sequence;
//     if (privateKeySeq.elements.length < 5) {
//     throw ArgumentError("Incomplete RSA private key elements");
//   }

//   var modulus = bytesToBigInt((privateKeySeq.elements[1] as ASN1Integer).encodedBytes);
//   var privateExponent = bytesToBigInt((privateKeySeq.elements[2] as ASN1Integer).encodedBytes);
//   var p = bytesToBigInt((privateKeySeq.elements[3] as ASN1Integer).encodedBytes);
//   var q = bytesToBigInt((privateKeySeq.elements[4] as ASN1Integer).encodedBytes);

//   return RSAPrivateKey(modulus, privateExponent, p, q);
// }

// Future<void> mainReady() async {
//   final aesKey = Key.fromSecureRandom(32);
//   final rsaKeyPair = generateRSAKeyPair();

//   // Serialize keys
//   final publicKeyPem = rsaKeyPair.publicKey as RSAPublicKey;
//   final privateKeyPem = rsaKeyPair.privateKey as RSAPrivateKey;

//   // Store keys securely
//   // await storeKey(
//   //   'alias',
//   //   'pin',
//   //   'rsa_public_key',
//   //   rsaPublicKeyToBytes(publicKeyPem)
//   // );
//   // print(privateKeyPem.privateExponent);
//   // print(privateKeyPem.publicExponent);
//   print(rsaPrivateKeyToBytes(privateKeyPem));
//   await storeKey(
//       'summy', '674534', 'rsa_private_key', rsaPrivateKeyToBytes(privateKeyPem));

//   // print('RSA keys generated and stored securely');

//   // Retrieve keys
//   // final storedPublicKey = await retrieveKey('alias', 'pin', 'rsa_public_key');
//   final storedPrivateKey = await retrieveKey('summy', '674534', 'rsa_private_key');

//   // print('Retrieved Public Key: $storedPublicKey');
//   print('Retrieved Private Key: $storedPrivateKey');
//   const plaintext = 'Sensitive Data';
//   final encryptedData = aesGcmEncrypt(plaintext, aesKey);
//   await storeKey(
//       'summy', '674534', 'secure_data', rsaEncrypt(encryptedData, publicKeyPem));
//   final key = await rsaDecrypt("rsa_public_key", privateKeyPem);
//   if (key != null) {
//     await storeKey('summy', '674534', 'secure_data', key);
//   }
// }
