# Reporte apkscan

- Objetivo: `MASTG-DEMO-0017.apk`
- Fecha: 2026-09-30T20:34:17
- Resultado: 2 vulnerables, 0 a revisar, 2 sin hallazgos

| Test | MASWE | Estado | Severidad | Evidencias |
|---|---|---|---|---|
| MASTG-TEST-0212 | MASWE-0003 | VULNERABLE | Alta | 3 |
| MASTG-TEST-0221 | MASWE-0007 | SIN HALLAZGOS | Alta | 0 |
| MASTG-TEST-0232 | MASWE-0007 | SIN HALLAZGOS | Alta | 0 |
| MASTG-TEST-0291 | MASWE-0038 | VULNERABLE | Media | ausencia |

## MASTG-TEST-0212 - Claves criptograficas hardcodeadas en el codigo

- Estado: **VULNERABLE**
- MASWE: MASWE-0003 / MASVS-CRYPTO
- Severidad: Alta

### Descripcion

La app construye una SecretKeySpec a partir de material que esta escrito en el propio codigo:
un arreglo de bytes literal, un string literal convertido con getBytes() o una cadena Base64
fija. La clave viaja dentro del APK y cualquiera puede extraerla.

### Evidencias


**#1** `sources/org/owasp/mastestapp/MastgTest.java:27` (uso inseguro) - Arreglo de bytes literal usado para crear una SecretKeySpec

```java
     25 | 
     26 |     public final String mastgTest() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
>    27 |         byte[] keyBytes = {108, 97, 107, 100, 115, 108, 106, 107, 97, 108, 107, 106, 108, 107, 108, 115};
     28 |         Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
     29 |         SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
```

**#2** `sources/org/owasp/mastestapp/MastgTest.java:29` (uso inseguro) - Arreglo de bytes literal usado para crear una SecretKeySpec

```java
     27 |         byte[] keyBytes = {108, 97, 107, 100, 115, 108, 106, 107, 97, 108, 107, 106, 108, 107, 108, 115};
     28 |         Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
>    29 |         SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
     30 |         cipher.init(1, secretKey);
     31 |         byte[] bytes = "my secret here".getBytes(Charsets.UTF_8);
```

**#3** `sources/org/owasp/mastestapp/MastgTest.java:33` (uso inseguro) - Arreglo de bytes literal usado para crear una SecretKeySpec

```java
     31 |         byte[] bytes = "my secret here".getBytes(Charsets.UTF_8);
     32 |         Intrinsics.checkNotNullExpressionValue(bytes, "getBytes(...)");
>    33 |         SecretKeySpec badSecretKeySpec = new SecretKeySpec(bytes, "AES");
     34 |         return "SUCCESS!!\n\nThe keys were generated and used successfully with the following details:\n\nHardcoded AES Encryption Key: " + Base64.encodeToString(keyBytes, 0) + "\nHardcoded Key from string: " + Base64.encodeToString(badSecretKeySpec.getEncoded(), 0) + "\n";
     35 |     }
```

### Impacto

Cualquiera que descargue el APK y lo decompile obtiene la clave. Con ella puede descifrar los
datos protegidos por la app, falsificar firmas o MACs, y la clave no se puede rotar sin
publicar una version nueva de la app. La misma clave queda ademas compartida entre todos los
usuarios.

### Mitigacion

No incluir claves en el codigo ni en los recursos. Generar la clave en el dispositivo con
KeyGenerator y guardarla en el Android Keystore, o derivarla de un secreto del usuario
(por ejemplo con PBKDF2 o Argon2). Si la clave llega desde un servidor, obtenerla
en tiempo de ejecucion por un canal autenticado.

### Validacion manual

Confirmar en cada ubicacion que la clave se usa en un contexto sensible y no, por ejemplo,
en un test o en una constante sin valor de seguridad.

### Referencias

- https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0212.md
- https://developer.android.com/reference/javax/crypto/spec/SecretKeySpec

## MASTG-TEST-0221 - Algoritmos de cifrado simetrico rotos

- Estado: **SIN HALLAZGOS**
- MASWE: MASWE-0007 / MASVS-CRYPTO
- Severidad: Alta

### Descripcion

La app usa algoritmos de cifrado simetrico que ya no se consideran seguros: DES, 3DES (DESede),
RC2, RC4 o Blowfish. Se detectan llamadas a Cipher.getInstance, SecretKeyFactory.getInstance y
KeyGenerator.getInstance con esos algoritmos, y el uso de las clases DESKeySpec y DESedeKeySpec.

### Evidencias

No se encontraron coincidencias.

### Referencias

- https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0221.md
- https://developer.android.com/privacy-and-security/risks/broken-cryptographic-algorithm
- https://sweet32.info/

## MASTG-TEST-0232 - Modos de cifrado simetrico rotos (ECB)

- Estado: **SIN HALLAZGOS**
- MASWE: MASWE-0007 / MASVS-CRYPTO
- Severidad: Alta

### Descripcion

La app usa el modo ECB en un cifrado simetrico, ya sea de forma explicita
(por ejemplo "AES/ECB/PKCS5Padding") o implicita: Cipher.getInstance("AES") usa AES/ECB por
defecto en Android. Las transformaciones RSA/ECB/* quedan fuera porque RSA no opera por bloques
y ese "ECB" es solo un placeholder de la API.

### Evidencias

No se encontraron coincidencias.

### Referencias

- https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0232.md
- https://csrc.nist.gov/pubs/sp/800/38/a/final

## MASTG-TEST-0291 - Ausencia de proteccion contra captura de pantalla (FLAG_SECURE)

- Estado: **VULNERABLE**
- MASWE: MASWE-0038 / MASVS-PLATFORM
- Severidad: Media

### Descripcion

Este test funciona al reves que los demas: el hallazgo es que NO hay evidencia. Busca
referencias a las APIs que evitan la captura de pantalla, principalmente FLAG_SECURE aplicado
con Window.addFlags() o Window.setFlags() (jadx lo muestra como 8192 o 0x2000), y
setRecentsScreenshotEnabled(false) para la vista de apps recientes. Si no aparece ninguna,
las pantallas de la app se pueden capturar, grabar o espejar. Tambien se buscan llamadas que
quitan la proteccion (clearFlags).

### Evidencias

Evidencia por ausencia: el analisis no encontro la proteccion esperada.

- Archivos de codigo analizados: 7851
- Coincidencias con la API de proteccion: 0
- Activities declaradas en resources/AndroidManifest.xml: 3

Patrones buscados:

```text
\.(?:addFlags|setFlags)\(\s*(?:WindowManager\.LayoutParams\.|LayoutParams\.)?FLAG_SECURE\b[^;]*;
(?:getWindow\(\)|\b[wW]indow\w*)\s*\.(?:addFlags\(\s*(?:8192|0x2000)\s*\)|setFlags\(\s*(?:8192|0x2000)\s*,\s*(?:8192|0x2000)\s*\))
setRecentsScreenshotEnabled\(\s*false\s*\)
```

Activities declaradas sin proteccion detectada:

- `org.owasp.mastestapp.MainActivity`
- `androidx.compose.ui.tooling.PreviewActivity`
- `androidx.activity.ComponentActivity`

> no se encontro ninguna referencia a la proteccion esperada

### Impacto

Sin FLAG_SECURE, el sistema permite capturar la pantalla y mostrar su contenido en
pantallas no seguras (screen sharing, Chromecast, apps de grabacion). Ademas, Android guarda
una miniatura de la app en la lista de recientes. Datos sensibles como saldos, credenciales
o informacion personal pueden filtrarse por capturas, malware con permisos de grabacion o
por alguien que mire los recientes.

### Mitigacion

Agregar getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE) en las activities que
muestran datos sensibles, antes de setContentView. En Android 13+ se puede complementar con
setRecentsScreenshotEnabled(false). Revisar que ningun flujo llame a clearFlags con
FLAG_SECURE sin una justificacion.

### Validacion manual

Que no haya referencias alcanza para fallar el test. Si las hay, confirmar manualmente que
cubren todas las pantallas con datos sensibles y que ningun camino de codigo quita la bandera.

### Referencias

- https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0291.md
- https://developer.android.com/security/fraud-prevention/activities#flag_secure
