# Reporte apkscan

- Objetivo: `MASTG-DEMO-0022.apk`
- Fecha: 2026-09-30T20:34:32
- Resultado: 2 vulnerables, 0 a revisar, 2 sin hallazgos

| Test | MASWE | Estado | Severidad | Evidencias |
|---|---|---|---|---|
| MASTG-TEST-0212 | MASWE-0003 | SIN HALLAZGOS | Alta | 0 |
| MASTG-TEST-0221 | MASWE-0007 | VULNERABLE | Alta | 8 |
| MASTG-TEST-0232 | MASWE-0007 | SIN HALLAZGOS | Alta | 0 |
| MASTG-TEST-0291 | MASWE-0038 | VULNERABLE | Media | ausencia |

## MASTG-TEST-0212 - Claves criptograficas hardcodeadas en el codigo

- Estado: **SIN HALLAZGOS**
- MASWE: MASWE-0003 / MASVS-CRYPTO
- Severidad: Alta

### Descripcion

La app construye una SecretKeySpec a partir de material que esta escrito en el propio codigo:
un arreglo de bytes literal, un string literal convertido con getBytes() o una cadena Base64
fija. La clave viaja dentro del APK y cualquiera puede extraerla.

### Evidencias

No se encontraron coincidencias.

### Referencias

- https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0212.md
- https://developer.android.com/reference/javax/crypto/spec/SecretKeySpec

## MASTG-TEST-0221 - Algoritmos de cifrado simetrico rotos

- Estado: **VULNERABLE**
- MASWE: MASWE-0007 / MASVS-CRYPTO
- Severidad: Alta

### Descripcion

La app usa algoritmos de cifrado simetrico que ya no se consideran seguros: DES, 3DES (DESede),
RC2, RC4 o Blowfish. Se detectan llamadas a Cipher.getInstance, SecretKeyFactory.getInstance y
KeyGenerator.getInstance con esos algoritmos, y el uso de las clases DESKeySpec y DESedeKeySpec.

### Evidencias


**#1** `sources/org/owasp/mastestapp/MastgTest.java:34` (uso inseguro) - Uso de DESKeySpec o DESedeKeySpec

```java
     32 |             byte[] keyBytes = new byte[8];
     33 |             new SecureRandom().nextBytes(keyBytes);
>    34 |             DESKeySpec keySpec = new DESKeySpec(keyBytes);
     35 |             SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
     36 |             Key keyGenerateSecret = keyFactory.generateSecret(keySpec);
```

**#2** `sources/org/owasp/mastestapp/MastgTest.java:35` (uso inseguro) - Algoritmo simetrico roto en Cipher, KeyGenerator o SecretKeyFactory

```java
     33 |             new SecureRandom().nextBytes(keyBytes);
     34 |             DESKeySpec keySpec = new DESKeySpec(keyBytes);
>    35 |             SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
     36 |             Key keyGenerateSecret = keyFactory.generateSecret(keySpec);
     37 |             Intrinsics.checkNotNullExpressionValue(keyGenerateSecret, "generateSecret(...)");
```

**#3** `sources/org/owasp/mastestapp/MastgTest.java:39` (uso inseguro) - Algoritmo simetrico roto en Cipher, KeyGenerator o SecretKeyFactory

```java
     37 |             Intrinsics.checkNotNullExpressionValue(keyGenerateSecret, "generateSecret(...)");
     38 |             Key secretKey = keyGenerateSecret;
>    39 |             Cipher cipher = Cipher.getInstance("DES");
     40 |             cipher.init(1, secretKey);
     41 |             byte[] bytes = data.getBytes(Charsets.UTF_8);
```

**#4** `sources/org/owasp/mastestapp/MastgTest.java:57` (uso inseguro) - Uso de DESKeySpec o DESedeKeySpec

```java
     55 |             byte[] keyBytes = new byte[24];
     56 |             new SecureRandom().nextBytes(keyBytes);
>    57 |             DESedeKeySpec keySpec = new DESedeKeySpec(keyBytes);
     58 |             SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
     59 |             Key keyGenerateSecret = keyFactory.generateSecret(keySpec);
```

**#5** `sources/org/owasp/mastestapp/MastgTest.java:58` (uso inseguro) - Algoritmo simetrico roto en Cipher, KeyGenerator o SecretKeyFactory

```java
     56 |             new SecureRandom().nextBytes(keyBytes);
     57 |             DESedeKeySpec keySpec = new DESedeKeySpec(keyBytes);
>    58 |             SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
     59 |             Key keyGenerateSecret = keyFactory.generateSecret(keySpec);
     60 |             Intrinsics.checkNotNullExpressionValue(keyGenerateSecret, "generateSecret(...)");
```

**#6** `sources/org/owasp/mastestapp/MastgTest.java:62` (uso inseguro) - Algoritmo simetrico roto en Cipher, KeyGenerator o SecretKeyFactory

```java
     60 |             Intrinsics.checkNotNullExpressionValue(keyGenerateSecret, "generateSecret(...)");
     61 |             Key secretKey = keyGenerateSecret;
>    62 |             Cipher cipher = Cipher.getInstance("DESede");
     63 |             cipher.init(1, secretKey);
     64 |             byte[] bytes = data.getBytes(Charsets.UTF_8);
```

**#7** `sources/org/owasp/mastestapp/MastgTest.java:81` (uso inseguro) - Algoritmo simetrico roto en Cipher, KeyGenerator o SecretKeyFactory

```java
     79 |             new SecureRandom().nextBytes(keyBytes);
     80 |             SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "RC4");
>    81 |             Cipher cipher = Cipher.getInstance("RC4");
     82 |             cipher.init(1, secretKey);
     83 |             byte[] bytes = data.getBytes(Charsets.UTF_8);
```

**#8** `sources/org/owasp/mastestapp/MastgTest.java:98` (uso inseguro) - Algoritmo simetrico roto en Cipher, KeyGenerator o SecretKeyFactory

```java
     96 |             new SecureRandom().nextBytes(keyBytes);
     97 |             SecretKey secretKey = new SecretKeySpec(keyBytes, "Blowfish");
>    98 |             Cipher cipher = Cipher.getInstance("Blowfish");
     99 |             cipher.init(1, secretKey);
    100 |             byte[] bytes = data.getBytes(Charsets.UTF_8);
```

### Impacto

DES tiene una clave de 56 bits que se puede recuperar por fuerza bruta. 3DES y Blowfish usan
bloques de 64 bits y son vulnerables a ataques de cumpleanos (Sweet32). RC4 genera un keystream
sesgado que permite recuperar el texto plano. Un atacante con acceso a los datos cifrados
(almacenamiento local, backups, trafico propio de la app) puede descifrarlos.

### Mitigacion

Reemplazar el algoritmo por AES con una clave de 128 bits o mas en un modo autenticado
(AES/GCM/NoPadding). Generar las claves con KeyGenerator y guardarlas en el Android Keystore
en lugar de manejarlas desde el codigo de la app.

### Validacion manual

Revisar cada ubicacion reportada y confirmar si el algoritmo protege datos sensibles o si se
usa solo por compatibilidad con un sistema externo que no es sensible.

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
