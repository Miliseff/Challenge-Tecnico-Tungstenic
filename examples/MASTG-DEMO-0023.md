# Reporte apkscan

- Objetivo: `MASTG-DEMO-0023.apk`
- Fecha: 2026-09-30T20:34:46
- Resultado: 4 vulnerables, 0 a revisar, 0 sin hallazgos

| Test | MASWE | Estado | Severidad | Evidencias |
|---|---|---|---|---|
| MASTG-TEST-0212 | MASWE-0003 | VULNERABLE | Alta | 4 |
| MASTG-TEST-0221 | MASWE-0007 | VULNERABLE | Alta | 6 |
| MASTG-TEST-0232 | MASWE-0007 | VULNERABLE | Alta | 6 |
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


**#1** `sources/org/owasp/mastestapp/MastgTest.java:35` (uso inseguro) - String literal con largo de clave convertido a bytes y usado en SecretKeySpec

```java
     33 |             byte[] key = "1234567890123456".getBytes(Charsets.UTF_8);
     34 |             Intrinsics.checkNotNullExpressionValue(key, "getBytes(...)");
>    35 |             SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
     36 |             Cipher cipher = Cipher.getInstance("AES");
     37 |             cipher.init(1, secretKeySpec);
```

**#2** `sources/org/owasp/mastestapp/MastgTest.java:54` (uso inseguro) - String literal con largo de clave convertido a bytes y usado en SecretKeySpec

```java
     52 |             byte[] key = "1234567890123456".getBytes(Charsets.UTF_8);
     53 |             Intrinsics.checkNotNullExpressionValue(key, "getBytes(...)");
>    54 |             SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
     55 |             Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
     56 |             cipher.init(1, secretKeySpec);
```

**#3** `sources/org/owasp/mastestapp/MastgTest.java:75` (uso inseguro) - String literal con largo de clave convertido a bytes y usado en SecretKeySpec

```java
     73 |             byte[] key = "1234567890123456".getBytes(Charsets.UTF_8);
     74 |             Intrinsics.checkNotNullExpressionValue(key, "getBytes(...)");
>    75 |             SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
     76 |             Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
     77 |             cipher.init(1, secretKeySpec);
```

**#4** `sources/org/owasp/mastestapp/MastgTest.java:94` (uso inseguro) - String literal con largo de clave convertido a bytes y usado en SecretKeySpec

```java
     92 |             byte[] key = "1234567890123456".getBytes(Charsets.UTF_8);
     93 |             Intrinsics.checkNotNullExpressionValue(key, "getBytes(...)");
>    94 |             SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
     95 |             Cipher cipher = Cipher.getInstance("AES/ECB/ISO10126Padding");
     96 |             cipher.init(1, secretKeySpec);
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

- Estado: **VULNERABLE**
- MASWE: MASWE-0007 / MASVS-CRYPTO
- Severidad: Alta

### Descripcion

La app usa algoritmos de cifrado simetrico que ya no se consideran seguros: DES, 3DES (DESede),
RC2, RC4 o Blowfish. Se detectan llamadas a Cipher.getInstance, SecretKeyFactory.getInstance y
KeyGenerator.getInstance con esos algoritmos, y el uso de las clases DESKeySpec y DESedeKeySpec.

### Evidencias


**#1** `sources/org/owasp/mastestapp/MastgTest.java:113` (uso inseguro) - Uso de DESKeySpec o DESedeKeySpec

```java
    111 |             byte[] bytes = "12345678".getBytes(Charsets.UTF_8);
    112 |             Intrinsics.checkNotNullExpressionValue(bytes, "getBytes(...)");
>   113 |             DESKeySpec keySpec = new DESKeySpec(bytes);
    114 |             SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
    115 |             Key keyGenerateSecret = keyFactory.generateSecret(keySpec);
```

**#2** `sources/org/owasp/mastestapp/MastgTest.java:114` (uso inseguro) - Algoritmo simetrico roto en Cipher, KeyGenerator o SecretKeyFactory

```java
    112 |             Intrinsics.checkNotNullExpressionValue(bytes, "getBytes(...)");
    113 |             DESKeySpec keySpec = new DESKeySpec(bytes);
>   114 |             SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
    115 |             Key keyGenerateSecret = keyFactory.generateSecret(keySpec);
    116 |             Intrinsics.checkNotNullExpressionValue(keyGenerateSecret, "generateSecret(...)");
```

**#3** `sources/org/owasp/mastestapp/MastgTest.java:118` (uso inseguro) - Algoritmo simetrico roto en Cipher, KeyGenerator o SecretKeyFactory

```java
    116 |             Intrinsics.checkNotNullExpressionValue(keyGenerateSecret, "generateSecret(...)");
    117 |             Key secretKey = keyGenerateSecret;
>   118 |             Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
    119 |             cipher.init(1, secretKey);
    120 |             byte[] bytes2 = data.getBytes(Charsets.UTF_8);
```

**#4** `sources/org/owasp/mastestapp/MastgTest.java:136` (uso inseguro) - Uso de DESKeySpec o DESedeKeySpec

```java
    134 |             byte[] bytes = "123456789012345678901234".getBytes(Charsets.UTF_8);
    135 |             Intrinsics.checkNotNullExpressionValue(bytes, "getBytes(...)");
>   136 |             DESedeKeySpec keySpec = new DESedeKeySpec(bytes);
    137 |             SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
    138 |             Key keyGenerateSecret = keyFactory.generateSecret(keySpec);
```

**#5** `sources/org/owasp/mastestapp/MastgTest.java:137` (uso inseguro) - Algoritmo simetrico roto en Cipher, KeyGenerator o SecretKeyFactory

```java
    135 |             Intrinsics.checkNotNullExpressionValue(bytes, "getBytes(...)");
    136 |             DESedeKeySpec keySpec = new DESedeKeySpec(bytes);
>   137 |             SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
    138 |             Key keyGenerateSecret = keyFactory.generateSecret(keySpec);
    139 |             Intrinsics.checkNotNullExpressionValue(keyGenerateSecret, "generateSecret(...)");
```

**#6** `sources/org/owasp/mastestapp/MastgTest.java:141` (uso inseguro) - Algoritmo simetrico roto en Cipher, KeyGenerator o SecretKeyFactory

```java
    139 |             Intrinsics.checkNotNullExpressionValue(keyGenerateSecret, "generateSecret(...)");
    140 |             Key secretKey = keyGenerateSecret;
>   141 |             Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
    142 |             cipher.init(1, secretKey);
    143 |             byte[] bytes2 = data.getBytes(Charsets.UTF_8);
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

- Estado: **VULNERABLE**
- MASWE: MASWE-0007 / MASVS-CRYPTO
- Severidad: Alta

### Descripcion

La app usa el modo ECB en un cifrado simetrico, ya sea de forma explicita
(por ejemplo "AES/ECB/PKCS5Padding") o implicita: Cipher.getInstance("AES") usa AES/ECB por
defecto en Android. Las transformaciones RSA/ECB/* quedan fuera porque RSA no opera por bloques
y ese "ECB" es solo un placeholder de la API.

### Evidencias


**#1** `sources/org/owasp/mastestapp/MastgTest.java:36` (uso inseguro) - Cipher.getInstance("AES") sin modo, usa ECB por defecto

```java
     34 |             Intrinsics.checkNotNullExpressionValue(key, "getBytes(...)");
     35 |             SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
>    36 |             Cipher cipher = Cipher.getInstance("AES");
     37 |             cipher.init(1, secretKeySpec);
     38 |             byte[] bytes = data.getBytes(Charsets.UTF_8);
```

**#2** `sources/org/owasp/mastestapp/MastgTest.java:55` (uso inseguro) - Transformacion con modo ECB explicito

```java
     53 |             Intrinsics.checkNotNullExpressionValue(key, "getBytes(...)");
     54 |             SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
>    55 |             Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
     56 |             cipher.init(1, secretKeySpec);
     57 |             int paddingLength = 16 - (data.length() % 16);
```

**#3** `sources/org/owasp/mastestapp/MastgTest.java:76` (uso inseguro) - Transformacion con modo ECB explicito

```java
     74 |             Intrinsics.checkNotNullExpressionValue(key, "getBytes(...)");
     75 |             SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
>    76 |             Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
     77 |             cipher.init(1, secretKeySpec);
     78 |             byte[] bytes = data.getBytes(Charsets.UTF_8);
```

**#4** `sources/org/owasp/mastestapp/MastgTest.java:95` (uso inseguro) - Transformacion con modo ECB explicito

```java
     93 |             Intrinsics.checkNotNullExpressionValue(key, "getBytes(...)");
     94 |             SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
>    95 |             Cipher cipher = Cipher.getInstance("AES/ECB/ISO10126Padding");
     96 |             cipher.init(1, secretKeySpec);
     97 |             byte[] bytes = data.getBytes(Charsets.UTF_8);
```

**#5** `sources/org/owasp/mastestapp/MastgTest.java:118` (uso inseguro) - Transformacion con modo ECB explicito

```java
    116 |             Intrinsics.checkNotNullExpressionValue(keyGenerateSecret, "generateSecret(...)");
    117 |             Key secretKey = keyGenerateSecret;
>   118 |             Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
    119 |             cipher.init(1, secretKey);
    120 |             byte[] bytes2 = data.getBytes(Charsets.UTF_8);
```

**#6** `sources/org/owasp/mastestapp/MastgTest.java:141` (uso inseguro) - Transformacion con modo ECB explicito

```java
    139 |             Intrinsics.checkNotNullExpressionValue(keyGenerateSecret, "generateSecret(...)");
    140 |             Key secretKey = keyGenerateSecret;
>   141 |             Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
    142 |             cipher.init(1, secretKey);
    143 |             byte[] bytes2 = data.getBytes(Charsets.UTF_8);
```

### Impacto

ECB cifra cada bloque por separado, asi que bloques de texto plano iguales producen bloques
cifrados iguales. Esto deja ver patrones en los datos, permite reordenar o reemplazar bloques
sin que se note y facilita ataques de texto plano conocido o elegido.

### Mitigacion

Usar un modo autenticado como AES/GCM/NoPadding con un IV nuevo y aleatorio en cada operacion
(12 bytes para GCM). Si hace falta CBC, agregar un MAC (encrypt-then-MAC). Evitar
Cipher.getInstance("AES") sin modo explicito.

### Validacion manual

Revisar cada ubicacion y confirmar si el cifrado se aplica sobre datos sensibles.

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
