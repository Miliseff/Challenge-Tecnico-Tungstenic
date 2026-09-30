# Reporte apkscan

- Objetivo: `MASTG-DEMO-0061.apk`
- Fecha: 2026-09-30T20:35:01
- Resultado: 0 vulnerables, 0 a revisar, 4 sin hallazgos

| Test | MASWE | Estado | Severidad | Evidencias |
|---|---|---|---|---|
| MASTG-TEST-0212 | MASWE-0003 | SIN HALLAZGOS | Alta | 0 |
| MASTG-TEST-0221 | MASWE-0007 | SIN HALLAZGOS | Alta | 0 |
| MASTG-TEST-0232 | MASWE-0007 | SIN HALLAZGOS | Alta | 0 |
| MASTG-TEST-0291 | MASWE-0038 | PROTEGIDO | Media | 1 |

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

- Estado: **PROTEGIDO**
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


**#1** `sources/org/owasp/mastestapp/MastgTest.java:32` (proteccion aplicada) - FLAG_SECURE aplicado a una ventana

```java
     30 |     public final String mastgTest() {
     31 |         if (this.context instanceof Activity) {
>    32 |             ((Activity) this.context).getWindow().addFlags(8192);
     33 |             return "SUCCESS!!\n\nThe FLAG_SECURE has been set";
     34 |         }
```

> la proteccion existe, pero hay que confirmar que cubre todas las pantallas con datos sensibles

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

### Referencias

- https://github.com/OWASP/mastg/blob/master/tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0291.md
- https://developer.android.com/security/fraud-prevention/activities#flag_secure
