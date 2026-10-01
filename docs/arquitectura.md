# Diagramas

Los diagramas están en Mermaid

## Flujo de una ejecucion

```mermaid
sequenceDiagram
    actor U as Usuario
    participant CLI as cli.py
    participant REG as registry.py
    participant DEC as decompile.py
    participant ENG as engine.py
    participant NUC as nuclei
    participant EVI as evidence.py
    participant REP as reporters

    U->>CLI: apkscan app.apk --md reporte.md
    CLI->>REG: discover() y select(--only / --skip)
    REG-->>CLI: modulos validados
    CLI->>DEC: decompile(app.apk)
    DEC-->>CLI: directorio con sources/ y resources/
    CLI->>ENG: scan(directorio, modulos)
    ENG->>NUC: un solo proceso con los templates de todos los modulos
    NUC-->>ENG: JSONL (template-id, archivo, texto extraido)
    ENG->>EVI: locate(hit)
    EVI-->>ENG: evidencia con archivo, linea y contexto
    ENG->>ENG: evaluate() segun el modo de cada modulo
    ENG-->>CLI: Report
    CLI->>REP: consola, markdown, json
    CLI-->>U: reporte y codigo de salida
```

## Estructura de un módulo

```mermaid
flowchart TB
    subgraph modulo["modules/mastg_test_0291/"]
        Y[module.yaml<br/>titulo, descripcion, impacto,<br/>mitigacion, severidad, mode]
        subgraph tpl["templates/"]
            T1["flag-secure-set.yaml<br/>tag role-protection"]
            T2["recents-screenshot.yaml<br/>tag role-protection"]
            T3["flag-secure-cleared.yaml<br/>tag role-weakening"]
        end
    end
    Y --> R[registry.py]
    tpl --> R
    R --> E[engine.py]
    tpl -->|-t| N[nuclei]
```

El motor no tiene referencias a ningún test concreto. 
Todo lo que cambia entre un test y otro vive en la carpeta del módulo.

## Cómo se decide el estado

```mermaid
flowchart TD
    S([Evidencias de nuclei del modulo]) --> M{mode}
    M -->|presence| P{hay evidencias?}
    P -->|si| V1[VULNERABLE<br/>se listan las evidencias]
    P -->|no| OK1[SIN HALLAZGOS]
    M -->|absence| A{hay role-protection?}
    A -->|no| V2[VULNERABLE por ausencia<br/>patrones buscados, archivos analizados,<br/>activities sin proteccion]
    A -->|si| W{hay role-weakening?}
    W -->|si| R[REVISAR]
    W -->|no| OK2[PROTEGIDO<br/>se muestra donde se aplica]
```

## Prueba dinámica (MASTG-TEST-0291)

```mermaid
flowchart TD
    I[AndroidManifest.xml] -->|lista de activities| L
    L[por cada activity] --> S[adb shell am start -W -n paquete/activity]
    S -->|error o permiso denegado| SK[omitida]
    S --> F[adb shell dumpsys window]
    F --> G{la activity tiene el foco?}
    G -->|no| SK
    G -->|si| FL[leer fl= de la ventana en foco]
    FL --> C[adb exec-out screencap -p]
    C --> B[decodificar PNG y revisar si esta en negro]
    B --> D{FLAG_SECURE?}
    D -->|si| PR[protegida]
    D -->|no| UN[sin proteccion]
    PR --> M[dynamic.apply]
    UN --> M
    SK --> M
    M --> ST[puede subir el estado a REVISAR]
```

Cuando la prueba dinámica contradice al análisis estático, el estado pasa a `REVISAR` y se deja una nota explicando el motivo.
