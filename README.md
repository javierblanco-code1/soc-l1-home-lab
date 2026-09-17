# Home Lab SOC L1 — Detección de Amenazas con Wazuh

Proyecto práctico de ciberseguridad orientado a un rol **SOC Analyst L1**. Consiste en un laboratorio de detección construido desde cero en VirtualBox, donde se simulan técnicas reales de ataque (framework **MITRE ATT&CK**) usando **Atomic Red Team**, y se valida su detección en un **SIEM Wazuh**.

## Objetivo

Demostrar capacidad práctica para:
- Desplegar y configurar un SIEM (Wazuh) desde cero.
- Instrumentar un endpoint Windows con telemetría de nivel forense (Sysmon).
- Simular técnicas de adversarios reales mapeadas a MITRE ATT&CK.
- Analizar alertas, identificar la cadena de ejecución de un proceso y documentar hallazgos como lo haría un analista SOC L1.

## Arquitectura del laboratorio

```
┌─────────────────────────────┐         ┌──────────────────────────────┐
│   WAZUH-SIEM (Ubuntu 22.04)  │         │   WIN-VICTIMA (Windows 11)     │
│   192.168.56.10               │◄───────►│   192.168.56.20                │
│   Wazuh Manager + Indexer     │  agente │   Agente Wazuh v4.9.2          │
│   + Dashboard v4.9             │ Wazuh  │   Sysmon v15.22 (config         │
│                                │         │   SwiftOnSecurity)              │
└─────────────────────────────┘         │   Invoke-AtomicRedTeam          │
                                          └──────────────────────────────┘

Red interna aislada (VirtualBox Host-Only): 192.168.56.0/24
```

**Componentes:**

| Componente | Detalle |
|---|---|
| Hipervisor | Oracle VirtualBox, red Host-Only aislada (192.168.56.0/24) |
| SIEM | Wazuh 4.9 (manager + indexer + dashboard, instalación todo-en-uno) sobre Ubuntu Server 22.04 |
| Endpoint víctima | Windows 11 Enterprise LTSC 2024 |
| Telemetría | Sysmon v15.22 con configuración pública de [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config) |
| Simulación de ataques | [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam) (Red Canary) |
| Framework de referencia | MITRE ATT&CK |

## Metodología

1. Se despliega la técnica ATT&CK usando Atomic Red Team en el endpoint víctima.
2. Sysmon captura el evento a nivel de sistema operativo (creación de procesos, línea de comandos, proceso padre/hijo).
3. El agente Wazuh envía el evento al manager.
4. Las reglas del *ruleset* de Wazuh (basadas en Sysmon Event ID 1) evalúan el evento y generan una alerta si el patrón coincide con comportamiento sospechoso.
5. Se documenta la alerta: regla disparada, severidad, y cadena de ejecución completa.

## Caso de detección #1 — T1057: Process Discovery

**Técnica MITRE ATT&CK:** [T1057 - Process Discovery](https://attack.mitre.org/techniques/T1057/)
**Táctica:** Discovery
**Test ejecutado:** Atomic Test #2 — *Process Discovery - tasklist*

### Simulación

Ejecutado en PowerShell (como administrador) en `WIN-VICTIMA`:

```powershell
Invoke-AtomicTest T1057 -TestNumbers 2
```

Resultado: `Exit code: 0` — `Done executing test: T1057-2 Process Discovery - tasklist`

### Detección en Wazuh

Se generaron **2 alertas** para el mismo evento, correspondientes a distintas reglas del ruleset de Sysmon:

| Rule ID | Descripción | Nivel |
|---|---|---|
| 92052 | Windows command prompt started by an abnormal process | 4 |
| 92032 | Suspicious Windows cmd shell execution | 3 |

**Lógica de la regla 92052** (`0800-sysmon_id_1.xml`): dispara cuando `cmd.exe` es lanzado por un proceso padre que no sea `explorer.exe` ni el propio `cmd.exe` — es decir, cuando el intérprete de comandos es invocado de forma "anómala" respecto al uso normal de un usuario.

### Cadena de ejecución observada

```
powershell.exe
   └── cmd.exe  ("cmd.exe" /c tasklist)
```

| Campo | Valor |
|---|---|
| `data.win.eventdata.parentImage` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| `data.win.eventdata.image` | `C:\Windows\System32\cmd.exe` |
| `data.win.eventdata.commandLine` | `"cmd.exe" /c tasklist` |
| `data.win.eventdata.originalFileName` | `Cmd.Exe` |
| `data.win.eventdata.integrityLevel` | High |
| `agent.name` / `agent.ip` | WIN-VICTIMA / 192.168.56.20 |

### Interpretación

Este comportamiento es exactamente el que produciría un atacante en fase de reconocimiento post-explotación: tras obtener una shell (por ejemplo vía PowerShell), listar los procesos en ejecución para identificar software de seguridad, herramientas de administración o procesos de interés antes de continuar el ataque. El hecho de que `cmd.exe` sea invocado por `powershell.exe` en vez de por el usuario directamente (`explorer.exe`) es la señal que la regla de Wazuh utiliza para distinguir esto de un uso normal del sistema.

## Próximos pasos

- [ ] Simular técnicas adicionales (credential access, persistence, lateral movement) y documentar cada caso siguiendo el mismo formato.
- [ ] Capturas de pantalla del dashboard de Wazuh para cada caso.
- [ ] Reglas personalizadas para casos no cubiertos por el ruleset por defecto.

## Créditos

- [Wazuh](https://wazuh.com/) — plataforma SIEM/XDR open source.
- [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) (Sysinternals/Microsoft).
- [sysmon-config de SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config).
- [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam) (Red Canary).
- [MITRE ATT&CK®](https://attack.mitre.org/).
