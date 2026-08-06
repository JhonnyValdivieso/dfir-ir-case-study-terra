# Baseline de Hardening — Post-incidente Caso Terra

Controles derivados directamente de los huecos explotados en el incidente.
Cada control referencia la tecnica ATT&CK que neutraliza.

## 1. Correo (T1566.001)

| Control | Implementacion | Estado |
|---|---|---|
| SPF | Registro TXT con politica `-all` (hard fail) | Pendiente |
| DKIM | Firma de todo el correo saliente, rotacion de claves semestral | Pendiente |
| DMARC | `p=reject; rua=mailto:dmarc@<dominio>` tras 30 dias en `p=none` | Pendiente |
| Lookalike domains | Monitorizacion y bloqueo de dominios typosquatted (`outluok.co`) | Pendiente |
| Banner externo | Aviso visible en todo correo procedente de fuera de la organizacion | Pendiente |

## 2. Endpoint — AppLocker / WDAC (T1204.002, T1059.001)

Reglas `Deny` para el grupo `Everyone`, con excepcion explicita para
administradores y rutas firmadas:

```
%OSDRIVE%\Users\*\AppData\Local\Temp\*
%OSDRIVE%\Users\*\AppData\Roaming\*
%OSDRIVE%\Users\*\Downloads\*
%OSDRIVE%\$Recycle.Bin\*
```

Bloqueo adicional por hash y por nombre de herramientas de doble uso:

| Herramienta | Hash conocido |
|---|---|
| `nc.exe` | `b3b207dfab2f429cc352ba125be32a0cae69fe4bf8563ab7d0128bba8c57a71c` |
| `ncat.exe`, `psexec.exe`, `nmap.exe` | Bloqueo por nombre de publicador |

> Desplegar primero en modo **Audit Only** durante 2-4 semanas para inventariar
> el software legitimo que se ejecuta desde esas rutas. Pasar a Enforce despues.

## 3. Extensiones de archivo (T1036.003)

`Computer Configuration -> Policies -> Administrative Templates -> Windows Components -> File Explorer`

Desactivar *"Ocultar las extensiones de archivo para tipos de archivo conocidos"*.
Control de coste cero que neutraliza directamente la doble extension `.pdf.exe`.

## 4. Firewall gestionado por GPO (T1562.001)

`Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Windows Defender Firewall with Advanced Security`

- Perfiles Domain, Private y Public forzados a **On**.
- El usuario local no puede modificarlos; la politica se reimpone en cada refresco de GPO.
- Alerta en el SIEM ante cualquier intento de cambio (ver `detections/04-*.eql`).

## 5. PowerShell (T1059.001)

| Control | Detalle |
|---|---|
| Constrained Language Mode | Aplicado a usuarios estandar via AppLocker |
| Script Block Logging | Event ID **4104** — habilitado y enviado al SIEM |
| Module Logging | Event ID **4103** |
| Transcription | Salida a share centralizado de solo escritura |
| ExecutionPolicy | `AllSigned` (no es control de seguridad por si solo, pero eleva el coste) |

## 6. Identidad (T1136.001, T1078.003)

- Alerta inmediata ante creacion de cuentas locales en endpoints (`detections/01-*.eql`).
- Revision periodica de miembros del grupo `Administrators` en todos los hosts.
- LAPS o equivalente para la cuenta de administrador local.

## 7. Concienciacion

Simulacros de phishing trimestrales centrados en los dos vectores que
funcionaron en este incidente: **urgencia artificial** y **doble extension**.
Metrica objetivo: tasa de clic por debajo del 5% y tasa de reporte por encima del 60%.
