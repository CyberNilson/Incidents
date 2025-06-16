# 🛡️ Incidente: Phishing con dominio typosquatting – Caso 8817

**ID del Caso:** 8817  
**Fecha:** 2025‑06‑10  
**Origen del ejercicio:** TryHackMe – Simulación SOC  
**Clasificación:** Medium – Phishing (Typosquatting)

---

## 🔎 Resumen

Se identificó una alerta de phishing asociada a un correo enviado desde un dominio que intenta suplantar la marca Microsoft. El mensaje dirigido al usuario `c.allen@thetrydaily.thm` contenía un enlace a un dominio falso (`m1crosoftsupport.co`). El usuario accedió al enlace, y a diferencia de otros casos, el firewall **no bloqueó** la conexión, lo que motivó la **escalación del incidente** para análisis y contención.

---

## 🧪 Análisis técnico

- **Remitente del correo:** `no-reply@m1crosoftsupport.co`
- **Destinatario:** `c.allen@thetrydaily.thm`
- **IP interna del usuario:** `10.20.2.25`
- **Enlace recibido:** `https://m1crosoftsupport.co/login`
- **IP de destino del enlace:** `45.148.10.131`

### Resultados de análisis:
- **VirusTotal:** 13 motores antivirus detectan la IP como maliciosa.
- **AbuseIPDB:** IP `45.148.10.131` con múltiples reportes.
- **Análisis del dominio:** Dominio usa técnica de typosquatting (`m1crosoftsupport.co`)
- **Firewall:** Permitió la conexión.
- **SIEM (Splunk):** Se registró el clic del usuario al enlace.

---

## 🧾 Indicadores de Compromiso (IOCs)

| Tipo       | Valor                              | Observaciones                                  |
|------------|------------------------------------|------------------------------------------------|
| Email      | `no-reply@m1crosoftsupport.co`     | Envío desde dominio typosquatting              |
| URL        | `https://m1crosoftsupport.co/login`| Página de login falsa                          |
| IP         | `45.148.10.131`                    | IP maliciosa, reportada en VirusTotal y AbuseIPDB |
| Usuario    | `c.allen@thetrydaily.thm`          | Usuario afectado                               |
| IP interna | `10.20.2.25`                       | Dirección IP del equipo del usuario            |

---

## 🗺️ Técnicas MITRE ATT&CK

- **T1566.002** – Phishing: Link  
- **T1204.001** – User Execution: Malicious Link  
- **T1583.001** – Acquire Infrastructure: Domains

---

## 🚨 Clasificación final

✅ Confirmado Malicioso  
⚠️ El enlace fue accedido exitosamente  
📈 Caso escalado para análisis posterior

---

## 🛡️ Acciones tomadas

- Se escaló el incidente al equipo de respuesta (Tier 2)
- El dominio fue bloqueado en el firewall y proxy
- Se solicitó análisis forense en el equipo de `c.allen@thetrydaily.thm`
- Se realizó campaña de concientización puntual

---

## 📘 Lecciones aprendidas

- Los dominios con typosquatting pueden eludir filtros básicos
- Importancia de detección temprana y análisis de logs en SIEM
- Necesidad de ampliar controles para dominios sospechosos `.co`

---

## 📎 Evidencias

### 📌 Evento SIEM (Splunk)

![SIEM Alert](../assets/phishing-siem-8817.png)

### 📌 Análisis en VirusTotal

![VirusTotal Result](../assets/virustotal-45.148.10.131.png)

### 📌 Reporte en AbuseIPDB

![AbuseIPDB Result](../assets/abuseipdb-45.148.10.131.png)

### 📌 Página falsa (captura de la URL)

![Fake Login Page](../assets/fake-m1crosoft-login.png)

