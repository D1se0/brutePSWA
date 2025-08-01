# 🛡️ BrutePSWA - Herramienta de Fuerza Bruta para PowerShell Web Access

**BrutePSWA** es una herramienta en **Python 3** diseñada para realizar ataques de fuerza bruta contra **PowerShell Web Access (PSWA)**.  
Permite probar múltiples contraseñas de forma controlada para detectar credenciales válidas, identificando además escenarios de sesiones excedidas o usuarios sin privilegios.

> ⚠️ **Aviso legal:** Esta herramienta es solo para fines educativos y pruebas en entornos controlados.  
> El uso en sistemas que no te pertenecen puede ser ilegal.  

---

## ✨ Características

- Fuerza bruta contra portales de **PowerShell Web Access** (`/pswa/en-US/logon.aspx`)
- Detección de:
  - ✅ Autenticación correcta
  - ⚠️ Límite de sesiones por usuario excedido
  - ⚠️ Usuario sin privilegios para acceder a PSWA
- Manejo de errores ante IPs inválidas o inaccesibles
- Detección de éxito también si existen **sesiones desconectadas disponibles**
- Permite parametrizar:
  1. **IP del objetivo**
  2. **Usuario a probar**
  3. **Diccionario de contraseñas**

---

## 🖥️ Uso de la Herramienta

```bash
python3 brutePSWA.py <IP> <usuario> <diccionario>
```

Ejemplo:

```bash
python3 brutePSWA.py 192.168.1.38 '.\Administrator' rockyou.txt
```

Salida esperada:

```
[+] Verificando objetivo 192.168.177.134...
[+] Objetivo válido, iniciando fuerza bruta contra .\Administrator con rockyou.txt

[1] Probando password: admin123
[2] Probando password: P@ssw0rd!
[+] ¡Contraseña encontrada!: P@ssw0rd!
```

---

## ⚙️ Preparación de un Entorno de Pruebas en Windows Server 2019/2022

Para probar BrutePSWA, primero debemos configurar PowerShell Web Access en un servidor Windows.

### 1️⃣ Requisitos previos

`Windows Server 2019 o 2022`

Credenciales de `administrador`

Acceso a `PowerShell` con permisos elevados

### 2️⃣ Habilitar `PowerShell Web Access (PSWA)`

Ejecuta PowerShell como Administrador y corre el siguiente script:

```powershell
# Comprobar privilegios de administrador
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Please run this script as an Administrator!"
    Exit
}

# Instalar el rol de PowerShell Web Access
try {
    Install-WindowsFeature -Name WindowsPowerShellWebAccess -IncludeManagementTools
    Write-Host "Windows PowerShell Web Access feature installed successfully." -ForegroundColor Green
} catch {
    Write-Error "Failed to install Windows PowerShell Web Access feature: $_"
    Exit
}

# Instalar IIS si no está presente
if (!(Get-WindowsFeature Web-Server).Installed) {
    Install-WindowsFeature -Name Web-Server -IncludeManagementTools
    Write-Host "IIS installed successfully." -ForegroundColor Green
}

# Configurar el gateway PSWA con certificado de prueba
try {
    Install-PswaWebApplication -UseTestCertificate
    Write-Host "PowerShell Web Access gateway configured successfully." -ForegroundColor Green
} catch {
    Write-Error "Failed to configure PowerShell Web Access gateway: $_"
    Exit
}

# Añadir regla de autorización global (solo para laboratorio)
Add-PswaAuthorizationRule -UserName * -ComputerName * -ConfigurationName *

Write-Host "PowerShell Web Access has been enabled and configured." -ForegroundColor Green
Write-Host "Warning: This configuration allows all users to access all computers. Please adjust the authorization rules for your specific security requirements." -ForegroundColor Yellow
```

🔹 Esto instalará PSWA y lo expondrá en:

```bash
https://<IP-Servidor>/pswa
```

### 3️⃣ Referencias y documentación

Script de instalación:

[-> Codigo original GitHub (MHaggis)](https://gist.github.com/MHaggis/7e67b659af9148fa593cf2402edebb41)

Artículo de Splunk sobre riesgos de PSWA:

[-> Informacion de PSWA](https://www.splunk.com/en_us/blog/security/powershell-web-access-your-network-s-backdoor-in-plain-sight.html)

---

## 🧪 Consejos de Laboratorio

Usa VMs aisladas para tus pruebas (`VirtualBox`, `VMware` o `Hyper-V`)

Modifica reglas de `PSWA` para usuarios específicos si quieres simular accesos restringidos

---

## ⚠️ Advertencia

Esta herramienta debe usarse solo en entornos controlados.
El uso no autorizado en sistemas de terceros puede ser ilegal y conllevar responsabilidades penales.

---

## ✍️ Autor

Herramienta desarrollada para fines educativos y de pentesting ético.
Inspirada en investigaciones de `PSWA` como vector de riesgo en entornos Windows Server.
