import socket
import ssl
import time

def escanear_puerto(ip, puerto):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        resultado = sock.connect_ex((ip, puerto))
        if resultado == 0:
            servicio = identificar_servicio(sock, puerto, ip)
            sock.close()
            return True, servicio
        sock.close()
        return False, None
    except:
        return False, None

def identificar_servicio(sock, puerto, ip):
    try:
        if puerto == 21:  # FTP
            respuesta = sock.recv(1024).decode(errors="ignore")
            return f"FTP: {respuesta.strip()}"
        elif puerto == 22:  # SSH
            respuesta = sock.recv(1024).decode(errors="ignore")
            return f"SSH: {respuesta.strip()}"
        elif puerto == 25:  # SMTP
            respuesta = sock.recv(1024).decode(errors="ignore")
            return f"SMTP: {respuesta.strip()}"
        elif puerto == 53:  # DNS
            return "DNS (posible servidor de nombres)"
        elif puerto == 80:  # HTTP
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            respuesta = sock.recv(1024).decode(errors="ignore")
            for linea in respuesta.split("\n"):
                if "Server:" in linea:
                    return linea.strip()
            return "HTTP (sin info de servidor)"
        elif puerto == 443:  # HTTPS
            contexto = ssl.create_default_context()
            with contexto.wrap_socket(sock, server_hostname=ip) as ssock:
                ssock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                respuesta = ssock.recv(1024).decode(errors="ignore")
                for linea in respuesta.split("\n"):
                    if "Server:" in linea:
                        return linea.strip()
            return "HTTPS (sin info. de servidor)"
        else:
            return "Servicio desconocido"
    except:
        return "Servicio desconocido"

# Pedir datos al usuario
ip = input("Introduce la IP a escanear: ")
start_port = int(input("Puerto inicial: "))
end_port = int(input("Puerto final: "))

print(f"\nEscaneando {ip} desde el puerto {start_port} al {end_port}...\n")
tiempo_inicio = time.time()

for puerto in range(start_port, end_port + 1):
    abierto, servicio = escanear_puerto(ip, puerto)
    if abierto:
        print(f"[+] Puerto {puerto} ABIERTO → {servicio}")
    else:
        print(f"[-] Puerto {puerto} cerrado")

duracion = time.time() - tiempo_inicio
print(f"\nEscaneo completado en {round(duracion, 2)} segundos.")
