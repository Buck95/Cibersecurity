import socket # Permite la comunicación entre computadoras mediante protocolos como TCP/IP. Aqui los usamos para probar conexiones a puertos.
import time # Nos permite medir cuanto tarda el escaneo completo.

#Pediremos al usuario la IP y el rango de puertos 

ip = input ("Introduce la IP que deseas escanear: ")
start_port = int(input("Puerto Inicial: "))
end_port = int(input("Puerto final: "))

#Ahora definimos una función para escanear un solo puerto

def escanear_puerto(ip, puerto):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1) # Este es el tiempo de espera, que sera igual a 1 segundo
    result = sock.connect_ex((ip, puerto))
    sock.close()
    return result == 0

#Creamos un bucle para escaner el rango 

print(f"\nEscaneando {ip} desde el puerto {start_port} al {end_port}...\n")
tiempo_inicio = time.time()

for puerto in range(start_port, end_port + 1):
    if escanear_puerto(ip, puerto):
        print(f"[+] Puerto {puerto} está ABIERTO")
    else:
        print(f"[-] Puerto {puerto} está CERRADO")

duración = time.time() - tiempo_inicio
print(f"\nEscaneo completo en {round(duración, 2)} segundos.")