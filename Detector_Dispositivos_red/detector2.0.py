import socket
import ipaddress
from scapy.all import ARP, Ether, srp

def obtener_cidr():
    # Obtiene la IP local de la máquina
    ip_local = socket.gethostbyname(socket.gethostname())
    
    # Máscara típica de red doméstica
    mascara = "255.255.255.0"
    
    # Convierte a formato CIDR
    red = ipaddress.IPv4Network(f"{ip_local}/{mascara}", strict=False)
    
    return str(red)

def scan_network(timeout=2):
    cidr = obtener_cidr()
    print(f"[+] Escaneando red: {cidr}")

    arp_request = ARP(pdst=cidr)  # Petición ARP
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast Ethernet
    packet = broadcast / arp_request

    answered, _ = srp(packet, timeout=timeout, verbose=False)

    devices = []
    for _, received in answered:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

if __name__ == "__main__":
    dispositivos = scan_network()
    print("\nDispositivos encontrados:")
    for dispositivo in dispositivos:
        print(f"IP: {dispositivo['ip']}, MAC: {dispositivo['mac']}")
