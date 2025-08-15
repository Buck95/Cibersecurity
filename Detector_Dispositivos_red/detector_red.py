#importamos las librerias necesarias para este proyecto 
from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup
import socket
import ipaddress

#Creamos las funciones 

def scan_network(cidr: str, timeout: int = 2): #Escaneamos la red "cidr" con ARP y devuelve una lista de dicts:[{'ip': str, 'mac': str, 'hostname': str}]
    arp_request = ARP(pdst=cidr) #Preguntamos ¿Quien tiene esas IPs? 
    broadcast = Ether(dst = "ff:ff:ff:ff:ff:ff") #Trama Ethernet a broadcast
    packet = broadcast / arp_request #Ethernet + ARP
    
    answered, _= srp(packet, timeout=timeout, verbose=False) # Enviar y recibir L2
    devices = []

    for _, received in answered:   # Cada respuesta ARP
        ip = received.psrc #IP del host que respondio
        mac = received.hwsrc #MAC del host que respondio
        
        # Intentamos ahora resolver el nombre de host (PTR); Si falla, dejar vacio
        
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            hostname = ""
            
        devices.append({"ip": ip, "mac": mac, "hostname": hostname})
    
    return devices

def lookup_vendor(mac: str) -> str: #Devuelve el fabricante de una MAC usando mac_vendor_lookup. Si no se encuentra o no hay base local, retorna 'Unknown vendor'
    try:
        return MacLookup().lookup(mac)
    except Exception:
        return "unknown vendor"
    
#Programa principal
if __name__ == "__main__":
    cidr = input ("Introduce la red a escanear: ").strip()
    print("\n[+] Escaneando la red (Necesita permisos de administrador/root)...\n")
    
    try:
        devices = scan_network(cidr)
    except PermissionError:
        print("Error: Ejecuta el script con privilegios elevados (Administrador/Root).")
        raise
    except Exception as e:
        print(f"Error durante el escaneo: {e}")
        raise
    
    #Ordenamos por IP para una salida limpia 
    devices_sorted = sorted(
        devices,
        key=lambda d: ipaddress.IPv4Address(d["ip"])
    )
    
    #Creamos la cabecera de la tabla 
    print("{:<16} {:<18} {:<30} {}".format("IP", "MAC", "Vendor", "Hostname"))
    
    #Filas
    for d in devices_sorted:
        vendor = lookup_vendor(d["mac"])
        print("{:<16} {:<18} {:<30} {}".format(d["ip"], d["mac"], vendor, d["hostname"]))
        
    print(f"\n[✓] Dispositivos encontrados: {len(devices_sorted)}")
