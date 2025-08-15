from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup
import socket

# -----------------------
# Función para escanear dispositivos en la red
# -----------------------
def scan_network(target_ip):
    arp_request = ARP(pdst=target_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    result = srp(packet, timeout=2, verbose=False)[0]

    devices = []
    for sent, received in result:
        mac = received.hwsrc
        try:
            vendor = MacLookup().lookup(mac)
        except:
            vendor = "Unknown"
        devices.append({
            "ip": received.psrc,
            "mac": mac,
            "vendor": vendor
        })
    return devices

# -----------------------
# Función para escanear puertos de una IP
# -----------------------
def scan_ports(ip):
    open_ports = []
    for port in range(1, 1024):  # Escanea del puerto 1 al 1024
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass
    return open_ports

# -----------------------
# Main
# -----------------------
if __name__ == "__main__":
    target_ip = "192.168...."  # Cambia por el rango de tu red
    devices = scan_network(target_ip)

    print("📡 Dispositivos detectados en la red:")
    print("{:<16} {:<18} {:<30} {:<20}".format("IP", "MAC Address", "Vendor", "Open Ports"))
    print("-" * 90)

    for device in devices:
        ports = scan_ports(device['ip'])
        ports_str = ", ".join(map(str, ports)) if ports else "None"
        print("{:<16} {:<18} {:<30} {:<20}".format(device['ip'], device['mac'], device['vendor'], ports_str))
