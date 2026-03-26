import os
from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP, TCP, ICMP
from scapy.layers.dns import DNS, DNSQR
import colorama
from colorama import Fore, Style
import tkinter as tk
from tkinter import filedialog

colorama.init(autoreset=True)

def ekrani_temizle():
    os.system('cls' if os.name == 'nt' else 'clear')

def wireshark_filtre_uret(tip, ip=None, ekstra=None):
    if tip == "HTTP":
        return f"http && ip.src == {ip}" if ip else "http"
    elif tip == "LOGIN":
        return f'http contains "password" && ip.src == {ip}' if ip else 'http contains "password"'
    elif tip == "DNS":
        return f"dns && ip.src == {ip}" if ip else "dns"
    elif tip == "ARP":
        return "arp"
    elif tip == "ICMP":
        return f"icmp && ip.src == {ip}" if ip else "icmp"
    elif tip == "PORT":
        return f"tcp.port == {ekstra}"
    elif tip == "FTP":
        return f"ftp && ip.src == {ip}" if ip else "ftp"
    return ""

def siber_analiz_yap(pcap_dosyasi, filtreler=None):
    if filtreler is None:
        filtreler = []

    print(f"\n{Fore.CYAN}{Style.BRIGHT}[*] Analiz başlatılıyor: {pcap_dosyasi}")
    print(f"{Fore.CYAN}" + "="*110)
    print(f"{'TİP':<15} | {'KAYNAK':<20} | {'DETAY / HEDEF':<45} | {'SEVİYE'}")
    print("-" * 110)
    
    try:
        paketler = rdpcap(pcap_dosyasi)
        bulgu_sayisi = 0

        for paket in paketler:
            ip_src = paket[IP].src if paket.haslayer(IP) else (paket.src if paket.haslayer(Ether) else "Bilinmiyor")

            # HTTP
            if paket.haslayer(HTTPRequest) and ('http' in filtreler or not filtreler):
                host = paket[HTTPRequest].Host.decode(errors='ignore') if paket[HTTPRequest].Host else "Bilinmiyor"
                path = paket[HTTPRequest].Path.decode(errors='ignore') if paket[HTTPRequest].Path else ""
                threat_level = "Düşük"

                if paket.haslayer(Raw):
                    payload = paket[Raw].load.decode(errors='ignore').lower()
                    if any(k in payload for k in ["user", "pass", "login", "sifre", "password"]):
                        threat_level = "YÜKSEK"
                        filtre = wireshark_filtre_uret("LOGIN", ip_src)
                        print(f"{Fore.RED}{'!!! LOGIN':<15} | {ip_src:<20} | HTTP form verisi tespit edildi | {threat_level}")
                        print(f"{Fore.WHITE}   ↳ Filter: {filtre}")

                filtre = wireshark_filtre_uret("HTTP", ip_src)
                print(f"{Fore.GREEN}{'HTTP':<15} | {ip_src:<20} | {host}{path[:35]:<45} | {threat_level}")
                print(f"{Fore.WHITE}   ↳ Filter: {filtre}")
                bulgu_sayisi += 1

            # DNS
            elif paket.haslayer(DNSQR) and ('dns' in filtreler or not filtreler):
                query = paket[DNS].qd.qname.decode(errors='ignore')
                filtre = wireshark_filtre_uret("DNS", ip_src)
                print(f"{Fore.BLUE}{'DNS':<15} | {ip_src:<20} | {query:<45} | Düşük")
                print(f"{Fore.WHITE}   ↳ Filter: {filtre}")
                bulgu_sayisi += 1

            # ARP
            elif paket.haslayer(ARP) and ('arp' in filtreler or not filtreler):
                op = "İSTEK" if paket[ARP].op == 1 else "YANIT"
                color = Fore.YELLOW if op == "İSTEK" else Fore.MAGENTA
                filtre = wireshark_filtre_uret("ARP")
                print(f"{color}{'ARP':<15} | {paket[ARP].psrc:<20} | {paket[ARP].hwsrc} -> {op:<34} | Bilgi")
                print(f"{Fore.WHITE}   ↳ Filter: {filtre}")
                bulgu_sayisi += 1

            # ICMP
            elif paket.haslayer(ICMP) and ('icmp' in filtreler or not filtreler):
                filtre = wireshark_filtre_uret("ICMP", ip_src)
                print(f"{Fore.CYAN}{'ICMP':<15} | {ip_src:<20} | Tip: {paket[ICMP].type:<39} | Düşük")
                print(f"{Fore.WHITE}   ↳ Filter: {filtre}")
                bulgu_sayisi += 1

            # TCP / FTP
            elif paket.haslayer(TCP):
                dport = paket[TCP].dport

                if ('port' in filtreler or not filtreler) and dport in [4444, 31337, 8888, 9999]:
                    filtre = wireshark_filtre_uret("PORT", ekstra=dport)
                    print(f"{Fore.RED}{Style.BRIGHT}{'KRİTİK PORT':<15} | {ip_src:<20} | Port: {dport:<36} | YÜKSEK")
                    print(f"{Fore.WHITE}   ↳ Filter: {filtre}")
                    bulgu_sayisi += 1

                if ('ftp' in filtreler or not filtreler) and (dport == 21 or paket[TCP].sport == 21):
                    if paket.haslayer(Raw):
                        payload = paket[Raw].load.decode(errors='ignore').strip()
                        if any(k in payload.upper() for k in ["USER", "PASS", "LOGIN"]):
                            filtre = wireshark_filtre_uret("FTP", ip_src)
                            print(f"{Fore.RED}{'FTP SIZINTI':<15} | {ip_src:<20} | Veri: {payload:<35} | KRİTİK")
                            print(f"{Fore.WHITE}   ↳ Filter: {filtre}")
                            bulgu_sayisi += 1

        print(f"{Fore.CYAN}" + "="*110)
        print(f"{Fore.WHITE}{Style.BRIGHT}[*] Analiz tamamlandı. Toplam {bulgu_sayisi} kayıt bulundu.")

    except Exception as e:
        print(f"{Fore.RED}[HATA] {e}")

if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)

    while True:
        ekrani_temizle()
        print(f"{Fore.MAGENTA}{Style.BRIGHT}=== TRAFİK ANALİZ ARACI ===")
        print(f"{Fore.WHITE}Analiz için bir PCAP dosyası seçin.\n")
        
        dosya_yolu = filedialog.askopenfilename(
            title="PCAP Dosyası Seç",
            filetypes=[("Packet Capture", "*.pcap *.pcapng")]
        )

        if not dosya_yolu:
            print(f"{Fore.YELLOW}[!] Dosya seçilmedi. Program sonlandırılıyor.")
            break

        print(f"{Fore.GREEN}[+] Dosya: {os.path.basename(dosya_yolu)}")
        print("\nAnaliz türü seçin:")
        print("1) HTTP")
        print("2) DNS")
        print("3) ARP")
        print("4) ICMP")
        print("5) Port & FTP")
        print("6) Tümü")
        print("0) Geri dön")

        secim = input("\nSeçim: ").strip().replace(" ", "")
        
        if secim == "0":
            continue

        secimler = secim.split(",")
        filtre_haritasi = {
            "1": ["http"],
            "2": ["dns"],
            "3": ["arp"],
            "4": ["icmp"],
            "5": ["port", "ftp"]
        }

        filtreler = []
        if "6" not in secimler:
            for s in secimler:
                if s in filtre_haritasi:
                    filtreler.extend(filtre_haritasi[s])

        siber_analiz_yap(dosya_yolu, filtreler)
        
        print(f"\n{Fore.YELLOW}" + "-"*60)
        devam = input(f"{Fore.WHITE}Yeni analiz yapmak ister misiniz? (e/h): ").lower().strip()
        if devam != 'e':
            print(f"{Fore.MAGENTA}[*] Program sonlandırıldı.")
            break

    root.destroy()
