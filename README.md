# Siber-Trafik-Analiz
Ağ trafik kayıtlarını (.pcap) analiz eden, şüpheli bağlantıları ve hassas verileri tespit eden interaktif terminal uygulaması.
import os
from scapy.all import *
from scapy.layers.http import HTTPRequest
import colorama
from colorama import Fore, Style
import tkinter as tk
from tkinter import filedialog

colorama.init(autoreset=True)

def siber_analiz_yap(pcap_dosyasi, filtreler=None):
    if filtreler is None:
        filtreler = []

    print(f"\n{Fore.CYAN}{Style.BRIGHT}[*] Detaylı Analiz Başlatılıyor: {pcap_dosyasi}")
    print(f"{Fore.CYAN}" + "="*100)
    print(f"{'TİP':<15} | {'KAYNAK':<20} | {'DETAY / HEDEF':<40} | {'TEHDİT SEVİYESİ'}")
    print("-" * 100)
    
    try:
        paketler = rdpcap(pcap_dosyasi)
        bulgu_sayisi = 0

        for paket in paketler:
            ip_src = paket[IP].src if paket.haslayer(IP) else "Bilinmiyor"
            
            if paket.haslayer(HTTPRequest) and ('http' in filtreler or not filtreler):
                host = paket[HTTPRequest].Host.decode(errors='ignore')
                path = paket[HTTPRequest].Path.decode(errors='ignore')
                threat_level = "Düşük"
                
                if paket.haslayer(Raw):
                    payload = paket[Raw].load.decode(errors='ignore').lower()
                    if any(k in payload for k in ["user", "pass", "login", "sifre"]):
                        threat_level = "Yüksek"
                        print(f"{Fore.RED}{'!!! LOGIN':<15} | {ip_src:<20} | {Fore.RED}Giriş denemesi tespit edildi! | {threat_level}")
                
                print(f"{Fore.GREEN}{'HTTP İSTEK':<15} | {ip_src:<20} | {host}{path:<40} | {threat_level}")
                bulgu_sayisi += 1

            if paket.haslayer(DNSQR) and ('dns' in filtreler or not filtreler):
                query = paket[DNS].qd.qname.decode(errors='ignore')
                threat_level = "Düşük"
                print(f"{Fore.BLUE}{'DNS SORGUSU':<15} | {ip_src:<20} | {query:<40} | {threat_level}")
                bulgu_sayisi += 1

            if paket.haslayer(TCP) and ('port' in filtreler or not filtreler):
                dport = paket[TCP].dport
                if dport in [4444, 31337, 8888]:
                    threat_level = "Orta/Yüksek"
                    print(f"{Fore.YELLOW}{'ŞÜPHELİ PORT':<15} | {ip_src:<20} | Hedef Port: {dport:<34} | {threat_level}")
                    bulgu_sayisi += 1

        print(f"{Fore.CYAN}" + "="*100)
        print(f"{Fore.WHITE}{Style.BRIGHT}[*] Analiz bitti. Toplam {bulgu_sayisi} işlem listelendi.")

    except Exception as e:
        print(f"{Fore.RED}[HATA] Analiz hatası: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)

    print(f"{Fore.MAGENTA}=== GENİŞ KAPSAMLI TRAFİK ANALİZÖRÜ ===")
    dosya_yolu = filedialog.askopenfilename(
        title="PCAP Dosyası Seçin",
        filetypes=[("Packet Capture", "*.pcap *.pcapng")]
    )

    if dosya_yolu:
        print("\nHangi protokollerin loglarını görmek istiyorsunuz? (birden fazla seçebilirsiniz, araya virgül koyun)")
        print("1) HTTP")
        print("2) DNS")
        print("3) Şüpheli Portlar")
        print("4) Hepsi")

        secim = input("Seçiminiz (örn: 1,2): ").strip().replace(" ", "")
        secimler = secim.split(",")

        filtre_dict = {"1": "http", "2": "dns", "3": "port", "4": None}

        filtreler = []
        if "4" in secimler:
            filtreler = []
        else:
            for s in secimler:
                protokol = filtre_dict.get(s)
                if protokol:
                    filtreler.append(protokol)

        siber_analiz_yap(dosya_yolu, filtreler)
    else:
        print(f"{Fore.RED}[!] Dosya seçilmedi.")
    
    root.destroy()
    input("\nKapatmak için Enter'a basın...")
