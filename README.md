# IP Intelligence Tracker v2.0

**IP Intelligence Tracker** adalah alat OSINT (Open Source Intelligence) untuk menganalisis alamat IP atau domain secara mendalam. Tool ini menggabungkan data dari berbagai sumber (ip-api, ipinfo, ipwho, AbuseIPDB) serta melakukan WHOIS, reverse DNS, pemindaian port, dan penilaian risiko otomatis.

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Fitur Utama

- Geolokasi multi-sumber: ip-api.com, ipinfo.io, ipwho.is
- Deteksi anonimitas: Proxy, VPN, TOR, Hosting/Datacenter, Mobile
- Skor risiko cerdas (0-100%) berdasarkan semua indikator
- Cek reputasi AbuseIPDB: skor kepercayaan & laporan abuse
- WHOIS & Reverse DNS
- Pemindaian port umum (paralel, 20+ port)
- Ekspor laporan: JSON, TXT, HTML
- Mode batch: analisis banyak IP dari file
- Tampilan terminal berwarna (colorama)

## Dependensi

Tool ini membutuhkan Python 3.7+ dan beberapa pustaka tambahan:
``
- requests
- colorama
- dnspython
- python-whois
- tabulate
             

## Instalasi

1. Clone repositori (atau simpan file `multi_ip_location_tool.py`):
   ```bash
   git clone https://github.com/Beelocks/lacak-ip.git
   cd lacak-ip
   pip install -r requirements.txt
   pip install requests colorama dnspython python-whois tabulate


 ## Setel environment variables atau edit langsung di script:
 
  
    export IPINFO_KEY="your_ipinfo_key"
    export ABUSEIPDB_KEY="your_abuseipdb_key"


  ## Penggunaan
     
    python multi_ip_location_tool.py

 ## Tanpa argumen, tool akan masuk ke mode interaktif – Anda bisa memasukkan IP/domain satu per satu.

  ## Analisis satu target
    
    python multi_ip_location_tool.py --ip 8.8.8.8
    python multi_ip_location_tool.py --ip google.com --scan-ports
    python multi_ip_location_tool.py --ip 1.1.1.1 --export html

 ## Batch dari file
 ##  Buat file targets.txt (satu target per baris, boleh ada komentar dengan #):
    
    8.8.8.8
    google.com
    # ini komentar
    1.1.1.1


  ## Jalankan:
    
    python multi_ip_location_tool.py --file targets.txt --export json

##  Argumen CLI
-  Argumen	Deskripsi
    ```bash
    --ip, -i	Alamat IP atau domain target
    --file, -f	File teks berisi daftar target (satu per baris)
    --scan-ports, -p	Lakukan pemindaian port umum
    --export, -e	Format laporan: json, txt, html
    --help, -h	Tampilkan bantuan

## Cara Kerja
Multi-source fetching – tool mengambil data dari:
    ```bash
    
    ip-api.com (gratis, tanpa key) – geolokasi, deteksi proxy/vpn/tor/hosting/mobile

    ipwho.is (gratis, tanpa key) – fallback geolokasi

    ipinfo.io (perlu key) – data ISP, organisasi, hostname yang lebih detail

    AbuseIPDB (perlu key) – skor kepercayaan abuse, laporan publik

    WHOIS & rDNS – menggunakan library whois dan socket.gethostbyaddr

    Port scanning – memeriksa 20 port umum (SSH, HTTP, RDP, MySQL, dll.) secara paralel

    Penilaian risiko – bobot dinamis:

    Proxy (+25), VPN (+25), TOR (+35), Hosting (+10)

    Abuse confidence >75% (+30), >25% (+15)

    Port sensitif terbuka (SSH, RDP, dll.) +5-15 poin

    Skor akhir 0-100%, dikategorikan Rendah, Sedang, Tinggi, Kritis.

Laporan – ditampilkan langsung di terminal dan (opsional) diekspor ke JSON, TXT, atau HTML.



## Contoh Laporan ('terminal' `multi_ip_location_tool.py`);

  
    ══════════════════════════════════════════════════════════════════
                    LAPORAN INTELIJEN IP
    ══════════════════════════════════════════════════════════════════
    Laporan ID : RPT-1747654321
    Dibuat     : 2025-05-19 10:30:45
    Target     : 8.8.8.8

    ┌──────────────────────────────────────────────────────────────┐
    │  1. IDENTITAS IP                                              │
    └──────────────────────────────────────────────────────────────┘
      IP Address           : 8.8.8.8
      Reverse DNS          : dns.google
      ...

    ┌──────────────────────────────────────────────────────────────┐
    │  4. INDIKATOR KEAMANAN                                        │
    └──────────────────────────────────────────────────────────────┘
      Proxy Server         : Bersih
      VPN Node             : Bersih
      TOR Exit Node        : Bersih
      Hosting/Datacenter   : TERDETEKSI
    ...
      Skor Risiko          : [..............] 10%
      Tingkat Risiko       : RENDAH

## Konfigurasi API (tanpa environment variable)

     API_CONFIG["ipinfo"]["key"] = "your_ipinfo_key"
     API_CONFIG["abuseipdb"]["key"] = "your_abuseipdb_key"

## Struktur Hasil Ekspor

    Format	Nama file contoh	Isi
    JSON	ip_report_8_8_8_8_1747654321.json	Semua data mentah + skor risiko
    TXT	ip_report_8_8_8_8_1747654321.txt	Teks polos ringkas (geolokasi, keamanan, port)
    HTML	ip_report_8_8_8_8_1747654321.html	Laporan interaktif dengan CSS minimalis


## Keterbatasan & Catatan
- ip-api.com memiliki batas 45 permintaan per menit (untuk IP publik). Tool akan otomatis melambat pada mode batch.
- Port scanning hanya memeriksa sekitar 20 port umum dan tidak mendeteksi layanan di balik firewall stateful.
- WHOIS tergantung pada server whois yang merespon; beberapa IP tidak memiliki entri whois.
- API AbuseIPDB memerlukan kunci gratis, namun tanpa kunci tool tetap berfungsi (fitur abuse dinonaktifkan).
- Tool ini hanya untuk keperluan edukasi, pengujian keamanan jaringan sendiri, dan OSINT yang sah. Jangan gunakan untuk aktivitas ilegal.

## Pemecahan Masalah
    Masalah	Solusi
    ModuleNotFoundError: No module named 'colorama'	Install dengan pip install colorama
    IPINFO_KEY tidak diset	Set environment variable IPINFO_KEY atau isi langsung di script
    Gagal resolve domain	Pastikan koneksi internet dan DNS server dapat dijangkau
    Port scanning lambat	Gunakan --scan-ports hanya jika diperlukan – secara default tidak dijalankan

## Lisensi
- MIT License – bebas digunakan, dimodifikasi, dan didistribusikan dengan mencantumkan kredit kepada pembuat asli.

      Kredit & Sumber Data
      ip-api.com – geolokasi & deteksi proxy/vpn/tor
      ipinfo.io – data ASN, org, hostname
      ipwho.is – geolokasi cadangan
      AbuseIPDB – database reputasi IP
  
 ## Dibuat untuk komunitas keamanan siber dan OSINT. Jika Anda menemukan bug atau memiliki saran, silakan buka issue di repositori ini.

