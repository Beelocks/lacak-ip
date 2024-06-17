import requests

# Masukkan API keys Anda dari layanan yang Anda pilih
api_keys = {
    'ipinfo': 'your_ipinfo_api_key_here',
    'ipstack': 'your_ipstack_api_key_here',
    'ipapi': 'your_ipapi_api_key_here',
    # Masukkan API keys lainnya jika Anda menggunakan lebih dari satu layanan
}

def get_ip_location(ip_address):
    results = {}
    
    for service, api_key in api_keys.items():
        url = f"https://{service}.io/{ip_address}/geo?token={api_key}"
        response = requests.get(url)
        
        if response.status_code == 200:
            data = response.json()
            results[service] = data
        else:
            print(f"Error fetching data from {service}: {response.status_code}")
    
    return results

def main():
    ip_address = input("Masukkan IP Address: ")
    location_data = get_ip_location(ip_address)
    
    if location_data:
        print(f"Lokasi IP {ip_address}:")
        for service, data in location_data.items():
            print(f"--- {service} ---")
            print(f"Negara: {data['country']}")
            print(f"Kota: {data['city']}")
            print(f"Koordinat: {data['loc']}")
            print()
    else:
        print("Gagal mendapatkan lokasi.")

if __name__ == "__main__":
    main()
