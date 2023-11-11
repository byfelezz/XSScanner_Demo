import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import threading
import queue
import re

# XSS payloadlarını dosyadan okuma fonksiyonu
def load_payloads(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file]

# URL parametrelerinde XSS zafiyeti tarama fonksiyonu
def scan_url_params(url, payloads, headers, cookies, vulnerabilities):
    try:
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        for param in query_params:
            for payload in payloads:
                query_params[param] = payload
                new_query = "&".join([f"{key}={value}" for key, value in query_params.items()])
                new_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                
                response = requests.get(new_url, headers=headers, cookies=cookies)
                if payload in response.text:
                    vulnerabilities.append((new_url, payload))
    
    except Exception as e:
        print(f"Hata: {url} adresinde tarama sırasında bir hata meydana geldi: {e}")

# Formlarda XSS zafiyeti tarama fonksiyonu
def scan_forms(url, payloads, headers, cookies, vulnerabilities):
    try:
        response = requests.get(url, headers=headers, cookies=cookies)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            action = form.get('action') or url
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            
            for payload in payloads:
                data = {input.get('name'): payload for input in inputs if input.get('type') != 'submit'}
                action_url = urljoin(url, action)

                if method == 'post':
                    response = requests.post(action_url, data=data, headers=headers, cookies=cookies)
                else:
                    response = requests.get(action_url, params=data, headers=headers, cookies=cookies)
                
                if payload in response.text:
                    vulnerabilities.append((action_url, payload))
    
    except Exception as e:
        print(f"Hata: {url} adresinde tarama sırasında bir hata meydana geldi: {e}")

# JavaScript linklerini tarama fonksiyonu
def scan_javascript_links(url, headers, cookies, url_queue):
    try:
        response = requests.get(url, headers=headers, cookies=cookies)
        soup = BeautifulSoup(response.text, 'html.parser')

        # JavaScript kodlarını tara
        script_tags = soup.find_all('script')
        for script in script_tags:
            if script.attrs.get("src"):
                # Dışarıdan yüklenen scriptleri keşfet
                new_url = urljoin(url, script.attrs.get("src"))
                url_queue.put(new_url)
            else:
                # Inline JavaScript'te URL'leri bul
                urls = re.findall(r'(http[s]?://\S+)', script.text)
                for new_url in urls:
                    url_queue.put(new_url)
    
    except Exception as e:
        print(f"Hata: {url} adresinde JavaScript link taraması sırasında bir hata meydana geldi: {e}")

# Tarama işlemini yürüten iş parçacığı fonksiyonu
def scan_thread(url_queue, payloads, headers, cookies, vulnerabilities, max_depth):
    depth = 0
    while not url_queue.empty() and depth < max_depth:
        url = url_queue.get()
        scan_url_params(url, payloads, headers, cookies, vulnerabilities)
        scan_forms(url, payloads, headers, cookies, vulnerabilities)
        scan_javascript_links(url, headers, cookies, url_queue)
        url_queue.task_done()
        depth += 1

# Ana fonksiyon
def main():
    start_url = input("Lütfen taramak istediğiniz başlangıç URL'sini girin: ")
    payloads = load_payloads("xsspayloadlist.txt")
    vulnerabilities = []
    max_depth = int(input("Maksimum tarama derinliği (örn: 3): "))

    # İsteğe bağlı header ve cookie bilgileri
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    cookies = {}  # Eğer giriş yapılacaksa buraya cookie bilgileri eklenebilir

    # URL kuyruğunu ve iş parçacıklarını oluşturma
    url_queue = queue.Queue()
    url_queue.put(start_url)
    threads = []

    # 10 iş parçacığı başlatma (bu sayı değiştirilebilir)
    for _ in range(10):
        t = threading.Thread(target=scan_thread, args=(url_queue, payloads, headers, cookies, vulnerabilities, max_depth))
        t.start()
        threads.append(t)

    # Tüm iş parçacıklarının tamamlanmasını bekleme
    for t in threads:
        t.join()

    if vulnerabilities:
        print("Tespit edilen XSS Zafiyetleri:")
        for vuln in vulnerabilities:
            print(f"URL: {vuln[0]}, Payload: {vuln[1]}")
    else:
        print("XSS zafiyeti tespit edilemedi.")

if __name__ == "__main__":
    main()