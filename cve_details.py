# cve_details.py
import requests
from bs4 import BeautifulSoup
import time
import os
import csv

BASIC_URL = "https://cve.mitre.org"
BASE_URL = BASIC_URL + "/cgi-bin/cvekey.cgi?keyword="

NVD_URL = "https://nvd.nist.gov/vuln/detail/"

def setup_session(url: str):
    
    session = requests.Session()
    session.headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.1.2222.33 Safari/537.36",
        "Accept-Encoding": "*",
        "Connection": "keep-alive"
    }
    response = session.get(url)
    
    return response

def check_file(file_path: str) -> bool:
    try:
        with open(file_path, 'r') as file:
            return True

    except FileNotFoundError:
        with open(file_path, 'x') as file:
            return True

def check_csv_file(file_path: str, headers: list[str]) -> bool:
    flag = False
    if check_file(file_path):
        with open(file_path, 'r') as csvfile:
            csv_reader = csv.reader(csvfile)
            try:
                if not csv_reader[0] == headers:
                    flag = True
            except TypeError:
                csv_dict = [row for row in csv_reader]
                if len(csv_dict) == 0:
                    flag = True

    if flag:
        with open(file_path, 'a') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(headers)
    return True

def get_patch_link(cve_id: str) -> str:
    url = NVD_URL + cve_id
    # url = 'https://nvd.nist.gov/vuln/detail/CVE-2023-38182'
    # url = 'https://nvd.nist.gov/vuln/detail/CVE-2023-4355'
    # url = 'https://nvd.nist.gov/vuln/detail/CVE-2022-27535/'
    patch_type = ''
    patch_link = []
    patch_available = False
    vendor_advisory_available = False
    nvd_response = setup_session(url)
    if nvd_response.status_code == 200:
        nvd_soup = BeautifulSoup(nvd_response.content, "html.parser")
        patch_text = nvd_soup.find('table', {'data-testid': 'vuln-hyperlinks-table'}).text
        if 'Patch' in patch_text:
            # print('Patch Available')
            patch_text = patch_text.splitlines()
            patch_available = False
            for text in patch_text:
                if text.startswith('https://'):
                    patch_link.append(text)
                    patch_type = 'Patch'
                    patch_available = True
        else:
            if 'Vendor Advisory' in patch_text:
                patch_text = patch_text.splitlines()
                vendor_advisory_available = False
                for text in patch_text:
                    if text.startswith('https://'):
                        patch_link.append(text)
                        patch_type = 'Vendor Advisory'
                        vendor_advisory_available = True
            
        if not patch_available and not vendor_advisory_available:
        # print('Patch Not Available')
            patch_link = ['Patch Not Available']
            patch_type = 'NA'
    else:
        patch_link = '\n'.join(patch_link)

    
    patch_link = '\n'.join(patch_link)

    return patch_type, patch_link

def get_cves(keyword: str, url: str) -> None:
    response = setup_session(url)

    if response.status_code == 200:
        soup = BeautifulSoup(response.content, "html.parser")
        table = soup.find('div', {'id': 'TableWithRules'}).find('table')
        if table:
            data = []
            rows = table.find_all('tr')
            found = False
            for row in rows:
                tds = row.find_all('td')
                if len(tds) >= 2:
                    title_element = tds[0].find('a')
                    link = title_element['href'] if title_element else ''
                    title = title_element.get_text().strip() if title_element else ''
                    if title and link:
                        cve_id = title
                        cve_link = BASIC_URL + link

                        # Get the patch link for the CVE from NVD
                        patch_type, patch_link = get_patch_link(cve_id)

                        # Extract base score value and NVD published date
                        base_score, nvd_published_date = extract_base_score_and_date(cve_id)

                        data = [cve_id, cve_link, patch_type, patch_link, base_score, nvd_published_date]

                if data:
                    try:
                        os.mkdir('cves')
                    except FileExistsError:
                        pass
                    file_path = 'cves/cve_data_' + keyword + '.csv'
                    if check_csv_file(file_path, ['CVE ID', 'Link', 'Patch Type', 'Patch Link (NVD)', 'Base-Score', 'NVD Published Date']):
                        write = False
                        while not write:
                            try:
                                with open(file_path, 'a', newline='') as file:
                                    csv_writer = csv.writer(file)
                                    csv_writer.writerow(data)
                                    write = True
                                    found = True
                            except PermissionError:
                                if not write:
                                    time.sleep(3)
                                    continue
                                else:
                                    raise PermissionError(f'File {file_path} not accessible')
                    else:
                        raise Exception(f'File {file_path} not accessible')
                    
            print(f'CVE details of {keyword} scraped from {url} stored at cves/cve_data_{keyword}.xlsx')
        if not found:
            print('No CVE IDs and Links Found')
        else:
            print('No Table With Rules Found')
    else:
        print("Failed to retrieve the page. Status code:", response.status_code)

def extract_base_score_and_date(cve_id: str) -> (str, str):
    url = NVD_URL + cve_id
    nvd_response = setup_session(url)
    if nvd_response.status_code == 200:
        nvd_soup = BeautifulSoup(nvd_response.content, "html.parser")
        base_score_element = nvd_soup.find('a', {'data-testid': 'vuln-cvss3-cna-panel-score'})

        if not base_score_element:
            base_score_element = nvd_soup.find('a', {'data-testid': 'vuln-cvss3-panel-score'})

        base_score = base_score_element.get_text() if base_score_element else 'N/A'

        nvd_published_date_element = nvd_soup.find('span', {'data-testid': 'vuln-published-on'})

        base_score = base_score_element.get_text() if base_score_element else 'N/A'
        nvd_published_date = nvd_published_date_element.get_text() if nvd_published_date_element else 'N/A'

        return base_score, nvd_published_date
    else:
        return 'N/A', 'N/A'

