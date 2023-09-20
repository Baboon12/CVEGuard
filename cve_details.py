# cve_details.py
import requests
from bs4 import BeautifulSoup
import pandas as pd
import os

BASIC_URL = "https://cve.mitre.org"
BASE_URL = BASIC_URL + "/cgi-bin/cvekey.cgi?keyword="

NVD_URL = "https://nvd.nist.gov/vuln/detail/"

def get_patch_link(cve_id: str) -> str:
    url = NVD_URL + cve_id
    # url = 'https://nvd.nist.gov/vuln/detail/CVE-2023-38182'
    # url = 'https://nvd.nist.gov/vuln/detail/CVE-2023-4355'
    # url = 'https://nvd.nist.gov/vuln/detail/CVE-2022-27535/'
    patch_type = ''
    patch_link = []
    patch_available = False
    vendor_advisory_available = False
    nvd_response = requests.get(url)
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
            patch_link = 'Patch Not Available'
            patch_type = 'NA'
    else:
        patch_link = 'Patch Not Available'
        patch_type = 'NA'
    
    patch_link = '\n'.join(patch_link)

    return patch_type, patch_link

def get_cves(keyword: str, url: str) -> None:
    response = requests.get(url)

    if response.status_code == 200:
        soup = BeautifulSoup(response.content, "html.parser")
        table = soup.find('div', {'id': 'TableWithRules'}).find('table')
        if table:
            data = []
            rows = table.find_all('tr')

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
                        # patch_link = ''

                        data.append({'CVE ID': cve_id, 'Link': cve_link, 'Patch Type': patch_type, 'Patch Link (NVD)': patch_link})

            if data:
                # Create a DataFrame
                df = pd.DataFrame(data)

                # Save to an Excel file
                try:
                    os.mkdir('cves')
                except FileExistsError:
                    pass
                df.to_excel('cves/cve_data_' + keyword + '.xlsx', index=False)
                print(f'CVE details of {keyword} scraped from {url} stored at cves/cve_data_{keyword}.xlsx')
            else:
                print('No CVE IDs and Links Found')
        else:
            print('No Table With Rules Found')
    else:
        print("Failed to retrieve the page. Status code:", response.status_code)
        