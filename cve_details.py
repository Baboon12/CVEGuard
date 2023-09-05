import requests
from bs4 import BeautifulSoup
import pandas as pd
import os

BASIC_URL = "https//cve.mitre.org"

BASE_URL = BASIC_URL + "cgi-bin/cvekey.cgi?keyword="


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
                        data.append({'CVE ID': title, 'Link': BASIC_URL + link})
                        # print(f"Title: {title}\nLink: {basic_url + link}\n")
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
            print('No Table WithRules Found')
    else:
        print("Failed to retrieve the page. Status code:", response.status_code)
