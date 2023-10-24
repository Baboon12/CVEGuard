from bs4 import BeautifulSoup
from tqdm import tqdm

from utils import setup_session
from .store import store_to_csv
from .cve_details import (
    get_patch_link,
    extract_base_score_and_date,
    BASIC_URL,
)


def extract_data(raw_table, cves_written = []):
    data = []
    tds = raw_table.find_all('td')

    if len(tds) >= 2:

        title_element = tds[0].find('a')
        link = title_element['href'] if title_element else ''
        title = title_element.get_text().strip() if title_element else ''

        if title and link:
            cve_id = title
            if (cve_id + '\n') in cves_written:
                return

            cve_link = BASIC_URL + link
            patch_type, patch_link = get_patch_link(cve_id)
            base_score, nvd_published_date = extract_base_score_and_date(cve_id)

            data = [cve_id, cve_link, patch_type, patch_link, base_score, nvd_published_date]

    return data

def get_cves(keyword: str, url: str, cves_written = []) -> None:
    response = setup_session(url)

    if response.status_code == 200:
        soup = BeautifulSoup(response.content, "html.parser")
        table = soup.find('div', {'id': 'TableWithRules'}).find('table')

        if table:
            rows = table.find_all('tr')
            found = False

            for i in tqdm(range(len(rows))):
                data = extract_data(rows[i], cves_written) if cves_written else extract_data(rows[i])

                if data:
                    store_to_csv(data, keyword)
                    found = True

            print(f'CVE details of {keyword} scraped from {url} stored at cves/cve_data_{keyword}.xlsx')

        if not found:
            print('No CVE IDs and Links Found')
    else:
        print("Failed to retrieve the page. Status code:", response.status_code)
