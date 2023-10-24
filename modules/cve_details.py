from bs4 import BeautifulSoup

from utils import setup_session


BASIC_URL = "https://cve.mitre.org"
BASE_URL = BASIC_URL + "/cgi-bin/cvekey.cgi?keyword="
NVD_URL = "https://nvd.nist.gov/vuln/detail/"


def extract_base_score_and_date(cve_id: str) -> tuple[str]:
    url = NVD_URL + cve_id
    nvd_response = setup_session(url)
    if nvd_response.status_code == 200:
        nvd_soup = BeautifulSoup(nvd_response.content, "html.parser")
        base_score = nvd_soup.find('a', {'class': 'label'}).get_text()
        base_score = nvd_soup.find('a', {'data-testid': 'vuln-cvss3-panel-score'}).get_text() if not base_score else base_score

        nvd_published_date_element = nvd_soup.find('span', {'data-testid': 'vuln-published-on'})
        nvd_published_date = nvd_published_date_element.get_text() if nvd_published_date_element else 'N/A'

        return base_score, nvd_published_date
    else:
        return 'N/A', 'N/A'


def extract_links(patch_text: str) -> tuple:
    patch_text = patch_text.splitlines()
    patch_available = False
    patch_link = []

    for text in patch_text:
        if text.startswith('https://'):
            patch_link.append(text)
            patch_available = True

    return patch_available, patch_link


def get_patch_link(cve_id: str) -> str:
    url = NVD_URL + cve_id
    patch_type = ''
    patch_available = False
    vendor_advisory_available = False
    nvd_response = setup_session(url)

    if nvd_response.status_code == 200:
        nvd_soup = BeautifulSoup(nvd_response.content, "html.parser")
        patch_text = nvd_soup.find('table', {'data-testid': 'vuln-hyperlinks-table'}).text

        if 'Patch' in patch_text:
            patch_available, patch_link = extract_links(patch_text)
            patch_type = 'Patch' if patch_available else ''

        elif 'Vendor Advisory' in patch_text:
            vendor_advisory_available, patch_link = extract_links(patch_text)
            patch_type = 'Vendor Advisory' if vendor_advisory_available else ''

        if not patch_available and not vendor_advisory_available:
            patch_link = ['Patch Not Available']
            patch_type = 'N/A'
        else:
            patch_link = '\n'.join(patch_link)

    return patch_type, patch_link
