from modules.extract import get_cves
from modules.keywords import (
    create_urls, 
    get_keywords,
)


PATH = 'keywords_demo.xlsx'


def process_keyword(keyword, url):
    print(f"Started processing keyword: {keyword}")
    try:
        file_path = 'cves_written/cve_data_' + keyword + '.txt'
        with open(file_path, 'r') as file:
            cves_written = file.readlines()

        get_cves(keyword, url, cves_written)
    except FileNotFoundError:
        get_cves(keyword, url)
    print(f"Finished processing keyword: {keyword}")


if __name__ == "__main__":
    keywords = get_keywords(PATH)
    urls = create_urls(keywords)

    for keyword, url in zip(keywords, urls):
        process_keyword(keyword, url)