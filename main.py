import excel_keywords
import cve_details

keywords = excel_keywords.get_keywords()
urls = excel_keywords.create_urls(keywords)

for keyword, url in zip(keywords, urls):
    cve_details.get_cves(keyword, url)
    