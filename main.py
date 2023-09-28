import concurrent.futures
import excel_keywords
import cve_details

def process_keyword(keyword, url):
    print(f"Started processing keyword: {keyword}")
    cve_details.get_cves(keyword, url)
    print(f"Finished processing keyword: {keyword}")

if __name__ == "__main__":
    keywords = excel_keywords.get_keywords()
    urls = excel_keywords.create_urls(keywords)

    # Create a ThreadPoolExecutor to run processes in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=11) as executor:
        # Submit each keyword and URL pair to run in parallel
        futures = [executor.submit(process_keyword, keyword, url) for keyword, url in zip(keywords, urls)]

        # Wait for all threads to complete
        concurrent.futures.wait(futures)
