import requests
from bs4 import BeautifulSoup

# URL of the CVE page
# url = "https://nvd.nist.gov/vuln/detail/CVE-2023-38182/"
url = "https://nvd.nist.gov/vuln/detail/CVE-2022-27535/"

try:
    response = requests.get(url)

    if response.status_code == 200:
    
        soup = BeautifulSoup(response.text, "html.parser")

    
        cve_number_element = soup.find(
            "span", {"data-testid": "page-header-vuln-id"})
        # print(cve_number_element.get_text(strip=True))

        if cve_number_element:
            cve_number = cve_number_element.get_text(strip=True)
        else:
            cve_number = "CVE Number Not Found"

        i = 0
        for i in range(10):
            selector = "vuln-hyperlinks-resType-" + str(i)
            td_element = soup.find("td", {"data-testid": selector})

            if td_element:
                patch_span = td_element.find("span", {"class": "badge"})

                if patch_span:
                    patch_text = patch_span.text.strip()

                    if "Patch" in patch_text:
                        patch_name = "Patch"
                    elif "Vendor Advisory" in patch_text:
                        patch_name = "Vendor Advisory"
                    else:
                        patch_name = "Unknown"

                    selector1 = "vuln-hyperlinks-link-" + str(i)
                    td_element1 = soup.find("td", {"data-testid": selector1})
                    # print(td_element1)
                    if td_element1:
                        patch_link = td_element1.find("a")
                        # print(patch_link)
                        if patch_link:
                            patch_url = patch_link["href"]
                            print(patch_url)
            #             else:
            #                 print(f"No URL found for element {i}")
            #     else:
            #         print("Patch or Vendor Advisory Not Available in element", i)
            # else:
            #     print("Element with selector", selector, "not found")


    else:
        print("Failed to retrieve the page. Status code:", response.status_code)

except requests.exceptions.RequestException as e:
    print("Error:", e)
