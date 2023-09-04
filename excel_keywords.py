import openpyxl

PATH = 'keywords.xlsx'
BASE_URL = "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword="
xl_keywords = openpyxl.load_workbook(PATH)
sheet = xl_keywords.active
max_rows = sheet.max_row

keywords = []
urls = []

for i in range(1, max_rows + 1):
    cell = sheet.cell(row = i, column = 1)
    cell_value = cell.value.lower()
    cell_value_split = cell_value.split(' ')
    if len(cell_value_split) > 1:
        cell_value = "+".join(cell_value_split)
    keywords.append(cell_value)

urls = [BASE_URL + keyword for keyword in keywords]

print(*urls, sep='\n')