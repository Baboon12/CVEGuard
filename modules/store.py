import os
import time
from datetime import datetime
import csv

from utils import (
    check_csv_file, 
    check_file,
)


def write_csv(data: list, file_path: str) -> None:
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


def log_csv(cve_id: str, file_path: str) -> None:
    if check_file(file_path):
        with open(file_path, 'a') as file:
            file.write(str(cve_id) + ' | ' + str(datetime.now().strftime("%d/%m/%Y %H:%M:%S")) + '\n')


def store_to_csv(data: list, keyword: str):
    try:
        os.mkdir('cves')
    except FileExistsError:
        pass

    try:
        os.mkdir('cves_log')
    except FileExistsError:
        pass

    file_path = 'cves/cve_data_' + keyword + '.csv'
    headers = ['CVE ID', 'Link', 'Patch Type', 'Patch Link (NVD)', 'Base-Score', 'NVD Published Date']

    if check_csv_file(file_path, headers):
        write_csv(data, file_path)
        file_path = 'cves_log/cve_data_' + keyword + '.txt'
        log_csv(data[0], file_path)
    else:
        raise Exception(f'File {file_path} not accessible')
