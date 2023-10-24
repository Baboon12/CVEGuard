import requests
import csv


def setup_session(url: str):
    session = requests.Session()
    session.headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.1.2222.33 Safari/537.36",
        "Accept-Encoding": "*",
        "Connection": "keep-alive"
    }
    response = session.get(url)

    return response


def check_file(file_path: str) -> bool:
    try:
        with open(file_path, 'r') as file:
            return True
    except FileNotFoundError:
        with open(file_path, 'x') as file:
            return True


def check_csv_file(file_path: str, headers: list[str]) -> bool:
    flag = False
    if check_file(file_path):
        with open(file_path, 'r') as csvfile:
            csv_reader = csv.reader(csvfile)
            try:
                if not csv_reader[0] == headers:
                    flag = True
            except TypeError:
                csv_dict = [row for row in csv_reader]
                if len(csv_dict) == 0:
                    flag = True

    if flag:
        with open(file_path, 'a') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(headers)
    return True
