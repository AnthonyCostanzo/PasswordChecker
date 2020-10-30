from hashlib import sha1
import requests
import hashlib


def request_api_data(queryCharacters):
    url = f'https://api.pwnedpasswords.com/range/{queryCharacters}'
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f'Error fetching: {res.status_code}, check the api and try again')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[0:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


def main(passwordFile):
    with open(passwordFile, 'r') as file:
        passwords = "".join(file.readlines()).splitlines()
        for password in passwords:
            count = pwned_api_check(password)
            if count:
                print(
                    f'{password} was found {count} times... you should probably change your password')
            else:
                print(f'{password} was not found')
        return 'done'


if __name__ == 'main':
    main('../passwords.txt')
