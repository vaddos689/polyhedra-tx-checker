import csv
import time

from config import SLEEP_BETWEEN_ACCOUNTS
import requests
from pyuseragents import random
from better_web3 import Wallet
from better_web3.utils import sign_message
from loguru import logger


class Checker:
    def __init__(self, wallet: str):
        self.wallet = Wallet.from_key(wallet)
        self.headers = {
            'accept': 'application/json, text/plain, */*',
            'authorization': '',
            'origin': 'https://zkbridge.com',
            'referer': 'https://zkbridge.com/',
            'user-agent': random(),
        }

    def validation_message(self):
        url = 'https://api.zkbridge.com/api/signin/validation_message'

        json = {
            'publicKey': str(self.wallet.address).lower()
        }

        response = requests.post(url, headers=self.headers, json=json)

        if response.json()['status'] == 'ok':
            return response.json()['message']
        else:
            logger.error(f'{self.wallet.address} | Error with validation_message: {response.json()}')
            return None

    def signin(self, signed_message: str):
        url = 'https://api.zkbridge.com/api/signin'

        json = {
            'publicKey': self.wallet.address,
            'signedMessage': signed_message
        }

        response = requests.post(url, headers=self.headers, json=json)

        if response.json()['code'] == 200:
            return response.json()['token']
        else:
            logger.error(f'{self.wallet.address} | Error with signin: {response.json()}')
            return None

    def get_nft_tx_count(self):
        url = f'https://api.zkbridge.com/api/bridge/orders?pageStart=1&pageSize=2&userAddress={self.wallet.address.lower()}&sourceChainId=%5B204%2C56%5D'

        response = requests.get(url, headers=self.headers)

        return response.json()['total']

    def get_opbnb_tx_count(self):
        url = f'https://api.zkbridge.com/api/bridge/token/bridgings?pageStart=1&pageSize=2&from={self.wallet.address.lower()}&sourceType=opbnb-light'

        response = requests.get(url, headers=self.headers)

        return response.json()['total']

    def start(self):
        message = self.validation_message()
        if not message:
            return f'{self.wallet.address}:{self.wallet.private_key}:ERROR:ERROR'
        else:
            signed_message = sign_message(message, self.wallet.eth_account)
            bearer_token = self.signin(signed_message)
            if not bearer_token:
                return f'{self.wallet.address}:{self.wallet.private_key}:ERROR:ERROR'
            else:
                self.headers['Authorization'] = f'Bearer {bearer_token}'
                nft_tx_count = self.get_nft_tx_count()
                logger.info(f'{self.wallet.address} | nft_tx_count: {nft_tx_count}')
                opbnb_tx_count = self.get_opbnb_tx_count()
                logger.info(f'{self.wallet.address} | opbnb_tx_count: {opbnb_tx_count}')

                return f'{self.wallet.address}:{self.wallet.private_key}:{opbnb_tx_count}:{nft_tx_count}'


def main(wallets: list):
    # address:private_key:opbnb_tx_count:nft_tx_count
    csv_results = []

    for wallet in wallets:
        checker = Checker(wallet=wallet)
        csv_result = checker.start()
        csv_results.append(csv_result)
        time.sleep(SLEEP_BETWEEN_ACCOUNTS)

    with open('result.csv', 'w', newline='') as csvfile:
        table_head = ['address', 'private_key', 'opbnb_tx_count', 'nft_tx_count']
        spamwriter = csv.writer(csvfile, delimiter=',', quoting=csv.QUOTE_MINIMAL)
        spamwriter.writerow(table_head)

        for csv_result in csv_results:
            address, private_key, opbnb_tx_count, nft_tx_count = csv_result.split(':')
            spamwriter.writerow([address, private_key, opbnb_tx_count, nft_tx_count])

    logger.success('finish')


if __name__ == '__main__':
    logger.info('start')
    with open('wallets.txt', 'r') as file:
        wallets = [row.strip() for row in file]

    main(wallets)
