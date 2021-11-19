from decouple import config
from django.conf import settings
from datetime import datetime
import requests

paystack_secret_key = config('paystack_secret_key')
paystack_test_headers = {"Authorization": f"Bearer {paystack_secret_key}"}
uba_bank_code = '033'

# This class returns the string needed to generate the key
class generateKey:
    @staticmethod
    def returnValue(phone):
        return f'{phone}{datetime.date(datetime.now())}{settings.SECRET_KEY}'

def resolve_card_bin(first_six_digits):
    url = f'https://api.paystack.co/decision/bin/{first_six_digits}'
    r = requests.get(url, headers=paystack_test_headers)
    print(r.json())
    if r.status_code == 200:
        res = r.json()
        if res['status'] == True:
            return res
        return None
    else:
        return None


def resolve_account_number(account_number):
    url = f'https://api.paystack.co/bank/resolve?account_number={account_number}&bank_code={uba_bank_code}'
    r = requests.get(url, headers=paystack_test_headers)
    print(r.json())
    if r.status_code == 200:
        res = r.json()
        if res['status'] == True:
            return res
        return None
    else:
        return None