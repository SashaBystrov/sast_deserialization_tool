import dill
import base64
from dill import loads as dill_loads


data_1 = input()
dill.loads(data_1)

data_2 = input()
tmp_2 = data_2
dill.loads(tmp_2)

data_3 = input()
payload_3 = base64.b64decode(data_3)
dill.loads(payload_3)

data_4 = input()
dill_loads(data_4)

safe_5 = b"constant_payload"
dill.loads(safe_5)  # safe


def get_payload_6():
    return input()

data_6 = get_payload_6()
dill.loads(data_6)


def deserialize_7(value):
    return dill.loads(value)

data_7 = input()
deserialize_7(data_7)