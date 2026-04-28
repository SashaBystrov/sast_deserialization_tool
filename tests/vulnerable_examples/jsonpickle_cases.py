import jsonpickle
import base64
from jsonpickle import decode as jsonpickle_decode


data_1 = input()
jsonpickle.decode(data_1)

data_2 = input()
jsonpickle.loads(data_2)

data_3 = input()
tmp_3 = data_3
jsonpickle.decode(tmp_3)

data_4 = input()
payload_4 = base64.b64decode(data_4)
jsonpickle.decode(payload_4)

data_5 = input()
jsonpickle_decode(data_5)

safe_6 = '{"safe": true}'
jsonpickle.decode(safe_6)  # safe


def get_payload_7():
    return input()

data_7 = get_payload_7()
jsonpickle.decode(data_7)


def deserialize_8(value):
    return jsonpickle.decode(value)

data_8 = input()
deserialize_8(data_8)