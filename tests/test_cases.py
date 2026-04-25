import pickle
import yaml
import base64
import os


# 1. Taint через цепочку присваиваний — должно детектиться
data_1 = input()
a_1 = data_1
b_1 = a_1
c_1 = b_1
pickle.loads(c_1)


# 2. Taint через propagation function — должно детектиться
data_2 = input()
decoded_2 = base64.b64decode(data_2)
pickle.loads(decoded_2)


# 3. Несколько propagation functions подряд — должно детектиться
data_3 = input()
decoded_3 = base64.b64decode(data_3)
converted_3 = str(decoded_3)
pickle.loads(converted_3)


# 4. Taint из переменной окружения — должно детектиться
data_4 = os.getenv("PAYLOAD")
pickle.loads(data_4)


# 5. Безопасный сценарий: константа — не должно детектиться
safe_5 = b"constant_payload"
pickle.loads(safe_5)


# 6. Безопасный сценарий: данные сформированы внутри программы — не должно детектиться
safe_6 = pickle.dumps({"role": "user"})
pickle.loads(safe_6)


# 7. YAML с недоверенными данными — должно детектиться
data_7 = input()
yaml.load(data_7)


# 8. YAML safe_load — не должно детектиться
data_8 = input()
yaml.safe_load(data_8)


# 9. Межпроцедурный сценарий: источник внутри функции
# Текущий анализатор, скорее всего, НЕ найдёт без доработки межпроцедурного анализа.
def get_payload_9():
    return input()

data_9 = get_payload_9()
pickle.loads(data_9)


# 10. Межпроцедурный сценарий: передача tainted-данных в функцию
# Текущий анализатор, скорее всего, НЕ найдёт.
def deserialize_10(value):
    return pickle.loads(value)

data_10 = input()
deserialize_10(data_10)


# 11. Межпроцедурный сценарий: функция-пропагатор пользователя
# Текущий анализатор, скорее всего, НЕ найдёт.
def normalize_11(value):
    return value

data_11 = input()
payload_11 = normalize_11(data_11)
pickle.loads(payload_11)


# 12. Межпроцедурный сценарий: несколько функций
# Текущий анализатор, скорее всего, НЕ найдёт.
def get_raw_12():
    return input()

def decode_12(value):
    return base64.b64decode(value)

def run_12(value):
    return pickle.loads(value)

raw_12 = get_raw_12()
decoded_12 = decode_12(raw_12)
run_12(decoded_12)


# 13. Условное присваивание
# Текущий анализатор может детектировать, если видит зависимость через переменную.
flag_13 = True
if flag_13:
    data_13 = input()
else:
    data_13 = b"safe"

pickle.loads(data_13)


# 14. Перезапись tainted-переменной безопасным значением
# Текущий анализатор может дать ложноположительное срабатывание,
# если не реализовано снятие taint-метки.
data_14 = input()
data_14 = b"safe"
pickle.loads(data_14)


# 15. Контейнеры: tainted-значение внутри словаря
# Текущий анализатор, скорее всего, НЕ найдёт без поддержки контейнеров.
data_15 = input()
container_15 = {"payload": data_15}
pickle.loads(container_15["payload"])