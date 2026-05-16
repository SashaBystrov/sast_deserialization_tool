import importlib
import pickle
import yaml


# -------------------------
# DYNAMIC ATTRIBUTE RESOLUTION
# -------------------------

data_1 = input()
function_name_1 = "loads"
loader_1 = getattr(pickle, function_name_1)
loader_1(data_1)


data_2 = input()
loader_2 = getattr(pickle, "loads")
loader_2(data_2)


# -------------------------
# DYNAMIC IMPORTS
# -------------------------

module_3 = importlib.import_module("pickle")
data_3 = input()
module_3.loads(data_3)


module_name_4 = "pickle"
module_4 = importlib.import_module(module_name_4)
data_4 = input()
module_4.loads(data_4)


# -------------------------
# DISPATCH TABLES
# -------------------------

dispatch_5 = {
    "pickle": pickle.loads
}

data_5 = input()
dispatch_5["pickle"](data_5)


dispatch_6 = {}
dispatch_6["loader"] = pickle.loads

data_6 = input()
dispatch_6["loader"](data_6)


# -------------------------
# CALLABLE ALIASES
# -------------------------

loader_7 = pickle.loads
data_7 = input()
loader_7(data_7)


def get_loader_8():
    return pickle.loads

loader_8 = get_loader_8()
data_8 = input()
loader_8(data_8)


# -------------------------
# LAMBDA WRAPPERS
# -------------------------

loader_9 = lambda value: pickle.loads(value)

data_9 = input()
loader_9(data_9)


def make_loader_10():
    return lambda value: pickle.loads(value)

loader_10 = make_loader_10()
data_10 = input()
loader_10(data_10)


# -------------------------
# CLASS AND METHOD WRAPPERS
# -------------------------

class PickleLoader11:
    def deserialize(self, value):
        return pickle.loads(value)

loader_11 = PickleLoader11()
data_11 = input()
loader_11.deserialize(data_11)


class PickleLoader12:
    def __init__(self):
        self.loader = pickle.loads

    def deserialize(self, value):
        return self.loader(value)

loader_12 = PickleLoader12()
data_12 = input()
loader_12.deserialize(data_12)


# -------------------------
# NESTED OBJECT ATTRIBUTES
# -------------------------

class Registry13:
    pass

registry_13 = Registry13()
registry_13.loader = pickle.loads

data_13 = input()
registry_13.loader(data_13)


# -------------------------
# GLOBALS AND LOCALS
# -------------------------

data_14 = input()
globals()["pickle"].loads(data_14)


data_15 = input()
locals()["pickle"].loads(data_15)


# -------------------------
# EVAL AND EXEC-LIKE DYNAMIC CODE
# -------------------------

data_16 = input()
eval("pickle.loads")(data_16)


data_17 = input()
function_name_17 = "pickle.loads"
eval(function_name_17)(data_17)


# -------------------------
# HIGHER-ORDER FUNCTIONS
# -------------------------

def call_loader_18(loader, value):
    return loader(value)

data_18 = input()
call_loader_18(pickle.loads, data_18)


def get_payload_19():
    return input()

def call_loader_19(loader, value):
    return loader(value)

payload_19 = get_payload_19()
call_loader_19(pickle.loads, payload_19)


# -------------------------
# DECORATOR-LIKE WRAPPERS
# -------------------------

def wrapper_20(func):
    return func

loader_20 = wrapper_20(pickle.loads)
data_20 = input()
loader_20(data_20)



# -------------------------
# COMPLEX CONTAINER CALLABLES
# -------------------------

loaders_26 = [pickle.loads]

data_26 = input()
loaders_26[0](data_26)


loaders_27 = {
    "items": [pickle.loads]
}

data_27 = input()
loaders_27["items"][0](data_27)


# -------------------------
# ASYNC / CALLBACK-LIKE CASES
# -------------------------

async def async_deserialize_28(value):
    return pickle.loads(value)

data_28 = input()
# The analyzer may not model async call semantics.
# await async_deserialize_28(data_28)


def register_callback_29(callback):
    return callback

callback_29 = register_callback_29(pickle.loads)
data_29 = input()
callback_29(data_29)