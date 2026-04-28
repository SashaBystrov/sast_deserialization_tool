import shelve
import os
from shelve import open as shelve_open


path_1 = input()
shelve.open(path_1)

path_2 = os.getenv("SHELVE_PATH")
shelve.open(path_2)

path_3 = input()
tmp_3 = path_3
shelve.open(tmp_3)

path_4 = input()
shelve_open(path_4)

safe_5 = "local.db"
shelve.open(safe_5)  # safe


def get_path_6():
    return input()

path_6 = get_path_6()
shelve.open(path_6)


def open_shelve_7(path):
    return shelve.open(path)

path_7 = input()
open_shelve_7(path_7)