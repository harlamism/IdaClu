import collections
import json
import re
#
import idaapi
import idautils
#
from idaclu import ida_shims


SCRIPT_NAME = 'Distinct Prefixes'
SCRIPT_TYPE = 'func'
SCRIPT_VIEW = 'tree'
SCRIPT_ARGS = []


def get_func_prefs(func_name, is_uscore=False, is_dummy=False):
    prefs = set()
    dummy_pref = 'sub_'  # special prefix w/o '%'
    if is_dummy and dummy_pref in func_name:
        prefs.add(dummy_pref)
    func_prfx = func_name.split('%')[:-1]
    for p in func_prfx:
        prefs.add('{}_'.format(p))
    return list(prefs)

def get_data(func_gen=None, env_desc=None, plug_params=None):
    report = {
        'data': collections.defaultdict(list),
        'stat': collections.defaultdict(int)
    }

    sep_char = '%'
    for func_addr in func_gen():
        func_name = ida_shims.get_func_name(func_addr)
        prefs = set()

        if sep_char in func_name:
            func_prefs = get_func_prefs(func_name, True, False)
            prefs.update(func_prefs)
        for pfx in list(prefs):
            report['data'][pfx].append(func_addr)
            report['stat'][pfx] += 1

    return report if __name__ == '__main__' else report['data']

def debug():
    data_obj = get_data(func_gen=idautils.Functions)
    ida_shims.msg(json.dumps(data_obj, indent=4))

if __name__ == '__main__':
    debug()
