import collections
import json
import re
#
import idaapi
import idautils
#
from idaclu import ida_shims
from idaclu.qt_utils import i18n


SCRIPT_NAME = i18n('Lost Mem in Restored Pseudocode')
SCRIPT_TYPE = 'func'
SCRIPT_VIEW = 'tree'
SCRIPT_ARGS = []


def get_psdo_str(func_ea):
    try:
       return str(idaapi.decompile(func_ea))  # restored microcode/pseudocode from idb
    except idaapi.DecompilationFailure:
       return ""
    
def get_lost_mem(func_ea):
    psdo_str = get_psdo_str(func_ea)
    pattern = r"MEMORY\[0x[0-9A-Fa-f]+\]|[0-9A-Za-z]+\->\?"  
    # Find cases like: `MEMORY[0x0040105C]`, `entity3->?`
    return re.findall(pattern, psdo_str)

def get_data(func_gen=None, env_desc=None, plug_params=None):
    report = {
        'data': collections.defaultdict(list),
        'stat': collections.defaultdict(int)
    }

    for func_addr in func_gen():
        for lost_mem in get_lost_mem(func_addr):
            if not func_addr in report['data'][lost_mem]:
                report['data'][lost_mem].append(func_addr)
                report['stat'][lost_mem] += 1

    return report if __name__ == '__main__' else report['data']

def debug():
    data_obj = get_data(func_gen=idautils.Functions)
    ida_shims.msg(json.dumps(data_obj, indent=4))

if __name__ == '__main__':
    debug()
