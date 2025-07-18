import collections
import json
import re
#
import idautils
import idaapi
#
from idaclu import ida_shims
from idaclu import ida_utils
from idaclu.qt_utils import i18n


SCRIPT_NAME = i18n('Explicit Calls')
SCRIPT_TYPE = 'func'
SCRIPT_VIEW = 'tree'
SCRIPT_ARGS = [(
    'checkbox', 'func_calls',
    [
        'Type Casting',
        'Helper Functions',
        'Standard Functions',
        'Custom Functions',
    ]
)]


def order_item_len(input_dict):
    def get_len(val):
        fs = val[1]
        if isinstance(fs, int):
            return fs
        elif isinstance(fs, list):
            return len(fs)

    return collections.OrderedDict(sorted(input_dict.items(), key=get_len, reverse=True))

def get_psdo_list(func_ea):
    func_pseudocode = []
    decomp_str = ""
    try:
       decomp_str = idaapi.decompile(func_ea)
    except idaapi.DecompilationFailure:
       return []
    for line in str(decomp_str).split('\n'):
        if '//' in line:
            code = line.split('//')[0]
            if code != '':
                func_pseudocode.append(code.lstrip())
        else:
            if line != '':
                func_pseudocode.append(line.lstrip())
    return func_pseudocode
    
def get_psdo_body(func_ea):
    psdo_list = get_psdo_list(func_ea)
    return psdo_list[2:-1]
 
def get_data(func_gen=None, env_desc=None, plug_params=None):

    report = {
        'data': collections.defaultdict(list),
        'stat': collections.defaultdict(int)
    }
    
    is_typ_add = plug_params['func_calls'][0][1]
    is_hlp_add = plug_params['func_calls'][1][1]
    is_std_add = plug_params['func_calls'][2][1]
    is_usr_add = plug_params['func_calls'][3][1]

    for func_addr in func_gen():
        caller_name = idaapi.get_func_name(func_addr)
        caller_psdo = get_psdo_body(func_addr)

        for psdo_line in caller_psdo:
            is_func_matched = re.match('(?:(?:.*\s)?)([0-9a-zA-Z\_\:]+)\(.*\)(?:(?:.*)?)', psdo_line)  # (?:(?:.*\s)?)([0-9a-zA-Z\_\:]+)\(.*\)
            if is_func_matched:
                
                calee_name = is_func_matched.group(1)
                fn_type = ida_utils.get_fn_type(calee_name)
                if ((is_typ_add and fn_type == 'typ')
                    or (is_hlp_add and fn_type == 'hlp')
                    or (is_std_add and fn_type == 'std')
                    or (is_usr_add and fn_type == 'usr')
                   ):
                    report['data'][calee_name].append((func_addr, psdo_line))
                    report['stat'][calee_name] += 1

    report['data'] = order_item_len(report['data'])
    report['stat'] = order_item_len(report['stat'])

    return report if __name__ == '__main__' else report['data']

def debug():
    data_obj = get_data(func_gen=idautils.Functions)
    ida_shims.msg(json.dumps(data_obj, indent=4))

if __name__ == '__main__':
    debug()
