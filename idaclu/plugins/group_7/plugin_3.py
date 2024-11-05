import collections
import json
import re
import sys
#
import idc
import idaapi
import idautils
#
from idaclu import ida_shims
from idaclu.qt_utils import i18n


SCRIPT_NAME = i18n('Distinct Colors')
SCRIPT_TYPE = 'func'
SCRIPT_VIEW = 'tree'
SCRIPT_ARGS = []


class RgbColor:
    def __init__(self, color_ref, color_nam='unknown'):
        ver_py = sys.version_info.major
        self.palette_val = {
            13107199: 'blue',    # '#C7FFFF'
            16777151: 'yellow',  # '#FFFFBF'
            12582847: 'green',   # '#BFFFBF'
            16760815: 'pink',    # '#FFBFEF'
            16777215: 'none'     # '#FFFFFF'
        }
        self.palette_nam = {v: k for k, v in self.palette_val.items()}

        if (ver_py == 2 and
            any(isinstance(color_ref, t) for t in (int, long)) and
            color_ref <= 0xFFFFFFFF):
            self.r, self.g, self.b = self.get_from_tuple(int(color_ref))
        elif (ver_py == 3 and
            isinstance(color_ref, int) and
            color_ref <= 0xFFFFFFFF):
            self.r, self.g, self.b = self.get_from_tuple(color_ref)
        elif isinstance(color_ref, tuple) and len(color_ref) == 3:
            self.r, self.g, self.b = color_ref
        elif isinstance(color_ref, str) or isinstance(color_ref, unicode):
            self.r, self.g, self.b = self.get_from_str(color_ref)
        else:
            raise ValueError("Invalid init value: {}/{}".format(type(color_ref), color_ref))
        self.name = color_nam

    def invert_color(self):
        self.r, self.g, self.b = self.b, self.g, self.r

    def is_color_defined(self):
        return self.get_to_int() in self.palette_val

    def get_from_tuple(self, rgb_int):
        r = (rgb_int >> 16) & 255
        g = (rgb_int >> 8) & 255
        b = rgb_int & 255
        return (r, g, b)

    def get_to_tuple(self):
        return (self.r, self.g, self.b)

    def get_from_str(self, color_ref):
        rgb_pat = r'rgb\((\d{1,3}),(\d{1,3}),(\d{1,3})\)'
        match = re.search(rgb_pat, color_ref)
        if match:
            r, g, b =  map(int, match.groups())
            if not all(0 <= c <= 255 for c in (r, g, b)):
                raise ValueError("Invalid color component values")
            return (r, g, b)
        elif color_ref in self.palette_nam:
            return self.get_from_tuple(self.palette_nam[color_ref])
        else:
            raise ValueError("Invalid 'rgb(r,g,b)' string format")

    def get_to_str(self):
        return "rgb({},{},{})".format(self.r, self.g, self.b)

    def get_to_int(self, reverse=False):
        return (
            (self.b << 16 | self.g << 8 | self.r) if reverse
            else (self.r << 16 | self.g << 8 | self.b)
        )

    def get_to_hash(self):
        hex_string = hex(self.get_to_int())[2:]
        hex_color = hex_string.rjust(6, '0')
        hex_color_code = '#' + hex_color.upper()
        return hex_color_code

    def get_to_name(self):
        col_int = self.get_to_int()
        return self.palette_val[col_int] if col_int in self.palette_val else self.get_to_hash()

    def __eq__(self, b):
        if isinstance(b, RgbColor):
            return self.r == b.r and self.g == b.g and self.b == b.b
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return self.get_to_str()


def get_data(func_gen=None, env_desc=None, plug_params=None):
    report = {
        'data': collections.defaultdict(list),
        'stat': collections.defaultdict(int)
    }

    for func_addr in func_gen():
        func_colr = ida_shims.get_color(func_addr, idc.CIC_FUNC)

        color = RgbColor(func_colr)
        color.invert_color()
        color_name = color.get_to_name()
        report['data'][color_name].append(func_addr)
        report['stat'][color_name] += 1

    return report if __name__ == '__main__' else report['data']

def debug():
    data_obj = get_data(func_gen=idautils.Functions)
    ida_shims.msg(json.dumps(data_obj, indent=4))

if __name__ == '__main__':
    debug()
