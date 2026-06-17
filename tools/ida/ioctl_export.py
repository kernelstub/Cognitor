# IDA Python: export Cognitor sidecars and ioctl.json without BinExport.
# Run with: ida64 -A -S"path\to\ioctl_export.py --out C:\out" driver.sys

import argparse
import json
import os
import re
import sys

import ida_bytes
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_name
import ida_ua
import idautils
import idc


IOCTL_RE = re.compile(r"\b(?:0x)?[0-9a-fA-F]{4,8}\b")


def _argv():
    raw = ida_kernwin.get_plugin_options("ioctl_export") or ""
    args = raw.split()
    if "--" in sys.argv:
        args = sys.argv[sys.argv.index("--") + 1 :]
    return args


def _hex(value):
    return "0x%x" % (value & 0xFFFFFFFF)


def _strings(func):
    found = []
    for ea in idautils.FuncItems(func.start_ea):
        for ref in idautils.DataRefsFrom(ea):
            value = idc.get_strlit_contents(ref, -1, ida_bytes.STRTYPE_C)
            if value:
                try:
                    found.append(value.decode("utf-8", errors="ignore"))
                except AttributeError:
                    found.append(str(value))
    return sorted(set(found))


def _calls(func):
    calls = []
    for ea in idautils.FuncItems(func.start_ea):
        if ida_ua.decode_insn(ida_ua.insn_t(), ea):
            for ref in idautils.CodeRefsFrom(ea, False):
                target = ida_funcs.get_func(ref)
                if target:
                    calls.append(ida_name.get_name(target.start_ea) or _hex(target.start_ea))
    return sorted(set(calls))


def _immediates(func):
    values = []
    for ea in idautils.FuncItems(func.start_ea):
        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, ea):
            continue
        for idx in range(ida_ua.UA_MAXOP):
            op = insn.ops[idx]
            if op.type == ida_ua.o_void:
                break
            if op.type in (ida_ua.o_imm, ida_ua.o_mem, ida_ua.o_displ) and 0x800 <= op.value <= 0xFFFFFFFF:
                values.append(op.value)
    return values


def _function_record(func):
    name = ida_name.get_name(func.start_ea) or _hex(func.start_ea)
    strings = _strings(func)
    ops = []
    ioctls = []
    for value in _immediates(func):
        code = _hex(value)
        if value >= 0x1000:
            ops.append("immediate " + code)
        if value >= 0x800 and (value & 0x3) <= 3:
            ioctls.append({"code": code, "handlers": [name], "source": "ida-immediate"})
    for text in strings:
        if "ioctl" in text.lower() or "ctl_code" in text.lower():
            ops.append(text)
            for match in IOCTL_RE.findall(text):
                code = match.lower()
                if not code.startswith("0x"):
                    code = "0x" + code
                ioctls.append({"code": code, "handlers": [name], "source": "ida-string"})
    return {
        "name": name,
        "address": _hex(func.start_ea),
        "basic_block_count": len(list(idautils.Chunks(func.start_ea))),
        "calls": _calls(func),
        "strings": strings,
        "operations": sorted(set(ops)),
        "ioctls": ioctls,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=".")
    parser.add_argument("--device", default="")
    args = parser.parse_args(_argv())
    ida_idaapi.auto_wait()
    input_path = ida_kernwin.get_root_filename()
    records = []
    ioctls = []
    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        if not func:
            continue
        record = _function_record(func)
        records.append(record)
        ioctls.extend(record["ioctls"])
    for ioctl in ioctls:
        if args.device and not ioctl.get("device"):
            ioctl["device"] = args.device
    os.makedirs(args.out, exist_ok=True)
    sidecar = {"functions": records, "ioctls": ioctls}
    base = os.path.basename(input_path)
    with open(os.path.join(args.out, base + ".analysis.json"), "w", encoding="utf-8") as fh:
        json.dump(sidecar, fh, indent=2, sort_keys=True)
    with open(os.path.join(args.out, "ioctl.json"), "w", encoding="utf-8") as fh:
        json.dump({base: ioctls}, fh, indent=2, sort_keys=True)
    ida_kernwin.qexit(0)


if __name__ == "__main__":
    main()
