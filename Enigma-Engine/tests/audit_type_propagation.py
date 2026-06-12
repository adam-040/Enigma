#!/usr/bin/env python3
"""
Type Propagation Audit Script
==============================
Quantifies how AnalysisBridge + TypeBridge improves decompiler output quality
by measuring variable-level type resolution across PE binaries.

Usage:
    python tests/audit_type_propagation.py [--exe path] [--pe-binary path]

Output: per-binary table + global summary with before/after stats.
"""

import subprocess
import re
import sys
import os
from collections import Counter

WINDOWS_API_TYPES = {
    'DWORD', 'HANDLE', 'HMODULE', 'HINSTANCE', 'HWND',
    'LPVOID', 'LPCVOID', 'PVOID',
    'LPCSTR', 'LPSTR', 'PCSTR', 'PSTR',
    'LPCWSTR', 'LPWSTR', 'PCWSTR', 'PWSTR',
    'LPDWORD', 'PDWORD', 'PUINT',
    'BOOL', 'LONG', 'ULONG', 'UINT',
    'SIZE_T', 'DWORD_PTR', 'DWORD32', 'DWORD64',
    'LONGLONG', 'ULONGLONG',
    'WCHAR', 'WORD', 'BYTE',
    'LPARAM', 'WPARAM', 'LRESULT',
    'HKEY', 'HRESULT', 'NTSTATUS',
    'LANGID', 'LCID',
}

UNDEFINED_TYPES = {'undefined1', 'undefined2', 'undefined4', 'undefined8', 'undefined'}

# Types that are standard C or decompiler-inferred (non-undefined)
STANDARD_TYPES = {
    'void', 'int', 'uint', 'long', 'ulong', 'char', 'short', 'ushort',
    'float', 'double', 'size_t',
    'int8', 'int16', 'int32', 'int64',
    'uint8', 'uint16', 'uint32', 'uint64',
    'int4', 'uint4',
    'uint64_t', 'uint32_t', 'uint16_t', 'uint8_t',
    'bool',
}


def run_decompiler(exe_path, binary_path, extra_args=None):
    cmd = [exe_path, '-base', '140001000', binary_path]
    if extra_args:
        cmd.extend(extra_args)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return result.stdout


def parse_function_params(sig_line):
    """Extract parameter types from a function signature line."""
    m = re.search(r'\(([^)]*)\)', sig_line)
    if not m:
        return []
    params = []
    raw = m.group(1).strip()
    if not raw or raw == 'void':
        return params
    for p in raw.split(','):
        p = p.strip()
        if not p:
            continue
        tokens = p.split()
        if len(tokens) >= 2:
            param_type = ' '.join(tokens[:-1])
            params.append(param_type)
        elif len(tokens) == 1:
            params.append(tokens[0])
    return params


def parse_return_type(sig_line):
    """Extract return type from a function signature."""
    m = re.match(r'^([\w\s\*]+?)\s+\w[\w\d_]*\s*\(', sig_line)
    if m:
        return m.group(1).strip()
    return 'void'


def parse_function_name(sig_line):
    """Extract function name from a signature."""
    m = re.match(r'^[\w\s\*]+\s+(\w[\w\d_]*)\s*\(', sig_line)
    return m.group(1) if m else None


def extract_address_from_name(name):
    """Try to extract hex address from names like sub_0x140001000, function_0x..."""
    m = re.match(r'(?:sub|function)_0x([0-9a-fA-F]+)', name)
    if m:
        return int(m.group(1), 16)
    return None


KNOWN_CALLING_CONVENTIONS = {'__fastcall', '__stdcall', '__cdecl', '__thiscall',
                            '__vectorcall', '__clrcall'}

def parse_func_signature(line):
    """Parse a C function signature line and return (return_type, func_name, rest).

    Handles formats:
      void func(params)
      void __fastcall func(params)
      unsigned int func(params)  -- (though decompiler avoids this)
    """
    tokens = line.split()
    if len(tokens) < 2:
        return None
    # Check if second token is a calling convention
    conv = None
    ret_type = None
    func_name = None
    if len(tokens) >= 3 and tokens[1] in KNOWN_CALLING_CONVENTIONS:
        ret_type = tokens[0]
        conv = tokens[1]
        func_name = tokens[2]
    elif len(tokens) >= 2:
        ret_type = tokens[0]
        func_name = tokens[1]
    else:
        return None
    return ret_type, func_name


def parse_output(output):
    """Parse decompiler C output into per-function type data.

    Returns dict: addr_or_name -> {return_type, params:[], locals:[]}
    Uses hex address when available, falls back to function name.
    """
    functions = {}
    current_name = None
    current_ret = None
    current_params = []
    current_locals = []
    in_body = False
    brace_depth = 0

    for line in output.split('\n'):
        stripped = line.strip()

        # Function declaration: "ret_type [calling_conv] func_name(params...)"
        parsed = None
        if not line.startswith(' ') and not line.startswith('\t') and '(' in line:
            parsed = parse_func_signature(stripped[:stripped.index('(')])
        if parsed:
            if current_name:
                addr = extract_address_from_name(current_name) or current_name
                functions[addr] = {
                    'return_type': current_ret,
                    'params': current_params[:],
                    'locals': current_locals[:],
                }
            current_ret = parsed[0]
            current_name = parsed[1]
            current_params = parse_function_params(line)
            current_locals = []
            in_body = False
            brace_depth = 0
            continue

        if not current_name:
            continue

        if '{' in line:
            in_body = True
            brace_depth += line.count('{')

        if '}' in line:
            brace_depth -= line.count('}')
            if brace_depth <= 0:
                addr = extract_address_from_name(current_name) or current_name
                functions[addr] = {
                    'return_type': current_ret,
                    'params': current_params[:],
                    'locals': current_locals[:],
                }
                current_name = None
                current_locals = []
                current_params = []
                current_ret = None
                in_body = False
                continue

        if in_body:
            stripped = line.strip()
            if not stripped.endswith(';'):
                continue
            # Skip void/struct/union forward declarations and externs
            if stripped.startswith('//'):
                continue
            # Remove array suffix: "name [N]" -> "name"
            no_array = re.sub(r'\s*\[[^\]]*\]\s*', ' ', stripped.rstrip(';'))
            no_array = no_array.strip()
            parts = no_array.split()
            if len(parts) < 2:
                continue
            # Last token is variable name (possibly with leading *)
            last = parts[-1]
            star_count = 0
            while star_count < len(last) and last[star_count] == '*':
                star_count += 1
            var_name = last[star_count:]
            if not var_name or not var_name[0].isalpha():
                continue
            var_type = ' '.join(parts[:-1])
            if star_count > 0:
                var_type += ' ' + '*' * star_count
            if var_type:
                current_locals.append(var_type)

    # Flush last function
    if current_name:
        addr = extract_address_from_name(current_name) or current_name
        functions[addr] = {
            'return_type': current_ret,
            'params': current_params[:],
            'locals': current_locals[:],
        }

    return functions


def classify_type(tname):
    """Classify a type string into a category."""
    tname = tname.strip()
    if tname in UNDEFINED_TYPES:
        return 'undefined'
    if tname in WINDOWS_API_TYPES:
        return 'windows_api'
    if tname in STANDARD_TYPES:
        return 'standard'
    if tname.endswith('*'):
        base = tname[:-2].strip()
        if base in WINDOWS_API_TYPES:
            return 'windows_api'
        return 'pointer'
    return 'other'


def collect_stats(functions):
    stats = {
        'func_count': len(functions),
        'total_vars': 0,
        'total_params': 0,
        'total_locals': 0,
        'typed_vars': 0,
        'undefined_vars': 0,
        'windows_api_vars': 0,
        'undefined_counts': Counter(),
        'windows_api_types': Counter(),
        'funcs_with_windows_api': 0,
    }
    for fname, fdata in functions.items():
        has_winapi = False
        all_vars = []

        # Return type
        cat = classify_type(fdata['return_type'])
        if cat == 'windows_api':
            has_winapi = True

        # Parameters
        for pt in fdata['params']:
            all_vars.append(('param', pt))

        # Locals
        for lt in fdata['locals']:
            all_vars.append(('local', lt))

        for kind, vt in all_vars:
            stats['total_vars'] += 1
            if kind == 'param':
                stats['total_params'] += 1
            else:
                stats['total_locals'] += 1
            cat = classify_type(vt)
            if cat == 'undefined':
                stats['undefined_vars'] += 1
                stats['undefined_counts'][vt] += 1
            elif cat == 'windows_api':
                stats['typed_vars'] += 1
                stats['windows_api_vars'] += 1
                stats['windows_api_types'][vt] += 1
                has_winapi = True
            elif cat in ('standard', 'pointer', 'other'):
                stats['typed_vars'] += 1

        if has_winapi:
            stats['funcs_with_windows_api'] += 1

    return stats


def classify_quality(tname):
    """Rank a type on a quality scale: 0=undefined, 1=generic, 2=windows_api."""
    tname = tname.strip()
    if tname in UNDEFINED_TYPES:
        return 0
    if tname.endswith('*'):
        base = tname[:-2].strip()
        if base in WINDOWS_API_TYPES:
            return 2
        if base in UNDEFINED_TYPES:
            return 0
        return 1
    if tname in WINDOWS_API_TYPES:
        return 2
    return 1


def diff_functions(before, after):
    """Compare per-function types before vs after bridge.

    Matches functions by hex address (extracted from sub_0x... names)
    or by function name when address is not available.

    Returns dict with change counts and detailed list.
    """
    changes = {
        'params_changed': 0,
        'locals_changed': 0,
        'return_type_changed': 0,
        'undefined_to_typed': 0,
        'generic_to_windows_api': 0,
        'undefined_to_windows_api': 0,
        'funcs_improved': 0,
        'funcs_regressed': 0,
        'total_improvements': 0,
        'detail': [],
    }

    # Build address-based lookup for both sides
    def resolve_key(funcs):
        lookup = {}
        for key in funcs:
            if isinstance(key, int):
                lookup[key] = key
            else:
                addr = extract_address_from_name(str(key))
                if addr:
                    lookup[addr] = key
                else:
                    lookup[key] = key
        return lookup

    b_lookup = resolve_key(before)
    a_lookup = resolve_key(after)

    all_keys = set(list(before.keys()) + list(after.keys()))
    for raw_key in sorted(all_keys, key=lambda k: (isinstance(k, int), str(k))):
        def find_in(funcs, lookup, raw_key):
            if raw_key in funcs:
                return funcs[raw_key]
            addr = extract_address_from_name(str(raw_key)) if not isinstance(raw_key, int) else raw_key
            if addr is not None and addr in lookup:
                return funcs.get(lookup[addr])
            return None

        b = find_in(before, b_lookup, raw_key)
        a = find_in(after, a_lookup, raw_key)
        if not b or not a:
            continue

        improved = False
        fdetail = {'name': str(raw_key), 'changes': []}

        def check_improvement(old_val, new_val, label):
            nonlocal improved
            if old_val == new_val:
                return
            old_q = classify_quality(old_val)
            new_q = classify_quality(new_val)
            old_cat = classify_type(old_val)
            new_cat = classify_type(new_val)
            if new_q > old_q:
                changes['total_improvements'] += 1
                improved = True
                fdetail['changes'].append(f"  {label}: {old_val} -> {new_val}")
                if old_q == 0 and new_q >= 1:
                    changes['undefined_to_typed'] += 1
                if old_q == 0 and new_q == 2:
                    changes['undefined_to_windows_api'] += 1
                if old_q == 1 and new_q == 2:
                    changes['generic_to_windows_api'] += 1

        # Return type
        check_improvement(b['return_type'], a['return_type'], 'return')
        if b['return_type'] != a['return_type']:
            changes['return_type_changed'] += 1

        # Parameters
        for i in range(min(len(b['params']), len(a['params']))):
            if b['params'][i] != a['params'][i]:
                changes['params_changed'] += 1
                check_improvement(b['params'][i], a['params'][i], f'param[{i}]')

        # Locals
        # Match locals by position (same index within function)
        for i in range(min(len(b['locals']), len(a['locals']))):
            if b['locals'][i] != a['locals'][i]:
                changes['locals_changed'] += 1
                check_improvement(b['locals'][i], a['locals'][i], f'local[{i}]')

        if improved:
            changes['funcs_improved'] += 1
            fdetail['improved'] = True
            changes['detail'].append(fdetail)

    return changes


def print_separator(c='='):
    print(c * 72)


def main():
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    exe_default = os.path.join(project_root, 'build-cmake', 'enigma_decompile_full.exe')
    binaries_dir = os.path.join(project_root, 'tests', 'binaries')

    import argparse
    ap = argparse.ArgumentParser(description='Type propagation audit')
    ap.add_argument('--exe', default=exe_default, help=f'Path to enigma_decompile_full.exe')
    ap.add_argument('--pe-binary', action='append', dest='pe_binaries',
                    help='Specific PE binary to analyze (may repeat)')
    args = ap.parse_args()

    exe_path = args.exe
    if not os.path.isfile(exe_path):
        print(f"Error: decompiler not found at {exe_path}")
        return 1

    if args.pe_binaries:
        pe_binaries = [b if os.path.isabs(b) else os.path.join(binaries_dir, b)
                       for b in args.pe_binaries]
    else:
        # The "PE binary" for corpus testing is enigma_test_loader.exe itself
        ldr_exe = os.path.join(project_root, 'build-cmake', 'enigma_test_loader.exe')
        if os.path.isfile(ldr_exe):
            pe_binaries = [ldr_exe]
        else:
            # Fallback: scan for any .exe files
            pe_binaries = [os.path.join(binaries_dir, f)
                           for f in sorted(os.listdir(binaries_dir))
                           if f.endswith('.exe') or f.endswith('.dll')]

    pe_binaries = [b for b in pe_binaries if os.path.isfile(b)]
    if not pe_binaries:
        print("No PE binaries found!")
        return 1

    all_reports = []

    for binary_path in pe_binaries:
        bin_name = os.path.basename(binary_path)
        print_separator()
        print(f"  Binary: {bin_name}")
        print_separator()

        # ---- Before: no bridge ----
        print("  [1/3] Running without bridge...")
        before_out = run_decompiler(exe_path, binary_path, ['-no-bridge', '-raw-types'])
        before_funcs = parse_output(before_out)
        before_stats = collect_stats(before_funcs)
        print(f"        {before_stats['func_count']} functions decompiled")

        # ---- Middle: functions/labels/ranges but no type bridge ----
        print("  [2/3] Running with function/label bridge, no type bridge...")
        typeonly_out = run_decompiler(exe_path, binary_path, ['-no-type-bridge', '-raw-types'])
        typeonly_funcs = parse_output(typeonly_out)
        typeonly_stats = collect_stats(typeonly_funcs)
        print(f"        {typeonly_stats['func_count']} functions decompiled")

        # ---- After: full bridge ----
        print("  [3/3] Running with full bridge...")
        after_out = run_decompiler(exe_path, binary_path, ['-raw-types'])
        after_funcs = parse_output(after_out)
        after_stats = collect_stats(after_funcs)
        print(f"        {after_stats['func_count']} functions decompiled")

        # Diffs
        diff_full = diff_functions(before_funcs, after_funcs)
        diff_type = diff_functions(typeonly_funcs, after_funcs)

        report = {
            'binary': bin_name,
            'before': before_stats,
            'typeonly': typeonly_stats,
            'after': after_stats,
            'diff_full': diff_full,
            'diff_type': diff_type,
            'before_funcs': before_funcs,
            'after_funcs': after_funcs,
            'typeonly_funcs': typeonly_funcs,
        }
        all_reports.append(report)

        # Print per-binary table
        print()
        header = f"  {'Metric':<50} {'Before':>8} {'TypeOnly':>8} {'After':>8}"
        sep = f"  {'-'*52} {'-'*8} {'-'*8} {'-'*8}"
        print(header)
        print(sep)

        rows = [
            ('Functions decompiled', before_stats['func_count'],
             typeonly_stats['func_count'], after_stats['func_count']),
            ('Total variables', before_stats['total_vars'],
             typeonly_stats['total_vars'], after_stats['total_vars']),
            ('  Parameters', before_stats['total_params'],
             typeonly_stats['total_params'], after_stats['total_params']),
            ('  Locals', before_stats['total_locals'],
             typeonly_stats['total_locals'], after_stats['total_locals']),
            ('Typed variables (resolved)', before_stats['typed_vars'],
             typeonly_stats['typed_vars'], after_stats['typed_vars']),
            ('Undefined variables (unresolved)', before_stats['undefined_vars'],
             typeonly_stats['undefined_vars'], after_stats['undefined_vars']),
        ]
        for label, b, t, a in rows:
            print(f"  {label:<50} {b:>8} {t:>8} {a:>8}")

        # Undefined breakdown
        for u in ['undefined1', 'undefined2', 'undefined4', 'undefined8']:
            print(f"  {'  ' + u:<50} {before_stats['undefined_counts'].get(u, 0):>8}"
                  f" {typeonly_stats['undefined_counts'].get(u, 0):>8}"
                  f" {after_stats['undefined_counts'].get(u, 0):>8}")

        print(f"  {'Windows API types used':<50} {before_stats['windows_api_vars']:>8}"
              f" {typeonly_stats['windows_api_vars']:>8}"
              f" {after_stats['windows_api_vars']:>8}")
        print(f"  {'Functions using Windows API':<50} {before_stats['funcs_with_windows_api']:>8}"
              f" {typeonly_stats['funcs_with_windows_api']:>8}"
              f" {after_stats['funcs_with_windows_api']:>8}")

        # Undefined -> typed improvements
        print(f"\n  Type improvement (full bridge vs no bridge):")
        print(f"  {'  Functions with improved types':<50} {diff_full['funcs_improved']:>8}")
        print(f"  {'  Parameters type changed':<50} {diff_full['params_changed']:>8}")
        print(f"  {'  Locals type changed':<50} {diff_full['locals_changed']:>8}")
        print(f"  {'  Return types changed':<50} {diff_full['return_type_changed']:>8}")
        print(f"  {'  Total type improvements':<50} {diff_full['total_improvements']:>8}")
        print(f"  {'  Undefined -> typed':<50} {diff_full['undefined_to_typed']:>8}")
        print(f"  {'  Undefined -> Windows API':<50} {diff_full['undefined_to_windows_api']:>8}")
        print(f"  {'  Generic -> Windows API':<50} {diff_full['generic_to_windows_api']:>8}")

        print(f"\n  Type bridge isolation (type bridge only vs without):")
        print(f"  {'  Functions with improved types':<50} {diff_type['funcs_improved']:>8}")
        print(f"  {'  Parameters type changed':<50} {diff_type['params_changed']:>8}")
        print(f"  {'  Locals type changed':<50} {diff_type['locals_changed']:>8}")
        print(f"  {'  Total type improvements':<50} {diff_type['total_improvements']:>8}")
        print(f"  {'  Undefined -> typed':<50} {diff_type['undefined_to_typed']:>8}")
        print(f"  {'  Undefined -> Windows API':<50} {diff_type['undefined_to_windows_api']:>8}")
        print(f"  {'  Generic -> Windows API':<50} {diff_type['generic_to_windows_api']:>8}")

        # Detailed changes for full bridge
        if diff_full['detail']:
            print(f"\n  Detailed changes (full bridge):")
            for d in diff_full['detail']:
                if d.get('improved'):
                    for c in d['changes']:
                        print(f"    {d['name']}: {c}")

    # ========================
    # GLOBAL SUMMARY
    # ========================
    print_separator()
    print("  GLOBAL SUMMARY")
    print_separator()

    totals = {}
    for metric in ['func_count', 'total_vars', 'total_params', 'total_locals',
                   'typed_vars', 'undefined_vars', 'windows_api_vars',
                   'funcs_with_windows_api']:
        totals[f'{metric}_before'] = sum(r['before'][metric] for r in all_reports)
        totals[f'{metric}_typeonly'] = sum(r['typeonly'][metric] for r in all_reports)
        totals[f'{metric}_after'] = sum(r['after'][metric] for r in all_reports)

    totals['funcs_improved_full'] = sum(r['diff_full']['funcs_improved'] for r in all_reports)
    totals['params_changed_full'] = sum(r['diff_full']['params_changed'] for r in all_reports)
    totals['locals_changed_full'] = sum(r['diff_full']['locals_changed'] for r in all_reports)
    totals['return_changed_full'] = sum(r['diff_full']['return_type_changed'] for r in all_reports)
    totals['total_improvements_full'] = sum(r['diff_full']['total_improvements'] for r in all_reports)
    totals['undef_to_typed_full'] = sum(r['diff_full']['undefined_to_typed'] for r in all_reports)
    totals['undef_to_winapi_full'] = sum(r['diff_full']['undefined_to_windows_api'] for r in all_reports)
    totals['generic_to_winapi_full'] = sum(r['diff_full']['generic_to_windows_api'] for r in all_reports)
    totals['funcs_improved_type'] = sum(r['diff_type']['funcs_improved'] for r in all_reports)
    totals['params_changed_type'] = sum(r['diff_type']['params_changed'] for r in all_reports)
    totals['locals_changed_type'] = sum(r['diff_type']['locals_changed'] for r in all_reports)
    totals['total_improvements_type'] = sum(r['diff_type']['total_improvements'] for r in all_reports)
    totals['undef_to_typed_type'] = sum(r['diff_type']['undefined_to_typed'] for r in all_reports)
    totals['undef_to_winapi_type'] = sum(r['diff_type']['undefined_to_windows_api'] for r in all_reports)
    totals['generic_to_winapi_type'] = sum(r['diff_type']['generic_to_windows_api'] for r in all_reports)

    # Aggregate undefined counts
    undef_labels = ['undefined1', 'undefined2', 'undefined4', 'undefined8']
    for u in undef_labels:
        totals[f'{u}_before'] = sum(r['before']['undefined_counts'].get(u, 0) for r in all_reports)
        totals[f'{u}_typeonly'] = sum(r['typeonly']['undefined_counts'].get(u, 0) for r in all_reports)
        totals[f'{u}_after'] = sum(r['after']['undefined_counts'].get(u, 0) for r in all_reports)

    # Aggregate Windows API types
    all_winapi_types = Counter()
    for r in all_reports:
        all_winapi_types.update(r['after']['windows_api_types'])

    print(f"\n  {'Metric':<50} {'Before':>10} {'After':>10} {'Change':>10}")
    print(f"  {'-'*50} {'-'*10} {'-'*10} {'-'*10}")
    rows = [
        ('Total variables', 'total_vars'),
        ('Typed (resolved)', 'typed_vars'),
        ('Undefined (unresolved)', 'undefined_vars'),
        ('Windows API types', 'windows_api_vars'),
        ('Functions using WinAPI', 'funcs_with_windows_api'),
    ]
    for label, key in rows:
        b = totals[f'{key}_before']
        a = totals[f'{key}_after']
        delta = a - b
        pct = f"{delta / b * 100:+.1f}%" if b > 0 else "N/A"
        print(f"  {label:<50} {b:>10} {a:>10} {pct:>10}")

    print(f"\n  {'Undefined breakdown':<50}")
    for u in undef_labels:
        b = totals[f'{u}_before']
        a = totals[f'{u}_after']
        delta = a - b
        pct = f"{delta / b * 100:+.1f}%" if b > 0 else "N/A"
        print(f"  {'  ' + u:<50} {b:>10} {a:>10} {pct:>10}")

    print(f"\n  {'Improvements from full bridge':<50}")
    print(f"  {'  Functions with improved types':<50} {totals['funcs_improved_full']:>8}")
    print(f"  {'  Parameters type changed':<50} {totals['params_changed_full']:>8}")
    print(f"  {'  Locals type changed':<50} {totals['locals_changed_full']:>8}")
    print(f"  {'  Return types changed':<50} {totals['return_changed_full']:>8}")
    print(f"  {'  Total type improvements':<50} {totals['total_improvements_full']:>8}")
    print(f"  {'  Undefined -> typed total':<50} {totals['undef_to_typed_full']:>8}")
    print(f"  {'  Undefined -> Windows API':<50} {totals['undef_to_winapi_full']:>8}")
    print(f"  {'  Generic -> Windows API':<50} {totals['generic_to_winapi_full']:>8}")

    print(f"\n  {'Type bridge only impact':<50}")
    print(f"  {'  Functions with improved types':<50} {totals['funcs_improved_type']:>8}")
    print(f"  {'  Parameters type changed':<50} {totals['params_changed_type']:>8}")
    print(f"  {'  Locals type changed':<50} {totals['locals_changed_type']:>8}")
    print(f"  {'  Total type improvements':<50} {totals['total_improvements_type']:>8}")
    print(f"  {'  Undefined -> typed total':<50} {totals['undef_to_typed_type']:>8}")
    print(f"  {'  Undefined -> Windows API':<50} {totals['undef_to_winapi_type']:>8}")
    print(f"  {'  Generic -> Windows API':<50} {totals['generic_to_winapi_type']:>8}")

    if all_winapi_types:
        print(f"\n  Windows API types used (after bridge):")
        for tname, count in all_winapi_types.most_common():
            print(f"    {tname:<20} {count:>4} occurrences")

    # Calculate resolution rate
    print(f"\n  Resolution rates:")
    for label, key in [('Before (no bridge)', 'before'), ('After (full bridge)', 'after')]:
        tv = totals[f'total_vars_{key}']
        uv = totals[f'undefined_vars_{key}']
        wv = totals[f'windows_api_vars_{key}']
        res_rate = f"{(1 - uv/tv) * 100:.1f}%" if tv > 0 else "N/A"
        winapi_rate = f"{wv/tv * 100:.1f}%" if tv > 0 else "N/A"
        print(f"  {label}: resolution rate = {res_rate}, Windows API rate = {winapi_rate}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
