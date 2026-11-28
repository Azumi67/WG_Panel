#!/usr/bin/env python3
"""Read-only systemd/cgroup v2 resource and host pressure diagnostics."""
import argparse
from pathlib import Path
import subprocess
import time

CGROUP = Path('/sys/fs/cgroup')
UNITS = ('wg-panel.service', 'wg-panel-bot.service', 'wg-reseller-worker.service',
         'wg-plan-shop.service', 'wg-provision.service', 'wg-monitor.service', 'postgresql.service', 'system.slice')
PROPERTIES = ('LoadState', 'ActiveState', 'ControlGroup', 'CPUQuotaPerSecUSec',
              'CPUWeight', 'MemoryHigh', 'MemoryMax', 'TasksMax', 'IOWeight',
              'MemoryCurrent', 'TasksCurrent')
FILES = ('cpu.stat', 'memory.events', 'pids.events', 'cpu.max', 'memory.high',
         'memory.max', 'pids.max', 'io.max', 'cpu.pressure', 'memory.pressure', 'io.pressure')


def systemctl(*args):
    try:
        result = subprocess.run(['systemctl', *args], capture_output=True, text=True, timeout=5)
        return result.stdout if result.returncode == 0 else ''
    except (OSError, subprocess.TimeoutExpired):
        return ''


def discover_units():
    output = systemctl('list-units', '--all', '--type=service', '--plain', '--no-legend', 'postgresql@*.service')
    return list(dict.fromkeys((*UNITS, *(line.split()[0] for line in output.splitlines()
                    if line.split() and line.split()[0].startswith('postgresql@')))))


def unit_properties(unit):
    output = systemctl('show', unit, *('--property='+p for p in PROPERTIES))
    return dict(line.split('=', 1) for line in output.splitlines() if '=' in line)


def cgroup_paths(group, base=CGROUP):
    if not group or not group.startswith('/') or '..' in Path(group).parts:
        return []
    root = base.resolve()
    path = (root / group.lstrip('/')).resolve()
    if not path.is_relative_to(root):
        return []
    return [path, *(p for p in path.parents if p.is_relative_to(root))]


def read(path):
    try:
        return path.read_text().strip()[:16384]
    except OSError:
        return ''


def counters(text):
    result = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            result[parts[0]] = int(parts[1])
        elif parts and parts[0] in ('some', 'full'):
            for item in parts[1:]:
                if item.startswith('total=') and item[6:].isdigit():
                    result[parts[0]+'_stall_us'] = int(item[6:])
    return result


def snapshot(paths):
    result = {}
    for path in paths:
        for name in FILES:
            data = read(path/name)
            if data:
                result[(str(path), name)] = data
    for resource in ('cpu', 'memory', 'io'):
        data = read(Path('/proc/pressure')/resource)
        if data:
            result[('host', resource+'.pressure')] = data
    return result


def differences(before, after):
    for key, data in sorted(after.items()):
        previous = counters(before.get(key, ''))
        for counter, value in counters(data).items():
            if counter in previous and value > previous[counter]:
                yield key[0], key[1], counter, value-previous[counter]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds', type=int, default=30, help='Sampling window, 0-120 seconds')
    args = parser.parse_args(argv)
    if not 0 <= args.seconds <= 120:
        parser.error('Choose 0–120 seconds.')
    print('WG Panel resource pressure (read-only; no credentials or SQL text)', flush=True)
    paths = set()
    for unit in discover_units():
        props = unit_properties(unit)
        if not props or props.get('LoadState') == 'not-found':
            continue
        print('\n'+unit)
        for key in PROPERTIES:
            if key in props:
                print('  '+key+'='+props[key])
        paths.update(cgroup_paths(props.get('ControlGroup')))
    if not (CGROUP/'cgroup.controllers').exists():
        print('cgroup v2 not detected; unit properties and available host pressure still shown.')
    first = snapshot(paths)
    for (group, name), data in sorted(first.items()):
        if name in ('cpu.max','memory.high','memory.max','pids.max','io.max'):
            print(f'{group} {name}: {data.replace(chr(10), "; ")}')
    if not args.seconds:
        return 0
    print(f'\nReproduce the slow reseller login now; sampling for {args.seconds} seconds.', flush=True)
    time.sleep(args.seconds)
    final = snapshot(paths)
    print('\nCounter increases during sampling (not lifetime totals):')
    changes = list(differences(first, final))
    for group, file, key, change in changes:
        print(f'{group} {file} {key}: +{change}')
    if not changes:
        print('No measurable counter increases, or counters unavailable.')
    if any(key in ('nr_throttled','throttled_usec') for _,_,key,_ in changes):
        print('CPU quota throttling observed. Inspect the affected cgroup and its parents.')
    if any(file == 'memory.events' and key in ('high','max','oom','oom_kill') for _,file,key,_ in changes):
        print('Memory reclaim/limit events observed. Inspect memory.high and memory.max.')
    if any(file == 'pids.events' and key == 'max' for _,file,key,_ in changes):
        print('Process/thread limit was reached.')
    if any(file == 'io.pressure' and key.endswith('stall_us') for _,file,key,_ in changes):
        print('I/O pressure observed; compare with PostgreSQL WAL/commit wait diagnostics.')
    print('Counters do not prove causation. Correlate with the application warning timestamps.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
