#!/usr/bin/env python3

import sys, os
import re
import math
from collections import defaultdict

def parse_unit_string(unit_str):
    unit_str = unit_str.strip().lower()
    if 'h' in unit_str:
        return int(re.findall(r'\d+', unit_str)[0]) * 60
    elif 'm' in unit_str:
        return int(re.findall(r'\d+', unit_str)[0])
    elif 'un' in unit_str:
        return int(re.findall(r'\d+', unit_str)[0])
    raise 'specify the min/hour/unit of unit or week!'

def parse_constraint_block(lines):
    constraints = defaultdict(dict)
    tuple_pattern = re.compile(r'\(\s*([^,]*)\s*,\s*([a-zA-Z]+)\s*,\s*([^)]*)\s*\)\s*(?:=\s*(\d+))?')

    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        match = tuple_pattern.match(line)
        if not match:
            continue

        min_raw, tag, max_raw, cost_raw = match.groups()

        if min_raw:
            if min_raw.endswith('d'):
                constraints[tag]['min_days'] = int(min_raw[:-1])
            else:
                constraints[tag]['min_units'] = int(min_raw)

        if max_raw:
            if max_raw.endswith('d'):
                constraints[tag]['max_days'] = int(max_raw[:-1])
            else:
                constraints[tag]['max_units'] = int(max_raw)

        if cost_raw:
            constraints[tag]['violation_cost'] = int(cost_raw)

    return constraints



def read_metadata(meta_file="metadata.txt"):
    tag_map = {}
    rules = {}
    unit_minutes = 30
    valid_tags = []
    constraint_lines = []
    in_constraint_block = False

    meta_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), meta_file)
    with open(meta_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith('[constraints]'):
                in_constraint_block = True
                continue
            if in_constraint_block:
                constraint_lines.append(line)
                continue
            if not line or line.startswith('#'):
                continue
            if line.startswith("unit"):
                unit_minutes = parse_unit_string(line.split('=')[1])
                continue
            tag, rest = line.split('=', 1)
            tag = tag.strip()
            valid_tags.append(tag)
            parts = [p.strip() for p in rest.split('|')]
            label = parts[0]
            tag_map[tag] = label
            rules[tag] = {'label': label}
            for part in parts[1:]:
                if '=' in part:
                    k, v = part.split('=')
                    rules[tag][k.strip()] = v.strip()

    constraint_dict = parse_constraint_block(constraint_lines)
    for tag, cons in constraint_dict.items():
        if tag not in rules:
            rules[tag] = {'label': tag}
        rules[tag].update(cons)

    return tag_map, rules, unit_minutes, sorted(valid_tags, key=lambda x: -len(x))

def parse_log(log_string, valid_tags):
    days = log_string.strip().split('/')
    parsed_data = []

    for day in days:
        day = day.replace(' ', '')
        i = 0
        parsed_day = defaultdict(int)
        while i < len(day):
            match = re.match(r'(\d+)', day[i:])
            if not match:
                break
            amount = int(match.group(1))
            i += len(match.group(1))

            matched_tag = None
            for tag in valid_tags:
                if day[i:].startswith(tag):
                    matched_tag = tag
                    i += len(tag)
                    break

            if matched_tag:
                parsed_day[matched_tag] += amount
            else:
                break
        parsed_data.append(parsed_day)

    return parsed_data

def parse_time_range(arg):
    match = re.match(r"(\d+)([dwm])", arg)
    if not match:
        return None
    value, unit = match.groups()
    value = int(value)
    return {"d": value, "w": value * 7, "m": value * 30}.get(unit, None)

def compute_summary(parsed_data, rules):
    total_per_tag = defaultdict(int)
    tag_days = defaultdict(int)

    for day in parsed_data:
        for tag, value in day.items():
            total_per_tag[tag] += value
            tag_days[tag] += 1

    for tag in rules:
        total_per_tag[tag]  # ensure zero entries

    return total_per_tag, tag_days

def evaluate_constraints(total, days, rules, unit_minutes, report_days):
    warnings = []
    score = 100  # start full

    for tag, rule in rules.items():
        label = rule['label']
        total_units = total.get(tag, 0)
        total_hours = total_units * unit_minutes / 60
        active_days = days.get(tag, 0)
        scale = report_days / 7
        violated = False

        # Day-based constraints
        if "min_days" in rule:
            min_day_required = math.floor(int(rule["min_days"]) * scale)
            if active_days < min_day_required:
                warnings.append(f"⚠️  {label}: below min days ({active_days}d < {min_day_required}d for {report_days}d)")
                violated = True

        if "max_days" in rule:
            max_day_allowed = math.floor(int(rule["max_days"]) * scale)
            if active_days > max_day_allowed:
                warnings.append(f"⚠️  {label}: above max days ({active_days}d > {max_day_allowed}d for {report_days}d)")
                violated = True

        # Unit-based constraints
        if "min_units" in rule:
            min_required = math.floor(int(rule["min_units"]) * scale)
            min_hours = min_required * unit_minutes / 60
            if total_units < min_required:
                warnings.append(f"⚠️  {label}: below min time ({total_hours:.1f}h < {min_hours:.1f}h for {report_days}d)")
                violated = True

        if "max_units" in rule:
            max_allowed = math.floor(int(rule["max_units"]) * scale)
            max_hours = max_allowed * unit_minutes / 60
            if total_units > max_allowed:
                warnings.append(f"⚠️  {label}: above max time ({total_hours:.1f}h > {max_hours:.1f}h for {report_days}d)")
                violated = True

        # Apply penalty if violated
        if violated:
            cost = int(rule.get("violation_cost", 5))
            score -= cost

    return warnings, max(score, 0)


def summarize_with_trend(cur_total, prev_total, rules, tag_map, unit_minutes):
    type_groups = defaultdict(list)
    for tag, rule in rules.items():
        typ = rule.get("type", "other")
        type_groups[typ].append(tag)

    total_units_all = sum(cur_total.values())
    summary = []
    priority_order = {"high": 0, "medium": 1, "low": 2}

    for typ in sorted(type_groups.keys()):
        tags = type_groups[typ]
        cur_type_units = sum([cur_total.get(t, 0) for t in tags])
        cur_type_hours = (cur_type_units * unit_minutes) / 60
        percent = (100 * cur_type_units / total_units_all) if total_units_all else 0

        if prev_total:
            prev_type_units = sum([prev_total.get(t, 0) for t in tags])
            prev_type_hours = (prev_type_units * unit_minutes) / 60
            type_diff = cur_type_hours - prev_type_hours
            trend_header = f"({cur_type_hours:.1f}h, {type_diff:+.1f})"
        else:
            trend_header = f"({cur_type_hours:.1f}h)"

        section = []
        section.append("")
        section.append(f"{f'{typ.capitalize()} ({percent:.1f}%)':<24} {trend_header}")

        sorted_tags = sorted(tags, key=lambda t: (priority_order.get(rules[t].get("priority", ""), 3), tag_map.get(t, t)))

        for tag in sorted_tags:
            label = tag_map.get(tag, tag)
            cur_units = cur_total.get(tag, 0)
            cur_hours = (cur_units * unit_minutes) / 60

            if prev_total:
                prev_units = prev_total.get(tag, 0)
                prev_hours = (prev_units * unit_minutes) / 60
                diff = cur_hours - prev_hours
                trend = f"{diff:+.1f}"
            else:
                trend = "—"

            percent_tags = (cur_units / total_units_all) if total_units_all else 0
            bar = "▪" * int(percent_tags * 60)
            priority = rules[tag].get("priority", "—")[0]
            info_field = f"({cur_hours:.1f}h, {trend})"
            label_field = f"  - {f'{label}[{priority}]':<20} {info_field:<15}| {bar:<60}|" + f' {100 * percent_tags:.0f}%'

            section.append(f"{label_field}")

        summary.append('\n'.join(section))

    return '\n'.join(summary)

def analyze_log_file(log_files, range_arg=None):
    script_dir = os.path.dirname(os.path.realpath(__file__))
    log_string = '/'.join([
        open(os.path.join(script_dir, file), 'r').read().strip().strip('/')
        for file in log_files
    ])

    tag_map, rules, unit_minutes, valid_tags = read_metadata()
    log_data = parse_log(log_string, valid_tags)

    if range_arg:
        period = parse_time_range(range_arg)
        current = log_data[-period:]
        cur_total, cur_days = compute_summary(current, rules)


        prev_total = None
        if len(log_data) >= period * 2:
            previous = log_data[-2 * period:-period]
            prev_total, _ = compute_summary(previous, rules)

        print(f"=== ACTIVITY SUMMARY (last {period} days) ===")
    else:
        period = len(log_data)
        cur_total, cur_days = compute_summary(log_data, rules)
        prev_total = None

        print(f"=== ACTIVITY SUMMARY (last {period} days) ===")

    print(summarize_with_trend(cur_total, prev_total, rules, tag_map, unit_minutes))

    print("\n=== CONSTRAINT CHECKS ===")
    warnings, score = evaluate_constraints(cur_total, cur_days, rules, unit_minutes, period)
    if warnings:
        for w in warnings:
            print(w)
        print(f"\n📉 Constraint Score: {score}/100")
    else:
        print("✅ All constraints satisfied.")
        print("📈 Constraint Score: 100/100")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python activity_report.py <log1.txt> [log2.txt ...] [range]')
    else:
        # Check if the last argument is a time range (e.g. 7d, 2w)
        last_arg = sys.argv[-1]
        if re.match(r"^\d+[dwm]$", last_arg):
            log_files = sys.argv[1:-1]
            range_arg = last_arg
        else:
            log_files = sys.argv[1:]
            range_arg = None

        analyze_log_file(log_files, range_arg)
