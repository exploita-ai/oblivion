#!/usr/bin/python3
"""Compile the installed Debian XKB/tzdata catalog into a read-only UI asset."""
import json
from pathlib import Path
import xml.etree.ElementTree as ET

layouts = ET.parse('/usr/share/X11/xkb/rules/base.xml').getroot().find('layoutList')
keyboards = []
for layout in layouts:
    config = layout.find('configItem')
    variants = [{"value": "", "label": "Default"}]
    for variant in layout.findall('variantList/variant/configItem'):
        variants.append({"value": variant.findtext('name'), "label": variant.findtext('description')})
    keyboards.append({"value": config.findtext('name'), "label": config.findtext('description'), "variants": variants})
zones = {'UTC'}
for line in Path('/usr/share/zoneinfo/zone.tab').read_text().splitlines():
    if line and not line.startswith('#'):
        zones.add(line.split('\t')[2])
target = Path('/usr/share/oblivion/settings-catalog.json')
target.parent.mkdir(parents=True, exist_ok=True)
target.write_text(json.dumps({"keyboards": sorted(keyboards, key=lambda entry: entry['label']), "timezones": sorted(zones)}) + '\n')
target.chmod(0o644)
