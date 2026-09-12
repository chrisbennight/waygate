# /// script
# requires-python = ">=3.11"
# dependencies = ["fonttools==4.65.0", "resvg-py==0.5.0"]
# ///
"""Export the checked-in Precision artwork. Run with uv run; use --check in review."""
import argparse
from html import escape
from pathlib import Path
import xml.etree.ElementTree as ET

import resvg_py
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

ROOT = Path(__file__).resolve().parent
NS = '{http://www.w3.org/2000/svg}'
PALETTES = {
    'light': ('#f7f5f0', '#23201b', '#1e5f46', '#80642d'),
    'dark': ('#191b1a', '#f3f0e7', '#86b39b', '#d4b77c'),
}
FONT = instantiateVariableFont(TTFont(ROOT / 'Outfit.ttf'), {'wght': 350})
GLYPHS = FONT.getGlyphSet()
CMAP = FONT.getBestCmap()
UNITS = FONT['head'].unitsPerEm
SYMBOL = ET.parse(ROOT / 'symbol.svg').getroot().find(NS + 'g')
FEATURES = list(ET.parse(ROOT / 'features.svg').getroot().find(NS + 'defs'))


def text(value, x, y, size, color, spacing=0, center=False):
    """Outline the supplied lettering so host fonts cannot change the artwork."""
    scale = size / UNITS
    advances = [FONT['hmtx'][CMAP[ord(c)]][0] * scale for c in value]
    width = sum(advances) + spacing * max(0, len(value) - 1)
    if center:
        x -= width / 2
    paths = []
    for char, advance in zip(value, advances):
        pen = SVGPathPen(GLYPHS, ntos=lambda n: f'{n:.2f}'.rstrip('0').rstrip('.') if n else '0')
        GLYPHS[CMAP[ord(char)]].draw(pen)
        paths.append(f'<path transform="translate({x:.3f} {y}) scale({scale:.6f} {-scale:.6f})" d="{pen.getCommands()}"/>')
        x += advance + spacing
    return f'<g fill="{color}" aria-label="{escape(value, quote=True)}">' + ''.join(paths) + '</g>'


def mark(x, y, size, theme, mono=False):
    bg, ink, green, brass = PALETTES[theme]
    source = ET.tostring(SYMBOL, encoding='unicode')
    for old, new in zip(PALETTES['light'], (bg, ink, ink if mono else green, ink if mono else brass)):
        source = source.replace(old, new)
    if theme == 'dark' and not mono:
        source = source.replace(f'fill="{green}"', 'fill="#315c50"')
    return f'<g transform="translate({x} {y}) scale({size / 128})">{source}</g>'


def svg(width, height, title, body, background=None):
    backdrop = f'<rect width="{width}" height="{height}" fill="{background}"/>' if background else ''
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
            f'viewBox="0 0 {width} {height}" role="img" aria-labelledby="title">\n'
            f'<title id="title">{escape(title)}</title>\n{backdrop}\n{body}\n</svg>\n').encode()


def connection_art(theme):
    bg, ink, green, brass = PALETTES[theme]
    parts = [f'<g stroke="{green}" stroke-width="2" fill="none" stroke-linecap="round">'
             '<path d="M104 120H150C180 120 180 134 212 134S254 120 276 120H286"/>'
             '<path d="M427 120H440C520 120 510 51 571 51H620 M440 120H640 M440 120C520 120 510 189 571 189H620"/></g>',
             mark(274, 50, 160, theme)]
    node_fill = '#315c50' if theme == 'dark' else green
    for x, y in [(104, 120), (620, 51), (640, 120), (620, 189)]:
        parts.append(f'<circle cx="{x}" cy="{y}" r="7" fill="{node_fill}" stroke="{brass}" stroke-width="2"/>')
    parts.append(text('IDEAS', 42, 124, 13, ink, 1.5))
    for label, x, y in [('MODELS', 643, 55), ('DATA', 663, 124), ('TOOLS', 643, 193)]:
        parts.append(text(label, x, y, 13, ink, 2))
    return ''.join(parts)


def outputs():
    result = {}
    for theme, (bg, ink, green, brass) in PALETTES.items():
        result[f'symbol-on-{theme}.svg'] = svg(128, 128, 'Waygate', mark(0, 0, 128, theme))
        result[f'wordmark-on-{theme}.svg'] = svg(530, 104, 'Waygate', mark(4, 4, 96, theme) + text('WAYGATE', 126, 65, 42, ink, 8))
        result[f'header-{theme}.svg'] = svg(760, 240, 'Ideas connect through Waygate to models, data, and tools', connection_art(theme) + text('WAYGATE', 354, 223, 19, ink, 5, center=True), bg)
        app = svg(256, 256, 'Waygate app icon', mark(24, 24, 208, theme), bg)
        result[f'app-{theme}.png'] = resvg_py.svg_to_bytes(svg_string=app.decode(), skip_system_fonts=True)
    result['symbol-mono.svg'] = svg(128, 128, 'Waygate', mark(0, 0, 128, 'light', mono=True))
    for size in (16, 32):
        result[f'favicon-{size}.png'] = resvg_py.svg_to_bytes(svg_string=result['symbol-on-dark.svg'].decode(), width=size, height=size, skip_system_fonts=True)
    bg, ink, green, brass = PALETTES['dark']
    social = mark(60, 52, 128, 'dark') + text('WAYGATE', 220, 137, 61, ink, 11)
    social += f'<path d="M0 210H1280" stroke="{ink}" stroke-opacity=".2"/>'
    social += '<g transform="translate(54 240) scale(1.5)">' + connection_art('dark') + text('WAYGATE', 354, 239, 22, ink, 7, center=True) + '</g>'
    result['social-preview.png'] = resvg_py.svg_to_bytes(svg_string=svg(1280, 640, 'Waygate — ideas connect to models, data, and tools', social, bg).decode(), skip_system_fonts=True)
    sheet = []
    for i, feature in enumerate(FEATURES):
        name = feature.attrib['id']
        shape = ''.join(ET.tostring(child, encoding='unicode') for child in feature)
        drawing = f'<g fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round">{shape}</g>'
        result[f'{name}.svg'] = svg(24, 24, name.capitalize(), drawing)
        x, y = 40 + (i % 4) * 180, 42 + (i // 4) * 165
        sheet.append(f'<g color="{ink}" transform="translate({x + 36} {y}) scale(3)">{drawing}</g>')
        sheet.append(text(name.upper(), x + 72, y + 107, 13, ink, 1.5, center=True))
    result['feature-icons.svg'] = svg(800, 360, 'Models, data, tools, policies, activity, workflows, files, and identity', ''.join(sheet), bg)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='compare exports without writing')
    args = parser.parse_args()
    assets = outputs()
    destination = ROOT / 'assets'
    if args.check:
        different = [name for name, data in assets.items() if not (destination / name).is_file() or (destination / name).read_bytes() != data]
        if different:
            raise SystemExit('Outdated branding exports: ' + ', '.join(different))
        print('Branding exports match their sources.')
    else:
        destination.mkdir(exist_ok=True)
        for name, data in assets.items():
            (destination / name).write_bytes(data)
        print('Exported branding assets.')


if __name__ == '__main__':
    main()
