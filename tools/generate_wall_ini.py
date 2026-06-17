#!/usr/bin/env python3
import argparse
import configparser
import hashlib
from collections import deque
from pathlib import Path

from PIL import Image, ImageDraw


def parse_color(value):
    text = value.strip().lstrip("#")
    if len(text) != 6:
        raise argparse.ArgumentTypeError("colors must use RRGGBB format")
    try:
        return tuple(int(text[index:index + 2], 16) for index in (0, 2, 4))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("colors must use RRGGBB format") from exc


def color_distance_sq(a, b):
    return sum((int(a[index]) - int(b[index])) ** 2 for index in range(3))


def is_candidate_pixel(pixel, target_colors, tolerance_sq, dark_threshold, saturated_orange):
    r, g, b, alpha = pixel
    if alpha == 0:
        return False
    if r <= dark_threshold and g <= dark_threshold and b <= dark_threshold:
        return False
    if target_colors and any(color_distance_sq((r, g, b), color) <= tolerance_sq for color in target_colors):
        return True
    if saturated_orange and r >= 180 and 55 <= g <= 175 and b <= 70 and r > g + 45:
        return True
    return False


def find_components(image, target_colors, tolerance, dark_threshold, saturated_orange):
    width, height = image.size
    pixels = image.load()
    tolerance_sq = tolerance * tolerance
    visited = bytearray(width * height)
    components = []

    for y in range(height):
        row_base = y * width
        for x in range(width):
            index = row_base + x
            if visited[index]:
                continue
            visited[index] = 1
            if not is_candidate_pixel(pixels[x, y], target_colors, tolerance_sq, dark_threshold, saturated_orange):
                continue

            queue = deque([(x, y)])
            min_x = max_x = x
            min_y = max_y = y
            area = 0

            while queue:
                cx, cy = queue.popleft()
                area += 1
                if cx < min_x:
                    min_x = cx
                if cx > max_x:
                    max_x = cx
                if cy < min_y:
                    min_y = cy
                if cy > max_y:
                    max_y = cy

                for nx, ny in ((cx + 1, cy), (cx - 1, cy), (cx, cy + 1), (cx, cy - 1)):
                    if nx < 0 or ny < 0 or nx >= width or ny >= height:
                        continue
                    next_index = ny * width + nx
                    if visited[next_index]:
                        continue
                    visited[next_index] = 1
                    if is_candidate_pixel(pixels[nx, ny], target_colors, tolerance_sq, dark_threshold, saturated_orange):
                        queue.append((nx, ny))

            components.append({
                "x": min_x,
                "y": min_y,
                "w": max_x - min_x + 1,
                "h": max_y - min_y + 1,
                "area": area,
            })

    return components


def merge_close_rects(rects, padding):
    merged = []
    for rect in sorted(rects, key=lambda item: (item["x"], item["y"], item["w"], item["h"])):
        current = dict(rect)
        changed = True
        while changed:
            changed = False
            next_rects = []
            for other in merged:
                if rects_overlap_or_close(current, other, padding):
                    current = union_rect(current, other)
                    changed = True
                else:
                    next_rects.append(other)
            merged = next_rects
        merged.append(current)
    return merged


def rects_overlap_or_close(a, b, padding):
    return not (
        a["x"] + a["w"] + padding < b["x"] or
        b["x"] + b["w"] + padding < a["x"] or
        a["y"] + a["h"] + padding < b["y"] or
        b["y"] + b["h"] + padding < a["y"]
    )


def union_rect(a, b):
    min_x = min(a["x"], b["x"])
    min_y = min(a["y"], b["y"])
    max_x = max(a["x"] + a["w"], b["x"] + b["w"])
    max_y = max(a["y"] + a["h"], b["y"] + b["h"])
    return {
        "x": min_x,
        "y": min_y,
        "w": max_x - min_x,
        "h": max_y - min_y,
        "area": a.get("area", 0) + b.get("area", 0),
    }


def filter_wall_rects(components, min_area, min_width, min_height, min_aspect):
    rects = []
    for component in components:
        width = component["w"]
        height = component["h"]
        area = component["area"]
        long_side = max(width, height)
        short_side = max(1, min(width, height))
        aspect = long_side / short_side
        if area < min_area:
            continue
        if width < min_width and height < min_height:
            continue
        if aspect < min_aspect:
            continue
        rects.append(component)
    return rects


def write_ini(path, image_path, image, rects):
    config = configparser.ConfigParser()
    config.optionxform = str

    image_bytes = image_path.read_bytes()
    sha256 = hashlib.sha256(image_bytes).hexdigest()

    config["Map"] = {
        "Name": image_path.stem,
        "File": image_path.name,
        "Sha256": sha256,
        "Width": str(image.size[0]),
        "Height": str(image.size[1]),
        "WallCount": str(len(rects)),
    }

    for index, rect in enumerate(rects, start=1):
        config[f"Wall.{index}"] = {
            "Name": f"Wall{index}",
            "Type": "Rect",
            "X": str(rect["x"]),
            "Y": str(rect["y"]),
            "W": str(rect["w"]),
            "H": str(rect["h"]),
            "Color": "00FF00",
            "DetectedArea": str(rect.get("area", 0)),
        }

    with path.open("w", encoding="utf-8") as file:
        config.write(file)


def draw_debug(path, image, rects):
    debug = image.convert("RGBA")
    draw = ImageDraw.Draw(debug)
    for index, rect in enumerate(rects, start=1):
        x1 = rect["x"]
        y1 = rect["y"]
        x2 = rect["x"] + rect["w"] - 1
        y2 = rect["y"] + rect["h"] - 1
        draw.rectangle((x1, y1, x2, y2), outline=(0, 255, 0, 255), width=3)
        draw.text((x1 + 3, y1 + 3), str(index), fill=(0, 255, 0, 255))
    debug.save(path)


def default_output_path(image_path):
    return image_path.with_suffix(".w2w.ini")


def main():
    parser = argparse.ArgumentParser(description="Generate wkWall2Wall wall-zone metadata from a map image.")
    parser.add_argument("maps", nargs="+", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--debug-dir", type=Path)
    parser.add_argument("--color", action="append", type=parse_color, default=[])
    parser.add_argument("--orange-heuristic", action="store_true")
    parser.add_argument("--tolerance", type=int, default=8)
    parser.add_argument("--dark-threshold", type=int, default=8)
    parser.add_argument("--min-area", type=int, default=80)
    parser.add_argument("--min-width", type=int, default=6)
    parser.add_argument("--min-height", type=int, default=20)
    parser.add_argument("--min-aspect", type=float, default=2.0)
    parser.add_argument("--merge-padding", type=int, default=2)
    args = parser.parse_args()

    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)
    if args.debug_dir:
        args.debug_dir.mkdir(parents=True, exist_ok=True)

    for image_path in args.maps:
        try:
            image = Image.open(image_path).convert("RGBA")
        except Exception as exc:
            print(f"skip {image_path}: {exc}")
            continue

        components = find_components(
            image,
            target_colors=args.color or [(255, 123, 0)],
            tolerance=args.tolerance,
            dark_threshold=args.dark_threshold,
            saturated_orange=args.orange_heuristic,
        )
        rects = filter_wall_rects(
            components,
            min_area=args.min_area,
            min_width=args.min_width,
            min_height=args.min_height,
            min_aspect=args.min_aspect,
        )
        rects = merge_close_rects(rects, args.merge_padding)
        rects = sorted(rects, key=lambda item: (item["x"], item["y"]))

        if args.output_dir:
            ini_path = args.output_dir / f"{image_path.stem}.w2w.ini"
        else:
            ini_path = default_output_path(image_path)
        write_ini(ini_path, image_path, image, rects)

        if args.debug_dir:
            debug_path = args.debug_dir / f"{image_path.stem}.debug.png"
        else:
            debug_path = image_path.with_name(f"{image_path.stem}.debug.png")
        draw_debug(debug_path, image, rects)

        print(f"{image_path.name}: {len(rects)} wall candidate(s)")
        print(f"  ini: {ini_path}")
        print(f"  debug: {debug_path}")


if __name__ == "__main__":
    main()
