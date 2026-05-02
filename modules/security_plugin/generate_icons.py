from pathlib import Path

from PIL import Image, ImageDraw


BG_COLOR = "#0f172a"
SHIELD_COLOR = "#38bdf8"
SIZES = (16, 48, 128)


def _shield_points(size: int) -> list[tuple[float, float]]:
    # Scaled shield silhouette based on normalized coordinates.
    normalized = [
        (0.50, 0.10),
        (0.22, 0.20),
        (0.22, 0.48),
        (0.50, 0.88),
        (0.78, 0.48),
        (0.78, 0.20),
    ]
    return [(x * size, y * size) for x, y in normalized]


def generate_icon(size: int, output_path: Path) -> None:
    image = Image.new("RGBA", (size, size), BG_COLOR)
    draw = ImageDraw.Draw(image)
    draw.polygon(_shield_points(size), fill=SHIELD_COLOR)
    image.save(output_path, "PNG")


def main() -> None:
    base_dir = Path(__file__).resolve().parent
    icons_dir = base_dir / "icons"
    icons_dir.mkdir(parents=True, exist_ok=True)

    for size in SIZES:
        generate_icon(size, icons_dir / f"icon{size}.png")

    print("✅ İkonlar oluşturuldu!")


if __name__ == "__main__":
    main()
