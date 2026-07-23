"""
VEILUX-NG Feature 6: Public Image Analysis
NDPA Basis: EXIF metadata embedded in publicly accessible images (Section 31).
Images are not stored — analysed in memory only.
"""

import io
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import quote

from PIL import Image, ExifTags
from PIL.ExifTags import TAGS, GPSTAGS

from veilux_ng.core.logger import get_logger
from veilux_ng.utils.helpers import safe_request
from veilux_ng.utils.validators import validate_url

logger = get_logger("image_analysis")


@dataclass
class GPSCoordinates:
    latitude: float
    longitude: float
    altitude: Optional[float] = None
    maps_url: str = ""


@dataclass
class ImageReport:
    source_url: str
    format: Optional[str] = None
    mode: Optional[str] = None
    width: Optional[int] = None
    height: Optional[int] = None
    file_size_kb: Optional[float] = None
    camera_make: Optional[str] = None
    camera_model: Optional[str] = None
    software: Optional[str] = None
    date_taken: Optional[str] = None
    gps: Optional[GPSCoordinates] = None
    exif_raw: dict = field(default_factory=dict)
    reverse_search_links: dict[str, str] = field(default_factory=dict)
    tampering_indicators: list[str] = field(default_factory=list)
    notes: str = ""


class ImageAnalysis:
    """
    Downloads a publicly accessible image and extracts EXIF metadata,
    GPS coordinates, and generates reverse image search links.
    Image data is never persisted to disk.
    """

    def analyze(self, image_url: str) -> ImageReport:
        if not validate_url(image_url):
            raise ValueError(f"Invalid image URL: {image_url}")

        report = ImageReport(source_url=image_url)
        logger.info("Fetching image for analysis: %s", image_url[:80])

        resp = safe_request(image_url, timeout=15)
        if not resp or resp.status_code != 200:
            report.notes = "Could not download image."
            return report

        content_type = resp.headers.get("Content-Type", "")
        if "image" not in content_type:
            report.notes = f"URL does not point to an image (Content-Type: {content_type})."
            return report

        raw_bytes = resp.content
        report.file_size_kb = round(len(raw_bytes) / 1024, 2)

        try:
            img = Image.open(io.BytesIO(raw_bytes))
            report.format = img.format
            report.mode = img.mode
            report.width, report.height = img.size
        except Exception as exc:
            report.notes = f"Could not open image with Pillow: {exc}"
            return report

        self._extract_exif(img, report)
        self._detect_tampering(img, report)
        report.reverse_search_links = self._reverse_search_links(image_url)

        logger.info(
            "Image analysis complete: %dx%d %s, GPS=%s",
            report.width or 0, report.height or 0,
            report.format, "yes" if report.gps else "no",
        )
        return report

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _extract_exif(self, img: Image.Image, report: ImageReport) -> None:
        try:
            raw_exif = img._getexif()  # type: ignore[attr-defined]
            if not raw_exif:
                return

            exif: dict = {}
            for tag_id, value in raw_exif.items():
                tag = TAGS.get(tag_id, str(tag_id))
                exif[tag] = value

            report.exif_raw = {k: str(v) for k, v in exif.items()}
            report.camera_make = exif.get("Make")
            report.camera_model = exif.get("Model")
            report.software = exif.get("Software")
            report.date_taken = str(exif.get("DateTimeOriginal") or exif.get("DateTime") or "")

            gps_info = exif.get("GPSInfo")
            if gps_info:
                report.gps = self._parse_gps(gps_info)
        except (AttributeError, Exception) as exc:
            logger.debug("EXIF extraction failed: %s", exc)

    @staticmethod
    def _parse_gps(gps_info: dict) -> Optional[GPSCoordinates]:
        try:
            gps: dict = {}
            for key, val in gps_info.items():
                gps[GPSTAGS.get(key, key)] = val

            def to_degrees(values) -> float:
                d, m, s = [float(v) for v in values]
                return d + (m / 60.0) + (s / 3600.0)

            lat = to_degrees(gps["GPSLatitude"])
            if gps.get("GPSLatitudeRef") == "S":
                lat = -lat

            lon = to_degrees(gps["GPSLongitude"])
            if gps.get("GPSLongitudeRef") == "W":
                lon = -lon

            alt = None
            if "GPSAltitude" in gps:
                alt = float(gps["GPSAltitude"])
                if gps.get("GPSAltitudeRef") == b"\x01":
                    alt = -alt

            maps_url = f"https://www.google.com/maps?q={lat:.6f},{lon:.6f}"
            return GPSCoordinates(latitude=lat, longitude=lon, altitude=alt, maps_url=maps_url)
        except Exception:
            return None

    @staticmethod
    def _detect_tampering(img: Image.Image, report: ImageReport) -> None:
        """Heuristic tampering indicators — not forensic-grade."""
        indicators = []
        exif_raw = report.exif_raw

        software = exif_raw.get("Software", "").lower()
        for editor in ("photoshop", "gimp", "lightroom", "affinity", "canva", "snapseed"):
            if editor in software:
                indicators.append(f"Editing software detected in EXIF: {exif_raw.get('Software')}")
                break

        if exif_raw.get("DateTimeOriginal") and exif_raw.get("DateTime"):
            if exif_raw["DateTimeOriginal"] != exif_raw["DateTime"]:
                indicators.append("EXIF DateTimeOriginal differs from DateTime — possible re-save.")

        report.tampering_indicators = indicators

    @staticmethod
    def _reverse_search_links(image_url: str) -> dict[str, str]:
        encoded = quote(image_url, safe="")
        return {
            "Google":  f"https://www.google.com/searchbyimage?image_url={encoded}",
            "Bing":    f"https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{encoded}",
            "Yandex":  f"https://yandex.com/images/search?url={encoded}&rpt=imageview",
            "TinEye":  f"https://tineye.com/search?url={encoded}",
        }
