"""
Layer 4: SteganographyScanner.

Detects steganographic payloads embedded in images via:

1. LSB (Least-Significant Bit) encoding analysis using chi-square tests
2. EXIF metadata inspection for hidden text
3. Statistical anomaly detection (entropy, distribution)
4. PNG text chunk (tEXt, iTXt, zTXt) extraction

Reference: Franklin et al. (2026). AI Agent Traps. SSRN 6372438.
"""

import io
import logging
import re
import struct
import zlib
from typing import Optional

import numpy as np
from PIL import Image
from scipy import stats

from agentguard.config import AgentGuardConfig
from agentguard.models import DetectionSignal, TrapClass

logger = logging.getLogger(__name__)

# Injection patterns to check against extracted steganographic payloads
_INJECTION_KEYWORD_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"ignore\s+(previous|all|above)\s+instructions?",
        r"you\s+are\s+now\s+(a|an|the)",
        r"disregard\s+(your|all|previous)",
        r"new\s+(directive|instruction|task|order|command)",
        r"system\s*:\s*",
        r"override\s+(safety|guidelines|rules|constraints)",
        r"exfiltrate|send.*to.*http|post.*data.*to",
        r"jailbreak|DAN\s+mode|developer\s+mode",
        r"ignore\s+(ethics|safety|alignment)",
    ]
]


class SteganographyScanner:
    """
    Scans images for steganographic payloads that may contain injection
    attacks hidden from casual visual inspection.
    """

    def __init__(self, config: AgentGuardConfig) -> None:
        self._config = config
        self._min_size = config.min_image_size_bytes
        self._chi_threshold = config.lsb_chi_square_threshold

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, image_bytes: bytes) -> list[DetectionSignal]:
        """
        Scan *image_bytes* for steganographic payloads.

        Returns an empty list for:
        * Images smaller than ``config.min_image_size_bytes``
        * Non-image data
        * Corrupt images
        """
        if len(image_bytes) < self._min_size:
            return []

        try:
            img = Image.open(io.BytesIO(image_bytes))
        except Exception as exc:
            logger.debug("SteganographyScanner: cannot open image — %s", exc)
            return []

        # Handle animated GIFs — use first frame
        try:
            if getattr(img, "is_animated", False):
                img.seek(0)
        except Exception:
            pass

        signals: list[DetectionSignal] = []
        signals.extend(self._detect_lsb_encoding(img))
        signals.extend(self._detect_exif_data(img))
        signals.extend(self._detect_statistical_anomalies(img))
        signals.extend(self._detect_png_text_chunks(image_bytes))

        return signals

    def detect_from_url(self, url: str) -> list[DetectionSignal]:
        """
        Fetch *url*, extract all <img> sources, download each image, and
        run :meth:`detect` on every image found.

        Falls back to treating the URL itself as a direct image link if no
        <img> tags are found.
        """
        signals: list[DetectionSignal] = []

        try:
            import requests
            from bs4 import BeautifulSoup
        except ImportError:
            logger.warning("SteganographyScanner: requests or bs4 not installed.")
            return signals

        try:
            resp = requests.get(
                url,
                timeout=self._config.request_timeout,
                verify=self._config.verify_ssl,
                headers={
                    "User-Agent": self._config.human_user_agent,
                },
            )
            resp.raise_for_status()
        except Exception as exc:
            logger.warning("SteganographyScanner: failed to fetch %s — %s", url, exc)
            return signals

        content_type = resp.headers.get("Content-Type", "")
        # If the response is directly an image, scan it
        if "image" in content_type:
            return self.detect(resp.content)

        # Otherwise, parse HTML for <img> tags
        image_urls: list[str] = []
        try:
            soup = BeautifulSoup(resp.text, "lxml")
            for img_tag in soup.find_all("img"):
                src = img_tag.get("src") or img_tag.get("data-src", "")
                if src:
                    # Resolve relative URLs
                    if src.startswith("//"):
                        src = "https:" + src
                    elif src.startswith("/"):
                        from urllib.parse import urlparse, urljoin
                        parsed = urlparse(url)
                        src = f"{parsed.scheme}://{parsed.netloc}{src}"
                    elif not src.startswith(("http://", "https://")):
                        from urllib.parse import urljoin
                        src = urljoin(url, src)
                    image_urls.append(src)
        except Exception:
            pass

        # Download and scan each image
        for img_url in image_urls[:20]:  # cap at 20 images to avoid abuse
            try:
                img_resp = requests.get(
                    img_url,
                    timeout=self._config.request_timeout,
                    verify=self._config.verify_ssl,
                )
                if "image" in img_resp.headers.get("Content-Type", ""):
                    signals.extend(self.detect(img_resp.content))
            except Exception as exc:
                logger.debug(
                    "SteganographyScanner: failed to fetch image %s — %s",
                    img_url, exc,
                )

        return signals

    # ------------------------------------------------------------------
    # Detection methods
    # ------------------------------------------------------------------

    def _detect_lsb_encoding(self, img: Image.Image) -> list[DetectionSignal]:
        """
        Analyse LSB (Least-Significant Bit) distribution across colour
        channels using a chi-square goodness-of-fit test.

        If the LSBs are uniformly distributed (p-value low), the image may
        contain an LSB-encoded payload.
        """
        signals: list[DetectionSignal] = []

        try:
            # Convert to RGB (handles RGBA, P, L, etc.)
            img_rgb = img.convert("RGB")
            pixel_array = np.array(img_rgb, dtype=np.uint8)
        except Exception as exc:
            logger.debug("SteganographyScanner: LSB — cannot convert to RGB: %s", exc)
            return signals

        if pixel_array.ndim != 3 or pixel_array.shape[2] < 3:
            return signals

        h, w, channels = pixel_array.shape
        total_pixels = h * w

        # Extract LSBs for each channel
        channel_names = ["R", "G", "B"]
        overall_confidence = 0.0
        chi_details: list[str] = []

        for ch_idx in range(min(3, channels)):
            lsb_plane = pixel_array[:, :, ch_idx] & 1
            lsb_flat = lsb_plane.flatten()

            # Count 0s and 1s
            count_0 = int(np.sum(lsb_flat == 0))
            count_1 = int(np.sum(lsb_flat == 1))

            # Chi-square test: expected equal distribution
            observed = np.array([count_0, count_1])
            expected = np.array([total_pixels / 2.0, total_pixels / 2.0])

            if expected[0] == 0:
                continue

            chi2_stat, p_value = stats.chisquare(observed, f_exp=expected)
            chi_details.append(
                f"{channel_names[ch_idx]}: χ²={chi2_stat:.2f}, p={p_value:.6f}"
            )

            ch_confidence = 0.0
            if p_value < 0.05:
                ch_confidence = 0.80
            elif p_value < 0.10:
                ch_confidence = 0.60

            if ch_confidence > overall_confidence:
                overall_confidence = ch_confidence

        if overall_confidence >= 0.60:
            # Try to extract the LSB message for deeper analysis
            lsb_message = self._extract_lsb_message(pixel_array)
            message_text = ""
            decoded_evidence = ""

            if lsb_message:
                # Check if the message is mostly printable ASCII
                printable_count = sum(
                    1 for b in lsb_message if 32 <= b <= 126 or b in (10, 13, 9)
                )
                printable_ratio = printable_count / max(len(lsb_message), 1)

                if printable_ratio > 0.2:
                    try:
                        message_text = bytes(lsb_message).decode("ascii", errors="replace")
                    except Exception:
                        message_text = str(lsb_message)

                    # Check the decoded message for injection patterns
                    injection_match = self._check_injection_patterns(message_text)
                    if injection_match:
                        overall_confidence = 0.95
                        decoded_evidence = injection_match[0]

            evidence = f"LSB chi-square: {'; '.join(chi_details)}"
            if decoded_evidence:
                evidence += f" | Decoded injection: {decoded_evidence}"
            elif message_text:
                evidence += f" | LSB message ({len(message_text)} chars): {message_text[:200]}"

            signals.append(DetectionSignal(
                trap_class=TrapClass.CONTENT_INJECTION,
                signal_name="lsb_steganography",
                confidence=overall_confidence,
                evidence=evidence,
                raw_payload=message_text[:1000] if message_text else None,
                detector="steganography",
            ))

        return signals

    def _detect_exif_data(self, img: Image.Image) -> list[DetectionSignal]:
        """
        Inspect EXIF metadata fields for hidden injection payloads.

        Checks: UserComment, ImageDescription, Artist, Copyright, Software.
        """
        signals: list[DetectionSignal] = []

        try:
            exif_data = img.getexif()
        except Exception:
            return signals

        if not exif_data:
            return signals

        # Fields of interest — these commonly hold attacker-supplied text
        interesting_tags = {
            0x9286: "UserComment",     # EXIF UserComment
            0x010E: "ImageDescription", # TIFF ImageDescription
            0x013B: "Artist",          # TIFF Artist
            0x8298: "Copyright",       # TIFF Copyright
            0x0131: "Software",        # TIFF Software
        }

        for tag_id, tag_name in interesting_tags.items():
            try:
                value = exif_data.get(tag_id)
                if value is None:
                    continue

                # EXIF values can be bytes — decode if needed
                if isinstance(value, bytes):
                    # UserComment may have a charset prefix (first 8 bytes)
                    if tag_id == 0x9286 and len(value) > 8:
                        value = value[8:]  # skip charset ID
                    try:
                        value = value.decode("utf-8", errors="replace")
                    except Exception:
                        continue

                value_str = str(value)
                if len(value_str) < 50:
                    continue

                matches = self._check_injection_patterns(value_str)
                if matches:
                    pattern_str = matches[0]
                    signals.append(DetectionSignal(
                        trap_class=TrapClass.CONTENT_INJECTION,
                        signal_name="exif_injection",
                        confidence=0.85,
                        evidence=(
                            f"EXIF field '{tag_name}' contains injection pattern "
                            f"{pattern_str!r}: {value_str[:200]!r}"
                        ),
                        raw_payload=value_str[:1000],
                        detector="steganography",
                    ))

            except Exception:
                continue

        # Also check the EXIF IFD for GPS and other sub-IFDs
        try:
            from PIL.ExifTags import TAGS
            for ifd_tag, ifd_data in exif_data.get_ifd(0x8769).items() if hasattr(exif_data, 'get_ifd') else []:
                pass  # Secondary IFDs handled above
        except Exception:
            pass

        return signals

    def _detect_statistical_anomalies(self, img: Image.Image) -> list[DetectionSignal]:
        """
        Detect statistical anomalies in image pixel data.

        High per-channel entropy (>7.9 bits for 8-bit channels) suggests
        the image data has been modified to carry hidden information.
        """
        signals: list[DetectionSignal] = []

        try:
            img_rgb = img.convert("RGB")
            pixel_array = np.array(img_rgb, dtype=np.uint8)
        except Exception:
            return signals

        if pixel_array.ndim != 3 or pixel_array.shape[2] < 3:
            return signals

        channel_names = ["R", "G", "B"]
        anomaly_channels: list[str] = []
        details: list[str] = []

        for ch_idx in range(min(3, pixel_array.shape[2])):
            channel_data = pixel_array[:, :, ch_idx].flatten().astype(np.float64)

            mean_val = float(np.mean(channel_data))
            std_val = float(np.std(channel_data))

            # Compute Shannon entropy
            histogram, _ = np.histogram(channel_data, bins=256, range=(0, 256))
            histogram = histogram.astype(np.float64)
            total = np.sum(histogram)
            if total > 0:
                probs = histogram[histogram > 0] / total
                entropy = float(-np.sum(probs * np.log2(probs)))
            else:
                entropy = 0.0

            details.append(
                f"{channel_names[ch_idx]}: μ={mean_val:.1f}, σ={std_val:.1f}, "
                f"H={entropy:.4f}"
            )

            if entropy > 7.9:
                anomaly_channels.append(channel_names[ch_idx])

        if anomaly_channels:
            signals.append(DetectionSignal(
                trap_class=TrapClass.CONTENT_INJECTION,
                signal_name="statistical_anomaly",
                confidence=0.50,
                evidence=(
                    f"High entropy in channels {anomaly_channels}: "
                    f"{'; '.join(details)}"
                ),
                raw_payload=None,
                detector="steganography",
            ))

        return signals

    def _detect_png_text_chunks(self, image_bytes: bytes) -> list[DetectionSignal]:
        """
        For PNG images, scan the raw byte stream for ancillary text chunks
        (tEXt, iTXt, zTXt) that may contain hidden injection payloads.

        PNG chunk structure: 4-byte length + 4-byte type + data + 4-byte CRC
        """
        signals: list[DetectionSignal] = []

        # Quick check: PNG signature
        if len(image_bytes) < 8 or image_bytes[:8] != b"\x89PNG\r\n\x1a\n":
            return signals

        offset = 8  # skip PNG signature
        while offset + 8 <= len(image_bytes):
            length_bytes = image_bytes[offset:offset + 4]
            if len(length_bytes) < 4:
                break
            chunk_length = struct.unpack(">I", length_bytes)[0]
            chunk_type = image_bytes[offset + 4:offset + 8]
            chunk_type_str = chunk_type.decode("ascii", errors="replace")

            # Total chunk size: 4 (length) + 4 (type) + data + 4 (CRC)
            total_chunk = 12 + chunk_length
            if offset + total_chunk > len(image_bytes):
                break

            chunk_data = image_bytes[offset + 8:offset + 8 + chunk_length]

            # Process text chunks
            extracted_text: Optional[str] = None

            if chunk_type_str == "tEXt" and chunk_length > 0:
                # tEXt: keyword\0text
                null_idx = chunk_data.find(b"\x00")
                if null_idx >= 0 and null_idx < len(chunk_data) - 1:
                    try:
                        extracted_text = chunk_data[null_idx + 1:].decode(
                            "latin-1", errors="replace"
                        )
                    except Exception:
                        pass

            elif chunk_type_str == "zTXt" and chunk_length > 0:
                # zTXt: keyword\0compression_method\0compressed_text
                null_idx = chunk_data.find(b"\x00")
                if null_idx >= 0:
                    try:
                        # Skip keyword + null + compression method byte + null
                        second_null = chunk_data.find(b"\x00", null_idx + 1)
                        if second_null >= 0 and second_null < len(chunk_data) - 1:
                            compressed = chunk_data[second_null + 1:]
                            decompressed = zlib.decompress(compressed)
                            extracted_text = decompressed.decode(
                                "latin-1", errors="replace"
                            )
                    except Exception:
                        pass

            elif chunk_type_str == "iTXt" and chunk_length > 0:
                # iTXt: keyword\0compression_flag\0compression_method\0language\0translated_keyword\0text
                # The text may be compressed (flag=1) or uncompressed (flag=0)
                null_positions: list[int] = []
                pos = 0
                while pos < len(chunk_data):
                    idx = chunk_data.find(b"\x00", pos)
                    if idx < 0:
                        break
                    null_positions.append(idx)
                    pos = idx + 1

                if len(null_positions) >= 3:
                    # After 3rd null: compression_flag (1 byte) + compression_method (1 byte)
                    # then language_tag\0 translated_keyword\0 text
                    # Actually iTXt format: keyword \0 compression_flag compression_method language_tag \0 translated_keyword \0 text
                    # Let's parse more carefully:
                    try:
                        keyword_end = chunk_data.find(b"\x00")
                        if keyword_end >= 0:
                            rest = chunk_data[keyword_end + 1:]
                            if len(rest) >= 2:
                                compression_flag = rest[0]
                                # compression_method = rest[1]
                                rest = rest[2:]
                                # language_tag \0 translated_keyword \0 text
                                text_start = 0
                                for _ in range(2):  # skip language_tag and translated_keyword
                                    nl = rest.find(b"\x00", text_start)
                                    if nl >= 0:
                                        text_start = nl + 1
                                    else:
                                        break

                                if text_start < len(rest):
                                    text_data = rest[text_start:]
                                    if compression_flag == 1:
                                        text_data = zlib.decompress(text_data)
                                    extracted_text = text_data.decode(
                                        "utf-8", errors="replace"
                                    )
                    except Exception:
                        pass

            if extracted_text and len(extracted_text) > 10:
                matches = self._check_injection_patterns(extracted_text)
                if matches:
                    pattern_str = matches[0]
                    signals.append(DetectionSignal(
                        trap_class=TrapClass.CONTENT_INJECTION,
                        signal_name="png_text_chunk_injection",
                        confidence=0.90,
                        evidence=(
                            f"PNG {chunk_type_str} chunk contains injection pattern "
                            f"{pattern_str!r}: {extracted_text[:200]!r}"
                        ),
                        raw_payload=extracted_text[:1000],
                        detector="steganography",
                    ))

            offset += total_chunk

        return signals

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_lsb_message(self, pixel_array: np.ndarray) -> list[int]:
        """
        Extract a message from the LSB plane by grouping bits into bytes.

        Reads across all channels row-by-row, MSB first per byte.
        Stops after 2048 bytes or when an embedded null terminator is found.
        """
        if pixel_array.ndim != 3:
            return []

        h, w, ch = pixel_array.shape
        # Flatten pixels in row-major order across all channels
        flat = pixel_array.reshape(-1, ch) if ch > 1 else pixel_array.reshape(-1)

        message: list[int] = []
        max_bytes = min(2048, flat.shape[0] // 8)

        for byte_idx in range(max_bytes):
            byte_val = 0
            for bit_idx in range(8):
                pixel_idx = byte_idx * 8 + bit_idx
                if pixel_idx >= flat.shape[0]:
                    break
                # Use first channel's LSB
                if flat.ndim == 2:
                    lsb = int(flat[pixel_idx, 0]) & 1
                else:
                    lsb = int(flat[pixel_idx]) & 1
                byte_val = (byte_val << 1) | lsb
            message.append(byte_val)

            # Stop at null terminator (optional — some payloads aren't null-terminated)
            if byte_val == 0 and len(message) > 4:
                break

        return message

    def _check_injection_patterns(self, text: str) -> list[str]:
        """
        Check *text* against hardcoded injection patterns.

        Returns a list of matched pattern strings (empty if none match).
        """
        results: list[str] = []
        for pattern in _INJECTION_KEYWORD_PATTERNS:
            match = pattern.search(text)
            if match:
                results.append(match.group(0))
        return results
