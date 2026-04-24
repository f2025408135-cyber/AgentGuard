"""
Layer 5: DocumentScanner.

Scans PDF, Excel (XLSX), and ICS (iCalendar) documents for embedded
injection payloads.  Detects file type from magic bytes, warns on
extension mismatches, and routes to format-specific deep scanners.

Reference: Franklin et al. (2026). AI Agent Traps. SSRN 6372438.
"""

import io
import logging
import re
import zipfile
from typing import Optional

from pypdf import PdfReader
from openpyxl import load_workbook
from icalendar import Calendar

from agentguard.config import AgentGuardConfig
from agentguard.models import DetectionSignal, TrapClass

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Magic-byte signatures (first 8 bytes)
# ---------------------------------------------------------------------------
_PDF_MAGIC = b"%PDF-"
_ZIP_MAGIC = b"PK\x03\x04"
_ICS_MAGIC = b"BEGIN:VCALENDAR"

# ---------------------------------------------------------------------------
# Regex helpers compiled once
# ---------------------------------------------------------------------------
_RE_WHITE_TEXT_RG = re.compile(rb"1\s+1\s+1\s+RG")
_RE_WHITE_TEXT_RG_BEFORE_TJ = re.compile(
    rb"(1\s+1\s+1\s+RG\s+.*?(?:Tj|TJ|'))",
    re.DOTALL,
)
_RE_WHITE_TEXT_RG_BEFORE_BT = re.compile(
    rb"(1\s+1\s+1\s+RG\s+.*?BT)",
    re.DOTALL,
)

# Dangerous formula patterns in Excel
_DANGEROUS_FORMULA_PATTERNS: list[tuple[str, float]] = [
    (r"IMPORTDATA\s*\(", 0.90),
    (r"WEBSERVICE\s*\(", 0.90),
    (r"HYPERLINK\s*\(", 0.70),
    (r"=cmd\s*\|", 0.95),
    (r"'/C\s*'", 0.95),
    (r"=MSEXCEL\s*\|", 0.95),
]

# HTML-in-ICS detection
_RE_HTML_IN_TEXT = re.compile(
    r"<\s*(?:a|div|iframe|img|script|body|html|form|input|link|meta|style|object|embed)\b",
    re.IGNORECASE,
)


class DocumentScanner:
    """
    Scans document files (PDF, Excel, ICS) for embedded injection payloads.

    The scanner first determines the actual file type via magic-byte analysis
    of the first 8 bytes.  If the file extension disagrees with the detected
    type, a warning signal is emitted.  The file is then routed to the
    appropriate format-specific deep scanner.

    Each sub-scanner extracts text and metadata, and runs the injection
    keyword patterns from the :class:`AgentGuardConfig` against all extracted
    content.
    """

    def __init__(self, config: AgentGuardConfig) -> None:
        self._config = config
        # Pre-compile injection keyword patterns
        self._injection_patterns: list[re.Pattern[str]] = [
            re.compile(p, re.IGNORECASE) for p in config.injection_keyword_patterns
        ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, file_bytes: bytes, filename: str = "") -> list[DetectionSignal]:
        """
        Scan a document file for injection payloads.

        Parameters
        ----------
        file_bytes:
            Raw bytes of the document.
        filename:
            Original filename (used to determine expected file type).

        Returns
        -------
        list[DetectionSignal]
        """
        signals: list[DetectionSignal] = []

        if not file_bytes:
            return signals

        header = file_bytes[:8]
        detected_type: str | None = None

        if header.startswith(_PDF_MAGIC):
            detected_type = "pdf"
        elif header.startswith(_ZIP_MAGIC):
            detected_type = "zip"  # XLSX is a ZIP container
        elif header.startswith(_ICS_MAGIC):
            detected_type = "ics"

        # --- Extension-mismatch warning -----------------------------------
        if detected_type and filename:
            ext = _get_extension(filename).lower()
            expected_map = {
                "pdf": {"pdf"},
                "zip": {"xlsx", "xlsm", "xlsb", "zip"},
                "ics": {"ics", "ical", "ifb", "icalendar"},
            }
            expected_exts = expected_map.get(detected_type, set())
            if ext and ext not in expected_exts:
                signals.append(DetectionSignal(
                    trap_class=TrapClass.CONTENT_INJECTION,
                    signal_name="document_extension_mismatch",
                    confidence=0.45,
                    evidence=(
                        f"File extension '{ext}' does not match detected type "
                        f"'{detected_type}' for file '{filename}'"
                    ),
                    detector="document_scanner",
                ))

        # --- Route to format scanner --------------------------------------
        try:
            if detected_type == "pdf" and self._config.scan_pdf:
                signals.extend(self._scan_pdf(file_bytes))
            elif detected_type == "zip" and self._config.scan_excel:
                signals.extend(self._scan_excel(file_bytes))
            elif detected_type == "ics" and self._config.scan_ics:
                signals.extend(self._scan_ics(file_bytes))
            elif detected_type is None:
                logger.debug(
                    "Unknown document type for %s — no scanner available",
                    filename or "<unknown>",
                )
        except Exception as exc:
            logger.warning(
                "Error scanning document %s: %s", filename or "<unknown>", exc,
            )
            signals.append(DetectionSignal(
                trap_class=TrapClass.CONTENT_INJECTION,
                signal_name="document_scan_error",
                confidence=0.30,
                evidence=f"Document scan raised an exception: {exc}",
                detector="document_scanner",
            ))

        return signals

    def detect_from_path(self, filepath: str) -> list[DetectionSignal]:
        """
        Scan a document file from disk.

        Parameters
        ----------
        filepath:
            Path to the document file.

        Returns
        -------
        list[DetectionSignal]
        """
        try:
            with open(filepath, "rb") as fh:
                file_bytes = fh.read()
        except OSError as exc:
            logger.warning("Could not read file %s: %s", filepath, exc)
            return [
                DetectionSignal(
                    trap_class=TrapClass.CONTENT_INJECTION,
                    signal_name="document_read_error",
                    confidence=0.30,
                    evidence=f"Could not read file '{filepath}': {exc}",
                    detector="document_scanner",
                )
            ]
        return self.detect(file_bytes, filename=filepath)

    # ------------------------------------------------------------------
    # PDF scanner
    # ------------------------------------------------------------------

    def _scan_pdf(self, file_bytes: bytes) -> list[DetectionSignal]:
        """Deep-scan a PDF for injection payloads."""
        signals: list[DetectionSignal] = []

        try:
            reader = PdfReader(io.BytesIO(file_bytes))
        except Exception as exc:
            logger.warning("Failed to parse PDF: %s", exc)
            signals.append(DetectionSignal(
                trap_class=TrapClass.CONTENT_INJECTION,
                signal_name="pdf_parse_error",
                confidence=0.35,
                evidence=f"PDF parsing failed: {exc}",
                detector="document_scanner",
            ))
            return signals

        num_pages = len(reader.pages)
        logger.debug("PDF has %d page(s)", num_pages)

        # SECURITY FIX: AG-DoS-002 (Adversarial Review 2025)
        # Limit pages scanned to prevent resource exhaustion from huge PDFs
        if num_pages > self._config.max_pdf_pages:
            logger.warning(
                "PDF has %d pages (max %d), scanning only first %d",
                num_pages, self._config.max_pdf_pages, self._config.max_pdf_pages,
            )

        pages_to_scan = reader.pages[:self._config.max_pdf_pages]

        # --- 1. Extract text from ALL pages (including hidden layers) ------
        all_text_parts: list[str] = []
        for page_num, page in enumerate(pages_to_scan):
            try:
                page_text = page.extract_text() or ""
                all_text_parts.append(page_text)
            except Exception as exc:
                logger.warning("Error extracting text from PDF page %d: %s", page_num, exc)

        full_text = "\n".join(all_text_parts)

        # --- 2. Check for white-text patterns in content streams -----------
        #    Look for "1 1 1 RG" (set graphics state to white) followed by
        #    text operators (Tj, TJ, ').  This is a classic PDF injection
        #    technique where text is rendered in white so it's invisible.
        try:
            raw_content = file_bytes
            # Check both rg and RG (fill and stroke color)
            white_fill_re = re.compile(rb"1\s+1\s+1\s+rg", re.IGNORECASE)
            white_stroke_re = re.compile(rb"1\s+1\s+1\s+RG", re.IGNORECASE)

            white_fill_matches = list(white_fill_re.finditer(raw_content))
            white_stroke_matches = list(white_stroke_re.finditer(raw_content))

            if white_fill_matches or white_stroke_matches:
                total_white = len(white_fill_matches) + len(white_stroke_matches)
                # Check if white text operators are followed by text operations
                # within a reasonable window
                text_near_white = False
                for match in white_fill_matches + white_stroke_matches:
                    after = raw_content[match.end():match.end() + 200]
                    if re.search(rb"(?:Tj|TJ|')\s", after):
                        text_near_white = True
                        break

                if text_near_white:
                    signals.append(DetectionSignal(
                        trap_class=TrapClass.CONTENT_INJECTION,
                        signal_name="pdf_white_text_detected",
                        confidence=0.75,
                        evidence=(
                            f"PDF contains {total_white} instances of white-text "
                            f"color setting (1 1 1 rg/RG) near text operators — "
                            f"potential invisible injection layer"
                        ),
                        detector="document_scanner",
                    ))
        except Exception as exc:
            logger.debug("Error checking PDF white-text patterns: %s", exc)

        # --- 3. Check for JavaScript actions (/JS dictionary keys) ----------
        try:
            # Check the trailer and page-level action dictionaries
            js_found = False
            js_sources: list[str] = []

            # Check document-level actions
            for key in ("/OpenAction", "/JS", "/AA", "/Actions"):
                raw_str = raw_content if 'raw_content' in dir() else file_bytes
                # Search for /JS entries in the raw PDF bytes
                js_pattern = re.compile(
                    rb"/JS\s*(?:\([^)]*\)|<[^>]*>|/[^\s/\[\]<>]+)",
                    re.DOTALL,
                )
                for js_match in js_pattern.finditer(file_bytes):
                    js_found = True
                    js_val = js_match.group(0).decode("latin-1", errors="replace")
                    js_sources.append(js_val[:200])

            if js_found:
                signals.append(DetectionSignal(
                    trap_class=TrapClass.BEHAVIORAL_CONTROL,
                    signal_name="pdf_javascript_detected",
                    confidence=0.80,
                    evidence=(
                        f"PDF contains JavaScript actions: "
                        f"{js_sources[:3]}"
                    ),
                    raw_payload="\n".join(js_sources[:5])[:2000],
                    detector="document_scanner",
                ))
        except Exception as exc:
            logger.debug("Error checking PDF JavaScript: %s", exc)

        # --- 4. Check XMP metadata and Document Information Dictionary -----
        try:
            metadata = reader.metadata
            if metadata:
                meta_fields = {
                    "/Title": metadata.title,
                    "/Author": metadata.author,
                    "/Subject": metadata.subject,
                    "/Keywords": metadata.keywords,
                    "/Creator": metadata.creator,
                    "/Producer": metadata.producer,
                }
                for field_name, field_value in meta_fields.items():
                    if field_value and isinstance(field_value, str):
                        matches = self._check_injection_patterns(field_value)
                        if matches:
                            pattern_str, _ = matches[0]
                            signals.append(DetectionSignal(
                                trap_class=TrapClass.CONTENT_INJECTION,
                                signal_name="pdf_metadata_injection",
                                confidence=0.80,
                                evidence=(
                                    f"Injection pattern in PDF metadata field "
                                    f"{field_name}: {pattern_str!r} in "
                                    f"{field_value[:200]!r}"
                                ),
                                raw_payload=field_value[:500],
                                detector="document_scanner",
                            ))
        except Exception as exc:
            logger.debug("Error checking PDF metadata: %s", exc)

        # --- 5. Check for OpenAction entries --------------------------------
        try:
            open_action = raw_content if 'raw_content' in dir() else file_bytes
            oa_pattern = re.compile(rb"/OpenAction\b")
            if oa_pattern.search(file_bytes):
                signals.append(DetectionSignal(
                    trap_class=TrapClass.BEHAVIORAL_CONTROL,
                    signal_name="pdf_open_action",
                    confidence=0.60,
                    evidence=(
                        "PDF contains /OpenAction dictionary entry — may "
                        "execute code or trigger actions on open"
                    ),
                    detector="document_scanner",
                ))
        except Exception as exc:
            logger.debug("Error checking PDF OpenAction: %s", exc)

        # --- 6. Scan ALL extracted text for injection patterns ---------------
        if full_text.strip():
            matches = self._check_injection_patterns(full_text)
            if matches:
                pattern_str, _ = matches[0]
                signals.append(DetectionSignal(
                    trap_class=TrapClass.CONTENT_INJECTION,
                    signal_name="pdf_text_injection",
                    confidence=0.85,
                    evidence=(
                        f"Injection pattern in PDF extracted text: "
                        f"{pattern_str!r} found in {full_text[:200]!r}"
                    ),
                    raw_payload=full_text[:2000],
                    detector="document_scanner",
                ))

        # --- 7. Check AcroForm fields with default values -------------------
        try:
            # Access the root document catalog
            if "/AcroForm" in file_bytes:
                acroform_re = re.compile(
                    rb"/V\s*(?:\([^)]*\)|<[^>]*>|/[^\s/\[\]<>]+)",
                    re.DOTALL,
                )
                # Find AcroForm region and check field default values
                acroform_pos = file_bytes.find(b"/AcroForm")
                if acroform_pos >= 0:
                    acroform_region = file_bytes[acroform_pos:acroform_pos + 10000]
                    for val_match in acroform_re.finditer(acroform_region):
                        val_text = val_match.group(0).decode("latin-1", errors="replace")
                        # Extract the string value
                        if val_text.startswith("/V"):
                            inner = val_text[2:].strip()
                            if len(inner) > 5:
                                matches = self._check_injection_patterns(inner)
                                if matches:
                                    pattern_str, _ = matches[0]
                                    signals.append(DetectionSignal(
                                        trap_class=TrapClass.CONTENT_INJECTION,
                                        signal_name="pdf_acroform_injection",
                                        confidence=0.75,
                                        evidence=(
                                            f"Injection pattern in PDF AcroForm "
                                            f"field default value: {pattern_str!r} "
                                            f"in {inner[:200]!r}"
                                        ),
                                        raw_payload=inner[:500],
                                        detector="document_scanner",
                                    ))
        except Exception as exc:
            logger.debug("Error checking PDF AcroForm fields: %s", exc)

        return signals

    # ------------------------------------------------------------------
    # Excel scanner
    # ------------------------------------------------------------------

    def _scan_excel(self, file_bytes: bytes) -> list[DetectionSignal]:
        """Deep-scan an XLSX workbook for injection payloads."""
        signals: list[DetectionSignal] = []

        try:
            wb = load_workbook(io.BytesIO(file_bytes), data_only=False)
        except Exception as exc:
            logger.warning("Failed to parse Excel workbook: %s", exc)
            signals.append(DetectionSignal(
                trap_class=TrapClass.CONTENT_INJECTION,
                signal_name="excel_parse_error",
                confidence=0.35,
                evidence=f"Excel parsing failed: {exc}",
                detector="document_scanner",
            ))
            return signals

        # --- 1. Check for VBA macro (xl/vbaProject.bin in ZIP) ------------
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
                vba_path = "xl/vbaProject.bin"
                if vba_path in zf.namelist():
                    signals.append(DetectionSignal(
                        trap_class=TrapClass.BEHAVIORAL_CONTROL,
                        signal_name="excel_vba_macro_detected",
                        confidence=0.85,
                        evidence=(
                            "XLSX contains VBA macro project (xl/vbaProject.bin) — "
                            "macros can execute arbitrary code"
                        ),
                        detector="document_scanner",
                    ))
        except Exception as exc:
            logger.debug("Error checking for VBA project in XLSX: %s", exc)

        # --- 2. Iterate ALL sheets including hidden ones -------------------
        # SECURITY FIX: AG-DoS-002 (Adversarial Review 2025)
        # Limit sheets scanned to prevent resource exhaustion
        sheet_names = wb.sheetnames[:self._config.max_excel_sheets]
        if len(wb.sheetnames) > self._config.max_excel_sheets:
            logger.warning(
                "Excel has %d sheets (max %d), scanning only first %d",
                len(wb.sheetnames), self._config.max_excel_sheets,
                self._config.max_excel_sheets,
            )
        for sheet_name in sheet_names:
            ws = wb[sheet_name]
            is_hidden = ws.sheet_state == "hidden"
            is_very_hidden = ws.sheet_state == "veryHidden"

            if is_hidden or is_very_hidden:
                logger.debug("Scanning hidden sheet: %s (state=%s)", sheet_name, ws.sheet_state)

            # --- 2a. Check cells in hidden sheets for injection patterns ---
            if is_hidden or is_very_hidden:
                for row in ws.iter_rows():
                    for cell in row:
                        if cell.value is not None and isinstance(cell.value, str):
                            cell_text = str(cell.value)
                            if len(cell_text) > 5:
                                matches = self._check_injection_patterns(cell_text)
                                if matches:
                                    pattern_str, _ = matches[0]
                                    signals.append(DetectionSignal(
                                        trap_class=TrapClass.CONTENT_INJECTION,
                                        signal_name="excel_hidden_sheet_injection",
                                        confidence=0.80,
                                        evidence=(
                                            f"Injection pattern in hidden sheet "
                                            f"'{sheet_name}' cell {cell.coordinate}: "
                                            f"{pattern_str!r} in {cell_text[:200]!r}"
                                        ),
                                        raw_payload=cell_text[:500],
                                        detector="document_scanner",
                                    ))

            # --- 2b. Scan ALL formula cells for dangerous formulas ---------
            for row in ws.iter_rows():
                for cell in row:
                    # Check cell comments
                    if cell.comment and cell.comment.text:
                        comment_text = cell.comment.text
                        if len(comment_text) > 5:
                            matches = self._check_injection_patterns(comment_text)
                            if matches:
                                pattern_str, _ = matches[0]
                                signals.append(DetectionSignal(
                                    trap_class=TrapClass.CONTENT_INJECTION,
                                    signal_name="excel_cell_comment_injection",
                                    confidence=0.70,
                                    evidence=(
                                        f"Injection pattern in cell comment at "
                                        f"{cell.coordinate} (sheet '{sheet_name}'): "
                                        f"{pattern_str!r} in {comment_text[:200]!r}"
                                    ),
                                    raw_payload=comment_text[:500],
                                    detector="document_scanner",
                                ))

        # --- 3. Re-scan with data_only=False to get formulas ---------------
        try:
            wb_formulas = load_workbook(io.BytesIO(file_bytes), data_only=False)
            for sheet_name in wb_formulas.sheetnames:
                ws = wb_formulas[sheet_name]
                for row in ws.iter_rows():
                    for cell in row:
                        if cell.value and isinstance(cell.value, str) and cell.value.startswith("="):
                            formula = cell.value
                            for pat, conf in _DANGEROUS_FORMULA_PATTERNS:
                                if re.search(pat, formula, re.IGNORECASE):
                                    signals.append(DetectionSignal(
                                        trap_class=TrapClass.BEHAVIORAL_CONTROL,
                                        signal_name="excel_dangerous_formula",
                                        confidence=conf,
                                        evidence=(
                                            f"Dangerous formula in cell "
                                            f"{cell.coordinate} (sheet '{sheet_name}'): "
                                            f"{formula[:200]!r}"
                                        ),
                                        raw_payload=formula[:500],
                                        detector="document_scanner",
                                    ))
                            # Also check formula for injection patterns
                            matches = self._check_injection_patterns(formula)
                            if matches:
                                pattern_str, _ = matches[0]
                                signals.append(DetectionSignal(
                                    trap_class=TrapClass.CONTENT_INJECTION,
                                    signal_name="excel_formula_injection",
                                    confidence=0.75,
                                    evidence=(
                                        f"Injection pattern in formula at "
                                        f"{cell.coordinate} (sheet '{sheet_name}'): "
                                        f"{pattern_str!r} in {formula[:200]!r}"
                                    ),
                                    raw_payload=formula[:500],
                                    detector="document_scanner",
                                ))
        except Exception as exc:
            logger.debug("Error scanning Excel formulas: %s", exc)

        # --- 4. Check defined names for suspicious formulas ----------------
        try:
            for dn in wb.defined_names.definedName:
                if dn.attr_text:
                    dn_text = str(dn.attr_text)
                    # Check for dangerous formula patterns
                    for pat, conf in _DANGEROUS_FORMULA_PATTERNS:
                        if re.search(pat, dn_text, re.IGNORECASE):
                            signals.append(DetectionSignal(
                                trap_class=TrapClass.BEHAVIORAL_CONTROL,
                                signal_name="excel_defined_name_formula",
                                confidence=conf,
                                evidence=(
                                    f"Suspicious defined name '{dn.name}' contains "
                                    f"dangerous formula: {dn_text[:200]!r}"
                                ),
                                raw_payload=dn_text[:500],
                                detector="document_scanner",
                            ))
                    # Check for injection patterns
                    matches = self._check_injection_patterns(dn_text)
                    if matches:
                        pattern_str, _ = matches[0]
                        signals.append(DetectionSignal(
                            trap_class=TrapClass.CONTENT_INJECTION,
                            signal_name="excel_defined_name_injection",
                            confidence=0.70,
                            evidence=(
                                f"Injection pattern in defined name '{dn.name}': "
                                f"{pattern_str!r} in {dn_text[:200]!r}"
                            ),
                            raw_payload=dn_text[:500],
                            detector="document_scanner",
                        ))
        except Exception as exc:
            logger.debug("Error checking defined names: %s", exc)

        return signals

    # ------------------------------------------------------------------
    # ICS scanner
    # ------------------------------------------------------------------

    def _scan_ics(self, file_bytes: bytes) -> list[DetectionSignal]:
        """Deep-scan an ICS (iCalendar) file for injection payloads."""
        signals: list[DetectionSignal] = []

        try:
            cal = Calendar.from_ical(file_bytes)
        except Exception as exc:
            logger.warning("Failed to parse ICS: %s", exc)
            signals.append(DetectionSignal(
                trap_class=TrapClass.CONTENT_INJECTION,
                signal_name="ics_parse_error",
                confidence=0.35,
                evidence=f"ICS parsing failed: {exc}",
                detector="document_scanner",
            ))
            return signals

        # Fields to scan for injection patterns
        _TEXT_FIELDS = ("SUMMARY", "DESCRIPTION", "LOCATION", "COMMENT")

        def _walk_component(component, event_count: list[int]) -> None:
            """Recursively walk iCalendar components."""
            # SECURITY FIX: AG-DoS-002 (Adversarial Review 2025)
            # Track event count to prevent resource exhaustion from huge calendars
            if component.name == "VEVENT":
                event_count[0] += 1
                if event_count[0] > self._config.max_ics_events:
                    logger.warning(
                        "ICS has more than %d events, stopping scan",
                        self._config.max_ics_events,
                    )
                    return

            for prop_name, prop_val in component.property_items():
                prop_name_upper = prop_name.upper()

                # --- Check standard text fields for injection patterns ------
                if prop_name_upper in _TEXT_FIELDS:
                    if isinstance(prop_val, str) and len(prop_val) > 5:
                        matches = self._check_injection_patterns(prop_val)
                        if matches:
                            pattern_str, _ = matches[0]
                            signals.append(DetectionSignal(
                                trap_class=TrapClass.CONTENT_INJECTION,
                                signal_name="ics_field_injection",
                                confidence=0.85,
                                evidence=(
                                    f"Injection pattern in ICS field "
                                    f"{prop_name}: {pattern_str!r} in "
                                    f"{prop_val[:200]!r}"
                                ),
                                raw_payload=prop_val[:500],
                                detector="document_scanner",
                            ))

                    # --- Check for embedded HTML in DESCRIPTION -------------
                    if prop_name_upper == "DESCRIPTION" and isinstance(prop_val, str):
                        if _RE_HTML_IN_TEXT.search(prop_val):
                            signals.append(DetectionSignal(
                                trap_class=TrapClass.CONTENT_INJECTION,
                                signal_name="ics_html_in_description",
                                confidence=0.70,
                                evidence=(
                                    f"HTML detected in ICS DESCRIPTION field: "
                                    f"{prop_val[:200]!r}"
                                ),
                                raw_payload=prop_val[:1000],
                                detector="document_scanner",
                            ))

                # --- Check URL and ATTENDEE/ORGANIZER fields ---------------
                if prop_name_upper in ("URL", "ORGANIZER", "ATTENDEE"):
                    val_str = str(prop_val) if not isinstance(prop_val, str) else prop_val
                    matches = self._check_injection_patterns(val_str)
                    if matches:
                        pattern_str, _ = matches[0]
                        signals.append(DetectionSignal(
                            trap_class=TrapClass.CONTENT_INJECTION,
                            signal_name="ics_url_field_injection",
                            confidence=0.75,
                            evidence=(
                                f"Injection pattern in ICS {prop_name} field: "
                                f"{pattern_str!r} in {val_str[:200]!r}"
                            ),
                            raw_payload=val_str[:500],
                            detector="document_scanner",
                        ))

                # --- Check X-* properties ----------------------------------
                if prop_name_upper.startswith("X-"):
                    val_str = str(prop_val) if not isinstance(prop_val, str) else prop_val
                    if len(val_str) > 10:
                        matches = self._check_injection_patterns(val_str)
                        if matches:
                            pattern_str, _ = matches[0]
                            signals.append(DetectionSignal(
                                trap_class=TrapClass.CONTENT_INJECTION,
                                signal_name="ics_custom_property_injection",
                                confidence=0.65,
                                evidence=(
                                    f"Injection pattern in ICS custom property "
                                    f"{prop_name}: {pattern_str!r} in "
                                    f"{val_str[:200]!r}"
                                ),
                                raw_payload=val_str[:500],
                                detector="document_scanner",
                            ))

                # --- Check ATTACH properties for suspicious URLs ------------
                if prop_name_upper == "ATTACH":
                    val_str = str(prop_val) if not isinstance(prop_val, str) else prop_val
                    if isinstance(prop_val, dict):
                        # vCal ATTACH can be a dict with URI/FMT params
                        uri = prop_val.get("URI", "") or ""
                        if uri and isinstance(uri, str) and len(uri) > 10:
                            matches = self._check_injection_patterns(uri)
                            if matches:
                                pattern_str, _ = matches[0]
                                signals.append(DetectionSignal(
                                    trap_class=TrapClass.CONTENT_INJECTION,
                                    signal_name="ics_attach_url_injection",
                                    confidence=0.75,
                                    evidence=(
                                        f"Suspicious ATTACH URI in ICS: "
                                        f"{pattern_str!r} in {uri[:200]!r}"
                                    ),
                                    raw_payload=uri[:500],
                                    detector="document_scanner",
                                ))

            # Recurse into sub-components
            for sub in component.subcomponents:
                _walk_component(sub, event_count)

        _walk_component(cal, [0])
        return signals

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _check_injection_patterns(self, text: str) -> list[tuple[str, float]]:
        """
        Check *text* against all compiled injection patterns from config.

        Returns a list of ``(matched_pattern_string, confidence)`` tuples.
        """
        results: list[tuple[str, float]] = []
        for pattern in self._injection_patterns:
            match = pattern.search(text)
            if match:
                matched_str = match.group(0)
                results.append((matched_str, 0.85))
        return results


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _get_extension(filename: str) -> str:
    """Return the file extension without the leading dot, lowercased."""
    dot = filename.rfind(".")
    if dot >= 0:
        return filename[dot + 1:]
    return ""
