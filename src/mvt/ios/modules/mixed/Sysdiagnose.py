# Mobile Verification Toolkit (MVT)
# Copyright (c) 2021-2023 The MVT Authors.
# Use of this software is governed by the MVT License 1.1 that can be found at
#   https://license.mvt.re/1.1/
import os
import glob
import re
import tarfile
import tempfile
import logging
import datetime
from typing import Iterator, Optional, Union

from ..base import IOSExtraction
from mvt.common.utils import convert_datetime_to_iso
from .CrashReporter import TIME_FORMATS, parse_timestamp

SYSDIAGNOSE_LOG_PATHS = [
    "**/*.log",
    "*.log",
    "**/*.log.*",
    "*.log.*",
]

SYSDIAGNOSE_PATH = [
    "DiagnosticLogs/sysdiagnose/sysdiagnose_*.tar.gz",
]

DIAGNOSTIC_LOGS_PATH = "DIAGNOSTIC_LOGS_PATH"

SYSDIAGNOSE_TZ_REGEX = re.compile(r"[+-]\d{4}")


def extract_device_timezone(filename):
    """Extract device timezone offset from a sysdiagnose tar filename.

    Example: sysdiagnose_2026.06.05_16-03-47+0800_iPhone-OS_iPhone_23F77.tar.gz
    Returns a datetime.timezone or None.
    """
    m = SYSDIAGNOSE_TZ_REGEX.search(os.path.basename(str(filename)))
    if not m:
        return None
    tz_str = m.group(0)
    sign = 1 if tz_str[0] == "+" else -1
    hours = int(tz_str[1:3])
    minutes = int(tz_str[3:5])
    return datetime.timezone(
        datetime.timedelta(hours=sign * hours, minutes=sign * minutes)
    )


def convert_to_utc(timestamp, device_tz=None):
    """Convert timestamp to UTC, using device timezone for naive datetimes.

    If the timestamp carries an explicit timezone offset, use it directly.
    If naive and device_tz is known, interpret as device local time.
    Raises ValueError if the timestamp is naive and no device_tz is available.
    """
    if timestamp.tzinfo is not None:
        return timestamp.astimezone(datetime.timezone.utc)
    if device_tz is not None:
        return timestamp.replace(tzinfo=device_tz).astimezone(datetime.timezone.utc)
    raise ValueError(
        "Cannot convert naive timestamp to UTC: no device timezone available"
    )


class SysdiagnoseLog(IOSExtraction):
    """Extracts and processes sysdiagnose log archives from iOS devices."""

    def __init__(
        self,
        file_path: Optional[str] = None,
        target_path: Optional[str] = None,
        results_path: Optional[str] = None,
        module_options: Optional[dict] = None,
        log: logging.Logger = logging.getLogger(__name__),
        results: Optional[list] = None,
    ) -> None:
        super().__init__(
            file_path=file_path,
            target_path=target_path,
            results_path=results_path,
            module_options=module_options,
            log=log,
            results=results,
        )
        self.device_timezone = None

    def serialize(self, record: dict) -> Union[dict, list]:
        return {
            "timestamp": record["timestamp"],
            "module": self.__class__.__name__,
            "event": record["event"],
            "data": record["data"],
        }

    def _get_files_from_patterns(
        self, target_path: str, root_paths: list
    ) -> Iterator[str]:
        for root_path in root_paths:
            for found_path in glob.glob(
                os.path.join(target_path, root_path), recursive=True
            ):
                if not os.path.exists(found_path):
                    continue
                yield found_path

    def process_sysdiagnose_logs(self, extracted_path: str) -> None:
        """Parse sysdiagnose log files, extracting timestamped lines."""
        self.log.info("Processing sysdiagnose logs at path: %s", extracted_path)
        for log_file in self._get_files_from_patterns(
            extracted_path, SYSDIAGNOSE_LOG_PATHS
        ):
            log_file_name = log_file.split("/")[-1]
            self.log.info("Found sysdiagnose log: %s", log_file_name)
            with open(log_file, "rb") as log_file_content:
                content = log_file_content.read().decode("utf-8", errors="ignore")
                try:
                    for line in content.split("\n"):
                        line = line.strip()
                        if not line:
                            continue
                        timestamp = parse_timestamp(line)
                        if not timestamp:
                            continue
                        timestamp_utc = convert_to_utc(
                            timestamp, self.device_timezone
                        )
                        self.results.append(
                            {
                                "timestamp": convert_datetime_to_iso(timestamp_utc),
                                "event": "sysdiagnose_log_activity",
                                "data": f"{log_file_name} : {line}",
                            }
                        )
                except (OSError, UnicodeDecodeError) as e:
                    self.log.error(
                        "Failed to read sysdiagnose log (%s) path: %s",
                        str(e),
                        log_file_name,
                    )

    def check_indicators(self) -> None:
        if not self.indicators:
            return

        for result in self.results:
            data = result.get("data", "")
            if not data:
                continue

            ioc_match = self.indicators.check_domain(data)
            if ioc_match:
                self.alertstore.high(
                    ioc_match.message, "", result, matched_indicator=ioc_match.ioc
                )

    def run(self) -> None:
        if self.is_backup:
            if DIAGNOSTIC_LOGS_PATH in os.environ:
                log_path = os.environ[DIAGNOSTIC_LOGS_PATH]
                if not os.path.exists(log_path):
                    self.log.warning(
                        "Diagnostic logs path does not exist: %s", log_path
                    )
                    return

                self.log.info(
                    "Processing diagnostic logs from: %s", log_path
                )

                for found_path in self._get_files_from_patterns(
                    log_path, SYSDIAGNOSE_PATH
                ):
                    self.log.info("Found sysdiagnose archive: %s", found_path)

                    # Extract device timezone from filename
                    self.device_timezone = extract_device_timezone(found_path)
                    if self.device_timezone:
                        self.log.info(
                            "Detected device timezone: %s", self.device_timezone
                        )

                    with tempfile.TemporaryDirectory() as tmp_dir:
                        self.log.info(
                            "Extracting sysdiagnose archive to: %s", tmp_dir
                        )
                        with tarfile.open(found_path, "r:gz") as tar:
                            tar.extractall(path=tmp_dir)

                        extracted_path = os.path.join(
                            tmp_dir,
                            found_path.split("/")[-1].replace(".tar.gz", ""),
                        )
                        self.process_sysdiagnose_logs(extracted_path)

        self.results = sorted(self.results, key=lambda entry: entry["timestamp"])
