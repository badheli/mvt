# Mobile Verification Toolkit (MVT)
# Copyright (c) 2021-2023 The MVT Authors.
# Use of this software is governed by the MVT License 1.1 that can be found at
#   https://license.mvt.re/1.1/

import logging
from json import loads, JSONDecodeError
from typing import Optional, Union, Dict, List
from pathlib import Path
import datetime
import os 
from ..base import IOSExtraction
from mvt.common.utils import convert_datetime_to_iso


CRASH_REPORTER_LOG_PATHS = [
    "private/var/mobile/Library/Logs/CrashReporter/*.ips",
    "private/var/mobile/Library/Logs/CrashReporter/*.ips.ca",
    "private/var/mobile/Library/Logs/CrashReporter/*.ips.ca.synced",
    "**/DiagnosticLogs/sysdiagnose/*/crashes_and_spins/*.ips",
    "**/DiagnosticLogs/sysdiagnose/*/crashes_and_spins/*.ips",
    "*.ips",
]


class CrashReporterLog(IOSExtraction):
    """Extracts and processes CrashReporter log files from iOS devices."""


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


    def serialize(self, record: dict) -> Union[dict, list]:
        """Serializes crash report data into a standardized format."""
        return {
            "timestamp": record["isodate"],
            "module": self.__class__.__name__,
            "event": "crashreporter_activity",
            "data": (
                f"Process '{record['name']}' crashed (Bug Type: {record['bug_type']}) "
                f"on {record['os_version']} - Incident ID: {record['incident_id']}"
            ),
        }


    def run(self) -> None:
        for found_path in self._get_fs_files_from_patterns(CRASH_REPORTER_LOG_PATHS):
            self.log.info("Found CrashReporter log at path: %s", found_path)
            with open(found_path, "rb") as crash_report_log:
                content = crash_report_log.read().decode('utf-8', errors='ignore')
                lines = content.split("\n")
                try:
                    log_line = loads(lines[0])
                except Exception as e:
                    self.log.error("Failed to parse CrashReporter log (%s) path: (%s)", str(e),found_path)
                timestamp = datetime.datetime.strptime(
                    log_line["timestamp"], "%Y-%m-%d %H:%M:%S.%f %z"
                )
                timestamp_utc = timestamp.astimezone(datetime.timezone.utc)
                self.results.append(
                    {
                        "isodate": convert_datetime_to_iso(timestamp_utc),
                        "os_version": log_line["os_version"],
                        "name": log_line.get("name", os.path.basename(found_path)),
                        "bug_type": log_line.get("bug_type", "unknown"),
                        "incident_id": log_line.get("incident_id", "unknown"),
                        "path": os.path.basename(found_path)
                    }
                )

        self.results = sorted(self.results, key=lambda entry: entry["isodate"])