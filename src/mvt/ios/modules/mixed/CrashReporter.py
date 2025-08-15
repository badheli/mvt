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
from json import loads, JSONDecodeError
from pathlib import Path
import datetime
from ..base import IOSExtraction
from mvt.common.utils import convert_datetime_to_iso
from typing import Iterator, Optional, Union,Optional, Union, Dict, List

CRASH_REPORTER_LOG_FS_PATHS = [
    # check fs 
    "private/var/mobile/Library/Logs/CrashReporter/*.ips",
    "private/var/mobile/Library/Logs/CrashReporter/*.ips.ca",
    "private/var/mobile/Library/Logs/CrashReporter/*.ips.ca.synced",
]
CRASH_REPORTER_LOG_PATHS = [
    "**/*.ips",
    "*.ips",
]
SYSDIAGNOSE_PATH = [
    "DiagnosticLogs/sysdiagnose/sysdiagnose_*.tar.gz",
]

DIAGNOSTIC_LOGS_PATH = "DIAGNOSTIC_LOGS_PATH"


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

    def _get_files_from_patterns(self, target_path: str, root_paths: list) -> Iterator[str]:
        for root_path in root_paths:
            for found_path in glob.glob(os.path.join(target_path, root_path), recursive=True):
                if not os.path.exists(found_path):
                    continue

                yield found_path


    def serialize(self, record: dict) -> Union[dict, list]:
        """Serializes crash report data into a standardized format."""
        return {
            "timestamp": record["timestamp"],
            "module": self.__class__.__name__,
            "event": record['event'],
            "data": record['data'],
        }
    

    def process_sysdiagnose_log(self, extracted_path: str , patterns: list) -> None:
            # Process each .fslisting file
            self.log.info("Processing sysdiagnose log at path: %s", extracted_path)
            for ips_file in self._get_files_from_patterns(extracted_path,patterns):
                ips_file_name = ips_file.split("/")[-1]
                self.log.info("Found CrashReporter log at path: %s", ips_file_name)
                with open(ips_file, "rb") as crash_report_log:
                    content = crash_report_log.read().decode('utf-8', errors='ignore')
                    lines = content.split("\n")
                    try:
                        log_line = loads(lines[0])
                    except Exception as e:
                        self.log.error("Failed to parse CrashReporter log (%s) path: (%s)", str(e),ips_file_name)
                    
                    try:
                        timestamp = datetime.datetime.strptime(
                            log_line["timestamp"], "%Y-%m-%d %H:%M:%S.%f %z"
                        )
                    except Exception as e:
                        self.log.error("Failed to parse timestamp (%s) path: (%s)", str(e),ips_file_name)
                        continue

                    timestamp_utc = timestamp.astimezone(datetime.timezone.utc)
                    self.results.append(
                        {
                            "timestamp": convert_datetime_to_iso(timestamp_utc),
                            "event": "crashreporter_activity",
                            "data": (
                                f"Process '{log_line.get("name", ips_file_name)}' crashed (Bug Type: {log_line.get("bug_type", "unknown")}) "
                                f"on {log_line["os_version"]} - Incident ID: {log_line.get("incident_id", "unknown")}"
                            ),
                        }
                    )


    def run(self) -> None:
                
        if self.is_backup:
            # Check for diagnostic logs from config
            # self.log.info("Checking for diagnostic logs in environment variable: %s", os.environ[DIAGNOSTIC_LOGS_PATH])
            if DIAGNOSTIC_LOGS_PATH in os.environ:
                if not os.path.exists(os.environ[DIAGNOSTIC_LOGS_PATH]):
                    self.log.warning("Diagnostic logs path does not exist: %s", os.environ[DIAGNOSTIC_LOGS_PATH])
                    return

                self.log.info("Processing diagnostic log file from config: %s", os.environ[DIAGNOSTIC_LOGS_PATH])

                # 处理 os.environ[DIAGNOSTIC_LOGS_PATH] 下的 ips
                self.process_sysdiagnose_log(os.environ[DIAGNOSTIC_LOGS_PATH], CRASH_REPORTER_LOG_PATHS) 
                # 处理 sysdiagnose 日志中的 ips
                for found_path in self._get_files_from_patterns(os.environ[DIAGNOSTIC_LOGS_PATH], SYSDIAGNOSE_PATH):
                    # DiagnosticLogs/sysdiagnose/sysdiagnose_2025.05.13_14-38-43+0800_iPhone-OS_iPhone_22E252.tar.gz
                    self.log.info("Found sysdiagnose log at path: %s", found_path)
                    # Extract the tar file to a temporary directory
                    with tempfile.TemporaryDirectory() as tmp_dir:
                        self.log.info("Extracting sysdiagnose log to: %s", tmp_dir)
                        with tarfile.open(found_path, "r:gz") as tar:
                            tar.extractall(path=tmp_dir)
                        # Find the extracted sysdiagnose files
                        extracted_path = os.path.join(tmp_dir, found_path.split("/")[-1].replace(".tar.gz", ""))
                        self.process_sysdiagnose_log(extracted_path, CRASH_REPORTER_LOG_PATHS)            

        else:
            self.process_sysdiagnose_log(self.target_path, CRASH_REPORTER_LOG_FS_PATHS)
        

        self.results = sorted(self.results, key=lambda entry: entry["timestamp"])


