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
from typing import Iterator, Optional, Union

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
SYSDIAGNOSE_LOG_PATHS = [
    "**/*.log",
    "*.log",
    "**/*.log.*",
    "*.log.*",
]

# transparency.log  / shutdown.log RunningBoard_state.log


SYSDIAGNOSE_PATH = [
    "DiagnosticLogs/sysdiagnose/sysdiagnose_*.tar.gz",
]

DIAGNOSTIC_LOGS_PATH = "DIAGNOSTIC_LOGS_PATH"



TIME_FORMATS = [
    "%a %b %d %H:%M:%S %Y",          # Sun Oct 19 13:19:37 2025
    "%m/%d/%y %H:%M:%S.%f",          # 09/13/25 13:43:37.426607
    "%m/%d/%y %H:%M:%S",             # 09/13/25 13:43:37
    "%Y-%m-%d %H:%M:%S.%fZ",         # 2025-08-28 04:36:25.285567Z
    "%Y-%m-%d %H:%M:%SZ",            # 2025-08-28 04:36:25Z
    "%Y-%m-%d %H:%M:%S.%f%z",        # 2023-12-30 00:37:44+0800
    "%Y-%m-%d %H:%M:%S.%f %z",       # 2026-05-08 10:57:44.00 +0300
    "%Y-%m-%d %H:%M:%S%z",           # 2025-09-08 21:58:56+0800
    "%Y-%m-%d_%H:%M:%S",             # 2025-11-12_16:13:41
    "%Y-%m-%d %H:%M:%S %z",          # 2022-01-13 14:04:21 +0000
]

SYSLOG_TIME_REGEX = re.compile(
    r"""
    (
        # 1. Sun Oct 19 13:19:37 2025
        [A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}
        |
        # 2. 09/13/25 13:43:37.426607 
        \d{2}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?
        |
        # 3. 2025-08-28 04:36:25.285567Z
        \d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?Z
        |
        # 4. 2023-12-30 00:37:44+0800  
        \d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\+\d{4}
        |
        # 5. 2025-11-12_16:13:41
        \d{4}-\d{2}-\d{2}_\d{2}:\d{2}:\d{2}
        |
        # 6. 2026-05-08 10:57:44.00 +0300
        \d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+\+\d{4}
    )
    """,
    re.VERBOSE,
)

def parse_timestamp(line: str):
    m = SYSLOG_TIME_REGEX.search(line)
    if not m:
        return None

    time_str = m.group(0)

    for fmt in TIME_FORMATS:
        try:
            return datetime.datetime.strptime(time_str, fmt)
        except Exception:
            continue

    return None

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
    

    def process_sysdiagnose_ips(self, extracted_path: str, patterns: list) -> None:
        """Parse .ips (iOS crash report) files, extracting key fields."""
        self.log.info("Processing IPS crash reports at path: %s", extracted_path)
        for ips_file in self._get_files_from_patterns(extracted_path, patterns):
            ips_file_name = ips_file.split("/")[-1]
            self.log.info("Found IPS crash report: %s", ips_file_name)

            # Read and parse first line as JSON
            with open(ips_file, "rb") as crash_report_log:
                content = crash_report_log.read().decode("utf-8", errors="ignore")
                lines = content.split("\n")

            log_line = None
            try:
                log_line = loads(lines[0])
            except (JSONDecodeError, IndexError) as e:
                self.log.error("Failed to parse IPS JSON (%s) path: %s", str(e), ips_file_name)
                continue

            if not isinstance(log_line, dict):
                self.log.error("IPS first line is not a JSON object: %s", ips_file_name)
                continue

            # Parse timestamp
            timestamp = None
            for ts_field in ("timestamp", "captureTime", "date"):
                if ts_field in log_line:
                    for fmt in TIME_FORMATS:
                        try:
                            timestamp = datetime.datetime.strptime(log_line[ts_field], fmt)
                            break
                        except (ValueError, TypeError):
                            continue
                if timestamp:
                    break

            if timestamp is None:
                self.log.error(
                    "Failed to parse timestamp in IPS: %s (value: %s)",
                    ips_file_name,
                    log_line.get("timestamp", log_line.get("captureTime", "missing")),
                )
                continue

            # Classify: system process / third-party / no bundleID
            bundle_id = log_line.get("bundleID", "")
            is_system = False
            if bundle_id:
                is_system = bundle_id.startswith("com.apple.")

            exception_info = log_line.get("exception", {})
            termination_info = log_line.get("termination", {})

            timestamp_utc = timestamp.astimezone(datetime.timezone.utc)
            record = {
                "timestamp": convert_datetime_to_iso(timestamp_utc),
                "event": (
                    "system_crashreporter_activity"
                    if is_system
                    else "crashreporter_activity"
                ),
                "data": (
                    f"Process '{log_line.get('name', ips_file_name)}' crashed "
                    f"(Bug Type: {log_line.get('bug_type', 'unknown')}, "
                    f"BundleID: {bundle_id or 'N/A'}) "
                    f"on {log_line.get('os_version', 'unknown')} "
                    f"- Incident ID: {log_line.get('incident_id', 'unknown')}"
                ),
                "BundleID": bundle_id,
                "ProcessName": log_line.get("name", ips_file_name),
                "BugType": str(log_line.get("bug_type", "")),
                "OSVersion": log_line.get("os_version", ""),
                "IncidentID": log_line.get("incident_id", ""),
                "IPSFile": ips_file_name,
            }

            # Exception details
            if exception_info:
                exc_type = exception_info.get("type", "")
                exc_signal = exception_info.get("signal", "")
                if exc_type or exc_signal:
                    record["ExceptionType"] = exc_type
                    record["ExceptionSignal"] = exc_signal
                    record["data"] += (
                        f", Exception: {exc_type}"
                        + (f"/{exc_signal}" if exc_signal else "")
                    )

            # Termination reason
            if termination_info:
                term_reason = termination_info.get("reason", "")
                if term_reason:
                    record["TerminationReason"] = term_reason

            # Triggered by
            triggered_by = log_line.get("triggered_by", "")
            if triggered_by:
                record["TriggeredBy"] = triggered_by

            self.results.append(record)

    def process_sysdiagnose_log(self, extracted_path: str, patterns: list) -> None:
        """Parse sysdiagnose log files, extracting timestamped lines."""
        self.log.info("Processing sysdiagnose log at path: %s", extracted_path)
        for log_file in self._get_files_from_patterns(extracted_path, patterns):
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
                        timestamp_utc = timestamp.astimezone(datetime.timezone.utc)
                        self.results.append(
                            {
                                "timestamp": convert_datetime_to_iso(timestamp_utc),
                                "event": "sysdiagnose_log_activity",
                                "data": f"{log_file_name} : {line}",
                            }
                        )
                except Exception as e:
                    self.log.error(
                        "Failed to parse sysdiagnose log (%s) path: %s",
                        str(e),
                        log_file_name,
                    )

    def check_indicators(self) -> None:
        if not self.indicators:
            return

        for result in self.results:
            # Check if crashed process BundleID matches known malicious app
            bundle_id = result.get("BundleID")
            if bundle_id:
                ioc_match = self.indicators.check_process(bundle_id)
                if ioc_match:
                    self.alertstore.high(
                        ioc_match.message, "", result, matched_indicator=ioc_match.ioc
                    )
                    continue

                ioc_match = self.indicators.check_app_id(bundle_id)
                if ioc_match:
                    self.alertstore.high(
                        ioc_match.message, "", result, matched_indicator=ioc_match.ioc
                    )

            # Check if ProcessName matches known malicious process
            process_name = result.get("ProcessName")
            if process_name:
                ioc_match = self.indicators.check_process(process_name)
                if ioc_match:
                    self.alertstore.high(
                        ioc_match.message, "", result, matched_indicator=ioc_match.ioc
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

                # parse os.environ[DIAGNOSTIC_LOGS_PATH] ips
                self.process_sysdiagnose_ips(os.environ[DIAGNOSTIC_LOGS_PATH], CRASH_REPORTER_LOG_PATHS) 
                # parse sysdiagnose ips
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
                        self.process_sysdiagnose_ips(extracted_path, CRASH_REPORTER_LOG_PATHS)  
                        self.process_sysdiagnose_log(extracted_path, SYSDIAGNOSE_LOG_PATHS)           

        else:
            self.process_sysdiagnose_ips(self.target_path, CRASH_REPORTER_LOG_FS_PATHS)
        

        self.results = sorted(self.results, key=lambda entry: entry["timestamp"])


