# Mobile Verification Toolkit (MVT)
# Copyright (c) 2021-2023 The MVT Authors.
# Use of this software is governed by the MVT License 1.1 that can be found at
#   https://license.mvt.re/1.1/
import os
import glob
import re
import logging
from json import loads, JSONDecodeError
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

DIAGNOSTIC_LOGS_PATH = "DIAGNOSTIC_LOGS_PATH"



# IPS crash reports always include timezone offsets in their timestamps.
# Only timezone-aware formats are listed here.
TIME_FORMATS = [
    "%Y-%m-%d %H:%M:%S.%f %z",       # 2026-05-08 10:57:44.00 +0300
    "%Y-%m-%d %H:%M:%S.%f%z",        # 2023-12-30 00:37:44+0800
    "%Y-%m-%d %H:%M:%S %z",          # 2022-01-13 14:04:21 +0000
    "%Y-%m-%d %H:%M:%S%z",           # 2025-09-08 21:58:56+0800
    "%Y-%m-%d %H:%M:%S.%fZ",         # 2025-08-28 04:36:25.285567Z
    "%Y-%m-%d %H:%M:%SZ",            # 2025-08-28 04:36:25Z
    # Naive formats — used only by Sysdiagnose for log parsing
    "%a %b %d %H:%M:%S %Y",          # Sun Oct 19 13:19:37 2025
    "%m/%d/%y %H:%M:%S.%f",          # 09/13/25 13:43:37.426607
    "%m/%d/%y %H:%M:%S",             # 09/13/25 13:43:37
    "%Y-%m-%d_%H:%M:%S",             # 2025-11-12_16:13:41
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

def parse_ips_files(target_path, patterns, results, log):
    """Parse .ips crash report files from a directory tree.

    Scans target_path with the given glob patterns, parses each .ips file,
    and appends records to the results list.  Returns the number of files
    successfully parsed.
    """
    count = 0
    for file_pattern in patterns:
        for ips_file in glob.glob(
            os.path.join(target_path, file_pattern), recursive=True
        ):
            if not os.path.exists(ips_file):
                continue

            ips_file_name = ips_file.split("/")[-1]
            log.info("Found IPS crash report: %s", ips_file_name)

            with open(ips_file, "rb") as fh:
                content = fh.read().decode("utf-8", errors="ignore")
                lines = content.split("\n")

            try:
                log_line = loads(lines[0])
            except (JSONDecodeError, IndexError) as e:
                log.error(
                    "Failed to parse IPS JSON (%s) path: %s", str(e), ips_file_name
                )
                continue

            if not isinstance(log_line, dict):
                log.error("IPS first line is not a JSON object: %s", ips_file_name)
                continue

            # Parse timestamp — IPS always carries a timezone offset
            timestamp = None
            for ts_field in ("timestamp", "captureTime", "date"):
                if ts_field not in log_line:
                    continue
                ts_value = str(log_line[ts_field])
                for fmt in TIME_FORMATS:
                    try:
                        ts = datetime.datetime.strptime(ts_value, fmt)
                        if ts.tzinfo is not None:
                            timestamp = ts
                            break
                    except (ValueError, TypeError):
                        continue
                if timestamp:
                    break

            if timestamp is None:
                log.error(
                    "Failed to parse timestamp in IPS: %s (value: %s)",
                    ips_file_name,
                    log_line.get(
                        "timestamp", log_line.get("captureTime", "missing")
                    ),
                )
                continue

            bundle_id = log_line.get("bundleID", "")
            is_system = bool(bundle_id and bundle_id.startswith("com.apple."))

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

            if termination_info:
                term_reason = termination_info.get("reason", "")
                if term_reason:
                    record["TerminationReason"] = term_reason

            triggered_by = log_line.get("triggered_by", "")
            if triggered_by:
                record["TriggeredBy"] = triggered_by

            results.append(record)
            count += 1

    return count


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
        """Parse .ips files and append results to self.results."""
        count = parse_ips_files(extracted_path, patterns, self.results, self.log)
        self.log.info("Parsed %d IPS crash reports at path: %s", count, extracted_path)

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
                self.process_sysdiagnose_ips(
                    log_path, CRASH_REPORTER_LOG_PATHS
                )
        else:
            self.process_sysdiagnose_ips(
                self.target_path, CRASH_REPORTER_LOG_FS_PATHS
            )

        self.results = sorted(self.results, key=lambda entry: entry["timestamp"])


