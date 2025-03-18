# Mobile Verification Toolkit (MVT)
# Copyright (c) 2021-2023 The MVT Authors.
# Use of this software is governed by the MVT License 1.1 that can be found at
#   https://license.mvt.re/1.1/

import logging
import datetime
from typing import Optional, Union
from mvt.common.utils import convert_datetime_to_iso
from ..base import IOSExtraction

SMS_MIGRATOR_LOG_PATH = [
    "private/var/mobile/Library/Logs/SMSMigrator/SMSMigrator.log",
]


class SMSMigratorLog(IOSExtraction):
    """This module extracts information from the SMSMigrator log file."""

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
        return {
            "timestamp": record["timestamp"],
            "module": self.__class__.__name__,
            "event": "sms_migrator_activity",
            "data": f"Process {record['process']} with PID {record['pid']} "
                    f"performed action: {record['action']}",
        }

    def process_smsmigrator_log(self, content):
        for line in content.split("\n"):
            line = line.strip()
            if not line:
                continue

            try:
                # Parse the log line
                # Example: "2025-03-05 03:04:32 +0800 IMDPersistenceAgent[187]: Created table (if needed) ok: deleted_messages"
                timestamp_str = line[0:19] + " " + line[20:25]  # e.g., "2025-03-05 03:04:32 +0800"
                process_start = len(timestamp_str) + 1
                process_end = line.find("[")
                process = line[process_start:process_end]
                pid = line[process_end + 1:line.find("]")]
                action = line[line.find(":") + 2:].strip()
                
                # Parse timestamp without microseconds
                timestamp = datetime.datetime.strptime(
                    timestamp_str, "%Y-%m-%d %H:%M:%S %z"
                )
                timestamp_utc = timestamp.astimezone(datetime.timezone.utc)

                self.results.append({
                    "timestamp": convert_datetime_to_iso(timestamp_utc),
                    "process": process,
                    "pid": pid,
                    "action": action,
                })
            except Exception as e:
                self.log.error("Failed to parse SMSMigrator log (%s)", str(e))

        # Sort results by timestamp
        self.results = sorted(self.results, key=lambda entry: entry["timestamp"])

    def run(self) -> None:
        self._find_ios_database(root_paths=SMS_MIGRATOR_LOG_PATH)
        self.log.info("Found SMSMigrator log at path: %s", self.file_path)
        with open(self.file_path, "r", encoding="utf-8") as handle:
            self.process_smsmigrator_log(handle.read())