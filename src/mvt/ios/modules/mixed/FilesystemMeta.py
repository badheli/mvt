# Mobile Verification Toolkit (MVT)
# Copyright (c) 2021-2023 The MVT Authors.
# Use of this software is governed by the MVT License 1.1 that can be found at
#   https://license.mvt.re/1.1/
import os
import glob
import tarfile
import tempfile
import logging
import datetime
from typing import Optional, Union
from mvt.common.utils import convert_mactime_to_iso
from ..base import IOSExtraction

FILE_SYSTEM_MATE_LOG_PATHS = [
    # "**/*.fslisting",
    "FilesystemMeta-*.fsmeta.tgz",
]


def human_readable_size(size):
    """将字节数转换为人类可读格式"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1000.0:
            return f"{size:.1f} {unit}"
        size /= 1000.0
    return f"{size:.1f} TB"

def mode_to_linux_format(mode):
    """将十进制 Mode 转换为 Linux 标准权限字符串"""
    # 转换为八进制字符串，去掉前缀 '0o'
    mode_oct = oct(int(mode))[2:]
    
    # 文件类型映射
    type_char = '-'
    if len(mode_oct) > 4 and mode_oct[-5] == '4':
        type_char = 'd'  # 目录
    # 其他类型（如 l, s 等）可根据需要扩展
    
    # 提取后三位权限
    perm_bits = mode_oct[-3:].zfill(3)  # 确保是三位，如 '755'
    
    # 权限映射表
    perm_map = {
        '0': '---', '1': '--x', '2': '-w-', '3': '-wx',
        '4': 'r--', '5': 'r-x', '6': 'rw-', '7': 'rwx'
    }
    
    # 转换为 rwx 格式
    user_perm = perm_map[perm_bits[0]]
    group_perm = perm_map[perm_bits[1]]
    other_perm = perm_map[perm_bits[2]]
    
    return type_char + user_perm + group_perm + other_perm



class FilesystemMetaLog(IOSExtraction):
    """This module extracts information from the FilesystemMeta log file."""

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
            "event": "file_system_mate_activity",
            "data": f"{record.get('Path', 'Unknown path')} modified at {record.get('timestamp', 'Unknown time')}, "
                    f"size: {record.get('FileSize', 'Unknown size')}, mode: {record.get('Mode', 'Unknown mode')}",
        }

    def process_file_system_mate_log(self, content):
        in_data_section = False
        for line in content.split("\n"):
            line = line.strip()
            if not line:
                continue
            
            # 头部处理
            if not in_data_section:
                if line.strip() == '<BEGIN>':
                    in_data_section = True
                continue
            
            # 数据部分处理
            columns = line.split('\t')
            if len(columns) < 9:
                continue
            
            
            # Size-On-Disk (第0列)
            try:
                size_on_disk = int(columns[0])
                columns[0] = human_readable_size(size_on_disk)
            except ValueError:
                pass
            
            # File-Size (第1列)
            try:
                file_size = int(columns[1])
                file_size_str = human_readable_size(file_size)
            except ValueError:
                pass
            
            # mtime (第4列)
            try:
                timestamp = int(columns[4])
            except ValueError:
                pass
            
            # Mode (第5列)
            try:
                mode = int(columns[5])
                mode_str = mode_to_linux_format(mode)
            except ValueError:
                pass
            
            # FS-Purgeable-Flags (第3列): 保留原值
            # 含义：0表示不可清除，非0表示可清除
            
            try:
                self.results.append({
                    "timestamp": convert_mactime_to_iso(timestamp=timestamp,from_2001=False),
                    "FileSize": file_size_str,
                    "Mode": mode_str,
                    "Path": columns[8],
                })
            except Exception as e:
                self.log.error("Failed to parse FilesystemMeta log (%s)", str(e))

        # Sort results by timestamp
        self.results = sorted(self.results, key=lambda entry: entry["timestamp"])
    
    def run(self) -> None:
        for found_path in self._get_fs_files_from_patterns(FILE_SYSTEM_MATE_LOG_PATHS):
            # # FilesystemMeta-*.fsmeta.tgz
            self.log.info("Found FilesystemMeta log at path: %s", found_path)
            # Extract the tar file to a temporary directory
            with tempfile.TemporaryDirectory() as tmp_dir:
                self.log.info("Extracting FilesystemMeta log to: %s", tmp_dir)
                with tarfile.open(found_path, "r:gz") as tar:
                    tar.extractall(path=tmp_dir)
                    # list the contents of the extracted directory
                    # self.log.info("Extracted files: %s",os.listdir(tmp_dir))
                # Find the extracted .fsmeta files
                fslisting_path = os.path.join(tmp_dir, found_path.split("/")[-1].replace(".tgz", ""))
                # self.log.info("Extracted fsmeta path: %s", fsmeta_path)
                fsmeta_files = glob.glob(os.path.join(fslisting_path, "*.fslisting"))
                if not fsmeta_files:
                    self.log.warning("No .fslisting files found in the extracted directory.")
                    continue
                # Process each .fslisting file
                for fsmeta_file in fsmeta_files:
                    self.log.info("Processing .fslisting file: %s", fsmeta_file.split("/")[-1])
                    with open(fsmeta_file, "r") as f:
                        content = f.read()
                        self.process_file_system_mate_log(content) 