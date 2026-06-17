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
from typing import Iterator, Optional, Union
from mvt.common.utils import convert_mactime_to_iso
from ..base import IOSExtraction

FILE_SYSTEM_MATE_LOG_PATHS = [
    # "**/*.fslisting",
    "FilesystemMeta-*.fsmeta.tgz",
]

# fsmeta 解压后目录中的各类 listing 文件扩展名
LISTING_FILE_TYPES = {
    ".fslisting": "fslisting",
    ".attrstaglisting": "attrstag",
    ".dirstatsdatalisting": "dirstats",
    ".purgeablerecordslisting": "purgeable",
    ".sharedextentslisting": "sharedextents",
}

DIAGNOSTIC_LOGS_PATH = "DIAGNOSTIC_LOGS_PATH"


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
        data = (
            f"{record.get('Path', 'Unknown path')} modified at {record.get('timestamp', 'Unknown time')}, "
            f"size: {record.get('FileSize', 'Unknown size')}, mode: {record.get('Mode', 'Unknown mode')}"
        )
        if record.get("AccessTime"):
            data += f", accessed at {record['AccessTime']}"
        if record.get("UID") is not None:
            data += f", uid: {record['UID']}"
        if record.get("GID") is not None:
            data += f", gid: {record['GID']}"
        if record.get("InodeID") is not None:
            data += f", inode: {record['InodeID']}"
        if record.get("TagOwner"):
            data += f", tag_owner: {record['TagOwner']}"
        if record.get("SAFDirStats") is not None:
            data += f", dir_stats: {record['SAFDirStats']}"
        if record.get("PurgeableFlags") is not None:
            data += f", purgeable_flags: {record['PurgeableFlags']}"
        if record.get("PurgeableSize") is not None:
            data += f", purgeable_size: {record['PurgeableSize']}"
        if record.get("SharedExtentCount") is not None:
            data += f", shared_extents: {record['SharedExtentCount']}"

        return {
            "timestamp": record["timestamp"],
            "module": self.__class__.__name__,
            "event": "file_system_mate_activity",
            "data": data,
        }
    
    def check_indicators(self) -> None:
        if not self.indicators:
            return

        for result in self.results:
            if "Path" not in result:
                continue

            ioc_match = self.indicators.check_file_path(result["Path"])
            if ioc_match:
                self.alertstore.high(
                    ioc_match.message, "", result, matched_indicator=ioc_match.ioc
                )

            if self.module_options.get("fast_mode", None):
                continue

            ioc_match = self.indicators.check_file_path_process(result["Path"])
            if ioc_match:
                self.alertstore.high(
                    ioc_match.message, "", result, matched_indicator=ioc_match.ioc
                )

            # 检查 TagOwner (来自 .attrstaglisting) 是否为已知恶意进程
            if result.get("TagOwner"):
                ioc_match = self.indicators.check_process(result["TagOwner"])
                if ioc_match:
                    self.alertstore.high(
                        ioc_match.message, "", result, matched_indicator=ioc_match.ioc
                    )

    def _parse_simple_listing(self, content, expected_cols):
        """通用简单 listing 解析器。

        跳过头部直到 <BEGIN>，然后按 tab 分割每行，
        返回列数足够的行列表。
        """
        rows = []
        in_data_section = False
        for line in content.split("\n"):
            line_stripped = line.strip()
            if not line_stripped:
                continue
            if not in_data_section:
                if line_stripped == '<BEGIN>':
                    in_data_section = True
                continue
            columns = line_stripped.split('\t')
            if len(columns) >= expected_cols:
                rows.append(columns)
        return rows

    def process_attrstag_listing(self, content):
        """解析 .attrstaglisting：Tag-Owner, Tag-Hash, Path

        返回以 Path 为键的字典，值为 TagOwner 和 TagHash。
        """
        tag_by_path = {}
        for columns in self._parse_simple_listing(content, 3):
            path = columns[2]
            try:
                tag_by_path[path] = {
                    "TagOwner": columns[0],
                    "TagHash": int(columns[1]),
                }
            except (ValueError, IndexError):
                pass
        self.log.info("Parsed %d attrstag entries", len(tag_by_path))
        return tag_by_path

    def process_dirstats_listing(self, content):
        """解析 .dirstatsdatalisting：Path, SAFDirStats

        返回以 Path 为键的字典，值为 SAFDirStats 标志。
        """
        stats_by_path = {}
        for columns in self._parse_simple_listing(content, 2):
            path = columns[0]
            try:
                stats_by_path[path] = int(columns[1])
            except (ValueError, IndexError):
                pass
        self.log.info("Parsed %d dirstats entries", len(stats_by_path))
        return stats_by_path

    def process_purgeable_listing(self, content):
        """解析 .purgeablerecordslisting：Inode-Number, Purgeable-Flags,
        Last-Access-Time, Purgeable-Size

        返回以 Inode-Number 为键的字典。
        """
        purgeable_by_inode = {}
        for columns in self._parse_simple_listing(content, 4):
            try:
                inode = int(columns[0])
                purgeable_by_inode[inode] = {
                    "PurgeableFlags": int(columns[1]),
                    "LastAccessTime": int(columns[2]),
                    "PurgeableSize": int(columns[3]),
                }
            except (ValueError, IndexError):
                pass
        self.log.info("Parsed %d purgeable entries", len(purgeable_by_inode))
        return purgeable_by_inode

    def process_sharedextents_listing(self, content):
        """解析 .sharedextentslisting：Physical-Block-Number, Owning-Obj-Id,
        Size, Reference-Count

        返回记录列表，同时建一个以 Owning-Obj-Id 为键的索引供关联查询。
        """
        extents = []
        for columns in self._parse_simple_listing(content, 4):
            try:
                extents.append({
                    "PhysicalBlockNumber": int(columns[0]),
                    "OwningObjId": int(columns[1]),
                    "Size": int(columns[2]),
                    "ReferenceCount": int(columns[3]),
                })
            except (ValueError, IndexError):
                pass
        self.log.info("Parsed %d shared extent entries", len(extents))
        return extents

    def _enrich_results(self, tag_by_path, stats_by_path,
                         purgeable_by_inode, extent_list):
        """将附加 listing 数据合并到 fslisting 结果中。

        通过 Path 关联 attrstag 和 dirstats，
        通过 InodeID 关联 purgeable 记录，
        通过 InodeID 关联 shared extents（OwningObjId ↔ InodeID）。
        """
        # 构建 extents 的 Inode → extent 索引 (OwningObjId ≈ InodeID)
        extent_by_owner = {}
        for ext in extent_list:
            oid = ext["OwningObjId"]
            if oid not in extent_by_owner:
                extent_by_owner[oid] = []
            extent_by_owner[oid].append(ext)

        for record in self.results:
            path = record.get("Path", "")
            inode_id = record.get("InodeID")

            # 通过 Path 关联 attrstag
            if path in tag_by_path:
                record["TagOwner"] = tag_by_path[path]["TagOwner"]
                record["TagHash"] = tag_by_path[path]["TagHash"]

            # 通过 Path 关联 dirstats
            if path in stats_by_path:
                record["SAFDirStats"] = stats_by_path[path]

            # 通过 InodeID 关联 purgeable 记录
            if inode_id is not None and inode_id in purgeable_by_inode:
                p = purgeable_by_inode[inode_id]
                record["PurgeableFlags"] = p["PurgeableFlags"]
                record["PurgeableSize"] = human_readable_size(p["PurgeableSize"])
                try:
                    record["LastAccessTime"] = convert_mactime_to_iso(
                        timestamp=p["LastAccessTime"], from_2001=False
                    )
                except Exception:
                    pass

            # 通过 InodeID 关联共享 extent
            if inode_id is not None and inode_id in extent_by_owner:
                exts = extent_by_owner[inode_id]
                record["SharedExtentCount"] = len(exts)
                record["SharedExtentTotalSize"] = human_readable_size(
                    sum(e["Size"] for e in exts)
                )

    def _get_files_from_patterns(self, target_path: str, root_paths: list) -> Iterator[str]:
        for root_path in root_paths:
            for found_path in glob.glob(os.path.join(target_path, root_path), recursive=True):
                if not os.path.exists(found_path):
                    continue

                yield found_path

    def _parse_column_map(self, line):
        """解析列标题行，返回列名到索引的映射。

        通过动态解析列标题行来确定各列的索引位置，
        兼容不同 iOS 版本的 fslisting 格式差异。
        iOS 26 新增了 atime 和 Inode-ID 列。
        """
        headers = line.strip().split('\t')
        return {header.strip(): idx for idx, header in enumerate(headers)}

    def _get_column_indices(self, column_map):
        """从列映射中获取各字段的索引，缺失时使用旧格式默认值。"""
        return {
            'size_on_disk': column_map.get('Size-On-Disk', 0),
            'file_size': column_map.get('File-Size', 1),
            'flags': column_map.get('FS-Purgeable-Flags', 3),
            'atime': column_map.get('atime', -1),
            'mtime': column_map.get('mtime', 4),
            'mode': column_map.get('Mode', 5),
            'uid': column_map.get('UID', 6),
            'gid': column_map.get('GID', 7),
            'inode': column_map.get('Inode-ID', -1),
            'path': column_map.get('Path', 8),
        }

    def process_file_system_mate_log(self, content):
        in_data_section = False
        column_map = None

        # 旧格式默认列映射 (回退方案)
        DEFAULT_COLUMN_MAP = {
            'Size-On-Disk': 0, 'File-Size': 1, 'Compression': 2,
            'FS-Purgeable-Flags': 3, 'mtime': 4, 'Mode': 5,
            'UID': 6, 'GID': 7, 'Path': 8,
        }

        for line in content.split("\n"):
            line_stripped = line.strip()
            if not line_stripped:
                continue

            # 头部处理
            if not in_data_section:
                if line_stripped == '<BEGIN>':
                    in_data_section = True
                    # 未找到列标题时使用旧格式默认映射
                    if column_map is None:
                        column_map = DEFAULT_COLUMN_MAP
                    continue

                # 动态解析列标题行 (兼容新旧格式)
                if 'Size-On-Disk' in line_stripped and 'Path' in line_stripped:
                    column_map = self._parse_column_map(line_stripped)
                continue

            indices = self._get_column_indices(column_map)
            columns = line.split('\t')

            # 确保列数足够
            max_idx = max(v for v in indices.values() if v >= 0)
            if len(columns) <= max_idx:
                continue

            # File-Size
            try:
                file_size = int(columns[indices['file_size']])
                file_size_str = human_readable_size(file_size)
            except (ValueError, IndexError):
                file_size_str = "Unknown"

            # mtime
            try:
                timestamp = int(columns[indices['mtime']])
            except (ValueError, IndexError):
                continue

            # Mode
            try:
                mode = int(columns[indices['mode']])
                mode_str = mode_to_linux_format(mode)
            except (ValueError, IndexError):
                mode_str = "Unknown"

            # Path
            try:
                path = columns[indices['path']]
            except IndexError:
                continue

            record = {
                "timestamp": convert_mactime_to_iso(timestamp=timestamp, from_2001=False),
                "FileSize": file_size_str,
                "Mode": mode_str,
                "Path": path,
            }

            # iOS 26 新增字段
            if indices['atime'] >= 0:
                try:
                    atime = int(columns[indices['atime']])
                    record["AccessTime"] = convert_mactime_to_iso(timestamp=atime, from_2001=False)
                except (ValueError, IndexError):
                    pass

            if indices['inode'] >= 0:
                try:
                    record["InodeID"] = int(columns[indices['inode']])
                except (ValueError, IndexError):
                    pass

            if indices['uid'] >= 0:
                try:
                    record["UID"] = int(columns[indices['uid']])
                except (ValueError, IndexError):
                    pass

            if indices['gid'] >= 0:
                try:
                    record["GID"] = int(columns[indices['gid']])
                except (ValueError, IndexError):
                    pass

            try:
                self.results.append(record)
            except Exception as e:
                self.log.error("Failed to parse FilesystemMeta log (%s)", str(e))

        # Sort results by timestamp
        self.results = sorted(self.results, key=lambda entry: entry["timestamp"])
    
    def run(self) -> None:
        # Check for diagnostic logs from config
        if DIAGNOSTIC_LOGS_PATH in os.environ:
            
            if not os.path.exists(os.environ[DIAGNOSTIC_LOGS_PATH]):
                self.log.warning("Diagnostic logs path does not exist: %s", os.environ[DIAGNOSTIC_LOGS_PATH])
                return
            # Add a print statement for testing
            # print(f"Additional diagnostic logs paths: {os.environ[DIAGNOSTIC_LOGS_PATH]}")
            self.log.info("Processing diagnostic log file from config: %s", os.environ[DIAGNOSTIC_LOGS_PATH])
            for found_path in self._get_files_from_patterns(os.environ[DIAGNOSTIC_LOGS_PATH], FILE_SYSTEM_MATE_LOG_PATHS):
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

                    # 收集目录中所有 listing 文件，按类型分类
                    listing_files = {key: [] for key in LISTING_FILE_TYPES.values()}
                    for ext, file_type in LISTING_FILE_TYPES.items():
                        pattern = os.path.join(fslisting_path, f"*{ext}")
                        listing_files[file_type] = glob.glob(pattern)

                    all_listing = sum(listing_files.values(), [])
                    if not all_listing:
                        self.log.warning("No listing files found in the extracted directory.")
                        continue

                    # 解析各类 listing 文件
                    tag_by_path = {}
                    stats_by_path = {}
                    purgeable_by_inode = {}
                    extent_list = []

                    for listing_file in all_listing:
                        base_name = listing_file.split("/")[-1]
                        self.log.info("Processing listing file: %s", base_name)
                        with open(listing_file, "r") as f:
                            content = f.read()

                        if listing_file in listing_files["fslisting"]:
                            self.process_file_system_mate_log(content)
                        elif listing_file in listing_files["attrstag"]:
                            tag_by_path.update(
                                self.process_attrstag_listing(content)
                            )
                        elif listing_file in listing_files["dirstats"]:
                            stats_by_path.update(
                                self.process_dirstats_listing(content)
                            )
                        elif listing_file in listing_files["purgeable"]:
                            purgeable_by_inode.update(
                                self.process_purgeable_listing(content)
                            )
                        elif listing_file in listing_files["sharedextents"]:
                            extent_list.extend(
                                self.process_sharedextents_listing(content)
                            )

                    # 将附加数据通过 Path 和 InodeID 关联到 fslisting 结果中
                    if tag_by_path or stats_by_path or purgeable_by_inode or extent_list:
                        self._enrich_results(
                            tag_by_path, stats_by_path,
                            purgeable_by_inode, extent_list,
                        ) 