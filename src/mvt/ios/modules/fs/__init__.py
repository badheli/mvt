# Mobile Verification Toolkit (MVT)
# Copyright (c) 2021-2023 The MVT Authors.
# Use of this software is governed by the MVT License 1.1 that can be found at
#   https://license.mvt.re/1.1/

from .analytics import Analytics
from .analytics_ios_versions import AnalyticsIOSVersions
from .cache_files import CacheFiles
from .filesystem import Filesystem
from .net_netusage import Netusage
from .safari_favicon import SafariFavicon
from .shutdownlog import ShutdownLog
from .version_history import IOSVersionHistory
from .webkit_indexeddb import WebkitIndexedDB
from .webkit_localstorage import WebkitLocalStorage
from .webkit_safariviewservice import WebkitSafariViewService
from .SMSMigratorlog import SMSMigratorLog

FS_MODULES = [
    CacheFiles,
    Filesystem,
    Netusage,
    Analytics,
    AnalyticsIOSVersions,
    SafariFavicon,
    ShutdownLog,
    IOSVersionHistory,
    WebkitIndexedDB,
    WebkitLocalStorage,
    WebkitSafariViewService,
    SMSMigratorLog,
]
