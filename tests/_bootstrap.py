"""测试公共引导：把仓库根目录加入 sys.path，使 ``import solution`` 可用。"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

CASES_PATH = os.path.join(ROOT, "cases.json")
