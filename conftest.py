# 这个空文件让 pytest 把仓库根目录插进 sys.path，
# 这样 tests/ 里才能 import models，而不必强求用 `python -m pytest` 启动。
