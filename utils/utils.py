import os
import logging
import hashlib
from pathlib import Path
from contextlib import contextmanager
import time
import re
from config import config

def parse_funcnames(text: str):
    """
    从形如 ***httpd_get_parm*** 或 ***httpd_get_parm,func2*** 的字符串中解析函数名
    返回一个去重后的列表，按出现顺序
    """
    if not text:
        return []

    # 1. 先找出所有 ***...*** 段
    blocks = re.findall(r"\*\*\*(.+?)\*\*\*", text, flags=re.DOTALL)
    result = []
    seen = set()

    for blk in blocks:
        # 2. 一个块里可能是 httpd_get_parm,func2 这样，用逗号分
        parts = blk.split(",")
        for p in parts:
            name = p.strip()
            # 去掉多余换行/回车
            name = name.replace("\r", "").replace("\n", "").strip()
            if name and name not in seen:
                seen.add(name)
                result.append(name)

    return result

def ensure_directory_exists(directory_path, logger=None):
    """
    Check if the directory exists; if not, create it.

    :param directory_path: The path of the directory to check or create.
    :param logger: Optional logger for logging messages.
    """
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)
        if logger:
            logger.info(f"Created folder: {directory_path}")
    else:
        if logger:
            logger.info(f"Folder already exists: {directory_path}")


def get_md5_prefix(file_path, length=6):
    """Compute the first `length` characters of the MD5 hash of the file."""
    md5 = hashlib.md5()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            md5.update(chunk)
    return md5.hexdigest()[:length]

def upsert_ProjectInfo_data(tag, data):
    session = config.IoTReaperConfig.get_db_session(config.Base)
    try:
        # 尝试查询是否已有此 tag
        existing_record = session.query(config.ProjectInfo).filter_by(tag=tag).first()

        if existing_record:
            # 如果已有记录，则更新
            existing_record.data = data
        else:
            # 如果没有记录，则插入
            new_entry = config.ProjectInfo(tag=tag, data=data)
            session.add(new_entry)
        
        # 提交更改
        session.commit()
    except Exception as e:
        session.rollback()
        print(f"Error: {e}")
    finally:
        session.close()

@contextmanager
def timeit_context(description="option"):
    start = time.time()
    yield
    end = time.time()
    print(f"{description} spend: {end - start:.2f} secs")

def scan_subfolders(target_dir):
    path = Path(target_dir)
    if not path.exists():
        raise FileNotFoundError(f"Path not exist: {target_dir}")
    if not path.is_dir():
        raise NotADirectoryError(f"Path is not Dir: {target_dir}")
    return [child.name for child in path.iterdir() if child.is_dir()]

import time

def run_with_timer(stage_name, func, *args, **kwargs):
    print(f"\n===== Running stage: {stage_name.upper()} =====")
    start_time = time.time()

    func(*args, **kwargs)

    end_time = time.time()
    cost = end_time - start_time
    print(f"===== Stage {stage_name.upper()} finished in {cost:.2f} seconds =====")


# Example usage
if __name__ == "__main__":
    # logging.basicConfig(level=logging.INFO)
    # logger = logging.getLogger(__name__)

    # folder_path = "my_directory"
    # ensure_directory_exists(folder_path, logger)

    target_directory = "/home/satc/iotreaper/result"
    subfolder_list = scan_subfolders(target_directory)
    print("dir list:", subfolder_list)


