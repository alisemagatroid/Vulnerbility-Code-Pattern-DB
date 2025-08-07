import os, time, random
from pathlib import Path

def clear_temp_dir(temp_dir: Path):
    for f in os.listdir(temp_dir):
        try:
            (temp_dir / f).unlink()
        except Exception:
            pass

def save_code_to_temp(user_code: str, temp_dir: Path) -> Path:
    ts = time.strftime("%Y%m%d-%H%M%S")
    rand = random.randint(1000, 9999)
    c_path = temp_dir / f"query_{ts}_{rand}.c"
    with open(c_path, "w") as f:
        f.write(user_code)
    return c_path