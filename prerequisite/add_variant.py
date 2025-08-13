# -*- coding: utf-8 -*-
"""
add_variant.py
- 단일 함수(대표 패턴)를 variant_db.json 에 추가/교체하는 CLI 유틸
- 2가지 입력 모드 지원:
  (A) --c-file: C 소스 파일 → AST 생성기 호출 → TU JSON → FunctionDefinition 추출 → build_variant
  (B) --ast-json: AST JSON(TranslationUnit or FunctionDefinition) 직접 입력 → build_variant

사용 예:
  # A) C 소스에서 바로
  python prerequisite/add_variant.py \
      --c-file ./temp/query_code/test_cmdinj.c \
      --func-name test_cmdinj \
      --pattern-id CWE-78_CommandInjection_System_P1 \
      --cwe-id CWE-78 \
      --desc "system(cmd) 기반 OS Command Injection 대표 패턴" \
      --replace-by-pattern

  # B) AST JSON에서
  python prerequisite/add_variant.py \
      --ast-json ./data/test_cmdinj.json \
      --func-name test_cmdinj \
      --pattern-id CWE-78_CommandInjection_System_P1 \
      --cwe-id CWE-78 \
      --replace-by-pattern
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

# ── 프로젝트 루트/경로 세팅 ─────────────────────────────────────────────
THIS_FILE = Path(__file__).resolve()
PREREQ_DIR = THIS_FILE.parent
BASE_DIR = PREREQ_DIR.parent
DATA_DIR = BASE_DIR / "data"

# 네 구조상 prerequisite/ 안의 모듈을 임포트해야 하므로 경로 보장
if str(PREREQ_DIR) not in sys.path:
    sys.path.insert(0, str(PREREQ_DIR))

# build_variant, make_json_serializable import
try:
    from cwe_similarity_v8_variant_creation import build_variant, make_json_serializable
except Exception as e:
    print("[ERROR] prerequisite/cwe_similarity_v8_variant_creation.py 임포트 실패:", e)
    sys.exit(1)


# ── 유틸: 임시 디렉토리 비우기 ──────────────────────────────────────────
def clear_dir(p: Path):
    if not p.exists():
        return
    for name in os.listdir(p):
        try:
            target = p / name
            if target.is_file():
                target.unlink()
            elif target.is_dir():
                shutil.rmtree(target, ignore_errors=True)
        except Exception:
            pass


# ── 유틸: AST 생성기 호출 (네 UI와 동일한 방식) ─────────────────────────
def run_ast_generator(generator_dir: Path, temp_dir: Path) -> subprocess.CompletedProcess:
    """
    sudo npm run generate:full -- --data=<temp_dir>
    """
    cmd = [
        "sudo", "npm", "run", "generate:full",
        f"--data={str(temp_dir)}"
    ]
    result = subprocess.run(cmd, cwd=str(generator_dir), capture_output=True, text=True)
    return result


def get_latest_result_dir(result_root: Path):
    """
    result_root 하위 디렉토리 중 가장 최근(사전순 마지막)을 고름.
    """
    if not result_root.exists():
        return None
    candidates = []
    for d in result_root.iterdir():
        if d.is_dir():
            candidates.append(d)
    if not candidates:
        return None
    candidates = sorted(candidates)
    return candidates[-1]


def move_template_json(result_dir: Path, ast_dir: Path, c_path: Path) -> Path:
    """
    result/<ts>/<basename>_templateTree.json → ast_dir/<basename>.json 으로 복사
    """
    base = c_path.stem
    src_json = result_dir / f"{base}_templateTree.json"
    if not src_json.exists():
        raise FileNotFoundError(f"{src_json} 없음")
    dst_json = ast_dir / f"{base}.json"
    shutil.copy(src_json, dst_json)
    return dst_json


# ── 유틸: TU/FunctionDefinition JSON에서 FunctionDefinition 추출 ────────
def extract_funcdef_from_ast_json(ast_json, func_name=None):
    """
    TranslationUnit 내에서 FunctionDefinition 노드를 추출.
    - func_name 지정 시 이름 일치하는 함수만 반환
    - 최상위가 FunctionDefinition이면 그대로 반환
    """
    if isinstance(ast_json, dict) and ast_json.get("nodeType") == "FunctionDefinition":
        return ast_json

    tu_node = None
    if isinstance(ast_json, list):
        for node in ast_json:
            if isinstance(node, dict) and node.get("nodeType") == "TranslationUnit":
                tu_node = node
                break
    elif isinstance(ast_json, dict) and ast_json.get("nodeType") == "TranslationUnit":
        tu_node = ast_json
    else:
        raise ValueError("TranslationUnit/FunctionDefinition JSON이 아닙니다.")

    if not tu_node:
        raise ValueError("TranslationUnit 노드를 찾을 수 없습니다.")

    children = tu_node.get("children", [])
    for child in children:
        if child.get("nodeType") == "FunctionDefinition":
            if (func_name is None) or (child.get("name") == func_name):
                return child

    raise ValueError("FunctionDefinition 노드를 찾을 수 없습니다. --func-name 을 확인하세요.")


# ── 핵심: variant_db append/replace ─────────────────────────────────────
def add_or_replace_variant_from_ast_json(
    ast_json_path: Path,
    variant_db_path: Path,
    func_name: str = None,
    cwe_id: str = "Query",
    pattern_id: str = "Query_Pattern",
    src: str = "Custom",
    desc: str = "대표 패턴(수동 등록)",
    file_name: str = None,
    replace_by_pattern: bool = True,
    backup: bool = True
):
    # 1) AST JSON 로드
    with open(ast_json_path, "r", encoding="utf-8") as f:
        ast_json = json.load(f)

    # 2) FunctionDefinition 확보
    func_node = extract_funcdef_from_ast_json(ast_json, func_name=func_name)

    # 3) build_variant 수행
    if file_name is None:
        file_name = ast_json_path.name

    variant = build_variant(
        func_node,
        cwe_id=cwe_id,
        pattern_id=pattern_id,
        window=3,
        src=src,
        file_name=file_name,
        desc=desc,
        max_n=5,
        max_m=3
    )
    variant = make_json_serializable(variant)

    # 4) DB 로드
    if not variant_db_path.exists():
        raise FileNotFoundError(f"variant_db.json 없음: {variant_db_path}")
    with open(variant_db_path, "r", encoding="utf-8") as f:
        db = json.load(f)
    if not isinstance(db, list):
        raise ValueError("variant_db.json 최상위는 list 형태여야 합니다.")

    # 5) 교체/추가
    replaced = False
    if replace_by_pattern:
        for i in range(len(db)):
            item = db[i]
            if item.get("pattern_id") == pattern_id:
                db[i] = variant
                replaced = True
                break
    if not replaced:
        db.append(variant)

    # 6) 백업/저장
    if backup:
        shutil.copy(str(variant_db_path), str(variant_db_path.with_suffix(".json.bak")))
    with open(variant_db_path, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)

    print("[OK] variant_db 갱신 완료.")
    print("     pattern_id:", pattern_id, "(replaced)" if replaced else "(added)")
    print("     cwe_id    :", variant.get("cwe_id"), "  variant_id:", variant.get("variant_id"))
    return variant


def main():
    parser = argparse.ArgumentParser(description="단일 함수(대표 패턴)를 variant_db.json에 등록")
    parser.add_argument("--c-file", type=str, default=None, help="입력 C 소스 파일 경로")
    parser.add_argument("--ast-json", type=str, default=None, help="입력 AST JSON 경로(TranslationUnit 또는 FunctionDefinition)")
    parser.add_argument("--func-name", type=str, default=None, help="추출할 함수명(생략 시 TU의 첫 함수)")

    parser.add_argument("--pattern-id", type=str, required=True, help="DB에 저장할 pattern_id (유일키로 사용 권장)")
    parser.add_argument("--cwe-id", type=str, default="Query", help="CWE ID (예: CWE-78). build_variant 내부 매핑이 있으면 최종값이 바뀔 수 있음")
    parser.add_argument("--src", type=str, default="Custom", help="meta.source")
    parser.add_argument("--desc", type=str, default="대표 패턴(수동 등록)", help="meta.description")

    parser.add_argument("--variant-db", type=str, default=str(DATA_DIR / "variant_db.json"), help="variant_db.json 경로")
    parser.add_argument("--generator-dir", type=str, default=None, help="C-AST-Generator-main 경로(미지정 시 기본 경로 추정)")
    parser.add_argument("--temp-root", type=str, default=str(BASE_DIR / "temp"), help="임시 작업 루트 디렉토리")
    parser.add_argument("--replace-by-pattern", action="store_true", help="pattern_id 동일 항목이 있으면 교체")
    parser.add_argument("--no-backup", action="store_true", help="백업 파일(.bak) 생성하지 않음")
    args = parser.parse_args()

    variant_db_path = Path(args.variant_db)
    backup = not args.no_backup

    # 입력 검증
    if not args.c_file and not args.ast_json:
        print("[ERROR] --c-file 또는 --ast-json 중 하나는 반드시 지정해야 합니다.")
        sys.exit(2)
    if args.c_file and args.ast_json:
        print("[ERROR] --c-file 과 --ast-json 을 동시에 지정하지 마세요. 하나만.")
        sys.exit(2)

    # AST Generator 경로 추정
    generator_dir = None
    if args.generator_dir:
        generator_dir = Path(args.generator_dir)
    else:
        # 네 구조상 리포 루트에도 있고, UI는 절대경로(/home/devel02/...)를 사용.
        # 우선 리포 루트의 C-AST-GENERATOR-main 를 기본값으로 시도
        guess1 = BASE_DIR / "C-AST-GENERATOR-main"
        if guess1.exists():
            generator_dir = guess1
        else:
            # 사용자 환경 절대경로(확실하지 않음)
            guess2 = Path("/home/devel02/data/C-AST-GENERATOR-main")
            generator_dir = guess2

    # ──────────────────────────────────────────────────────────────────
    # 모드 A: C 소스에서 시작
    if args.c_file:
        c_path = Path(args.c_file).resolve()
        print("[DEBUG] cwd:", os.getcwd())
        print("[DEBUG] args.c_file:", args.c_file)

        if not c_path.exists():
            print("[ERROR] C 파일 없음:", c_path)
            sys.exit(2)

        # 임시 작업 디렉토리 준비
        temp_root = Path(args.temp_root)
        query_dir = temp_root / "query_code_cli"
        ast_dir = temp_root / "ast_cli"
        query_dir.mkdir(parents=True, exist_ok=True)
        ast_dir.mkdir(parents=True, exist_ok=True)
        clear_dir(query_dir)
        clear_dir(ast_dir)

        # C 파일을 임시 디렉토리로 복사
        # (AST 생성기는 --data=<temp_dir> 하위의 *.c 를 대상으로 생성)
        dst_c = query_dir / c_path.name
        shutil.copy(c_path, dst_c)

        # AST 생성기 호출
        if not generator_dir or not generator_dir.exists():
            print("[ERROR] AST Generator 디렉토리를 찾을 수 없습니다:", generator_dir)
            sys.exit(2)

        print("[INFO] AST 생성기 호출:", generator_dir)
        result = run_ast_generator(generator_dir, query_dir)
        if result.returncode != 0:
            print("[ERROR] AST 생성 실패!")
            print("STDOUT:\n", result.stdout)
            print("STDERR:\n", result.stderr)
            sys.exit(2)

        # result/<timestamp>/ 찾기
        result_root = generator_dir / "result"
        result_dir = get_latest_result_dir(result_root)
        if not result_dir:
            print("[ERROR] result 디렉토리를 찾을 수 없습니다:", result_root)
            sys.exit(2)

        # templateTree.json → ast_dir/<base>.json
        try:
            ast_json_path = move_template_json(result_dir, ast_dir, dst_c)
        except Exception as e:
            print("[ERROR] templateTree.json 복사 오류:", e)
            sys.exit(2)

        # DB 추가/교체
        add_or_replace_variant_from_ast_json(
            ast_json_path=ast_json_path,
            variant_db_path=variant_db_path,
            func_name=args.func_name,
            cwe_id=args.cwe_id,
            pattern_id=args.pattern_id,
            src=args.src,
            desc=args.desc,
            file_name=ast_json_path.name,
            replace_by_pattern=args.replace_by_pattern,
            backup=backup
        )
        return

    # ──────────────────────────────────────────────────────────────────
    # 모드 B: AST JSON에서 시작
    if args.ast_json:
        ast_json_path = Path(args.ast_json).resolve()
        if not ast_json_path.exists():
            print("[ERROR] AST JSON 없음:", ast_json_path)
            sys.exit(2)

        add_or_replace_variant_from_ast_json(
            ast_json_path=ast_json_path,
            variant_db_path=variant_db_path,
            func_name=args.func_name,
            cwe_id=args.cwe_id,
            pattern_id=args.pattern_id,
            src=args.src,
            desc=args.desc,
            file_name=ast_json_path.name,
            replace_by_pattern=args.replace_by_pattern,
            backup=backup
        )
        return


if __name__ == "__main__":
    main()
