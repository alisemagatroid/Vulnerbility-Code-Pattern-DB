import subprocess, shutil, json
from pathlib import Path

def run_ast_generator(temp_dir):
    generator_dir = Path("/home/devel02/data/C-AST-Generator-main")
    result = subprocess.run(
        [
            "sudo", "npm", "run", "generate:full",
            f"--data={str(temp_dir)}"
        ],
        cwd=str(generator_dir),
        capture_output=True, text=True
    )
    return result


def move_template_json(result_dir, ast_dir, c_path):
    base = c_path.stem
    src_json = result_dir / f"{base}_templateTree.json"
    if not src_json.exists():
        raise FileNotFoundError(f"{src_json} 없음")
    dst_json = ast_dir / f"{base}.json"
    shutil.copy(src_json, dst_json)
    return dst_json


# Function Definition을 추출하여, 임베딩 벡터 추출 세팅
def extract_funcdef_from_ast_json(ast_json, func_name=None):
    """
    TranslationUnit 내에서 FunctionDefinition 노드 추출.
    func_name 지정 시 이름 일치하는 함수만 반환.
    """
    tu_node = None
    # 1. 최상위가 리스트이면 TranslationUnit 노드 찾기
    if isinstance(ast_json, list):
        for node in ast_json:
            if isinstance(node, dict) and node.get("nodeType") == "TranslationUnit":
                tu_node = node
                break
    elif isinstance(ast_json, dict) and ast_json.get("nodeType") == "TranslationUnit":
        tu_node = ast_json
    else:
        raise ValueError("TranslationUnit 노드를 찾을 수 없습니다.")

    # 2. FunctionDefinition 노드 추출
    for child in tu_node.get("children", []):
        if child.get("nodeType") == "FunctionDefinition":
            if (func_name is None) or (child.get("name") == func_name):
                return child
    raise ValueError("FunctionDefinition 노드를 찾을 수 없습니다. 정확한 함수를 입력하세요.")