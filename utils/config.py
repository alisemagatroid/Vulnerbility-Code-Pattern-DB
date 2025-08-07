from pathlib import Path

# 프로젝트 경로
BASE_DIR = Path(__file__).parent.parent.parent
PREREQ_DIR = BASE_DIR / "prerequisite"
DATA_DIR   = BASE_DIR / "data"
GENERATOR_DIR = Path("/home/devel02/data/C-AST-Generator-main")

# DB 파일
SIGNATURE_DB_PATH = DATA_DIR / 'signature_db.yaml'
VARIANT_DB_PATH = DATA_DIR / 'variant_db.json'


# Temp 디렉토리
QUERY_TEMP_DIR = BASE_DIR / "temp" / "query_code"
AST_TEMP_DIR   = BASE_DIR / "temp" / "ast"

TAG_WEIGHT_PATH = DATA_DIR / 'tag_weight.py'



# UI 안내/설명
PAGE_GUIDE = {
    "query_code": """
    1. 분석할 C 함수를 아래 텍스트 창에 입력하세요.
    2. [분석 실행] 버튼을 누르면 자동으로 코드가 AST로 변환·분석됩니다.
    3. 결과로 Top-3 유사 취약점 패턴과 상세 패턴 매칭 리포트가 표시됩니다.
    """,
    "topk_caption": "DB 내에 저장된 가장 높은 유사도를 가진 3개의 함수 패턴 및 상세 비교 결과입니다.",
    "code_caption": "입력된 함수(또는 추출된 코드 블록)의 주요 영역입니다.",
    "signature_caption": "선택한 패턴의 signature, structure 등의 세부 비교 분석 정보입니다."
}

# 테마 색상 등도 여기에!
COLOR_STYLE = {
    "code_block": "#ffe599",
    "topk_block": "#b6d7a8",
    "signature_block": "#cfe2f3"
}