import streamlit as st
import pandas as pd
import tempfile, subprocess, json, sys, traceback, os, shutil, time, random, importlib.util
from pathlib import Path

# Query_code.py 최상단 어딘가(렌더 전에)
st.session_state["_active_page"] = "query_code"

st.set_page_config(page_title="함수 쿼리", layout="wide")

# ==== BASE 경로 세팅 ====
BASE_DIR = Path(__file__).parent.parent.parent
PREREQ_DIR = BASE_DIR / "prerequisite"
DATA_DIR   = BASE_DIR / "data"
UI_DIR = Path(__file__).parent.parent / "ui"

SIGNATURE_DB_PATH = DATA_DIR / 'signature_db.yaml'


TAG_WEIGHT_PATH = DATA_DIR / 'tag_weight.py'
spec = importlib.util.spec_from_file_location("tag_weight", str(TAG_WEIGHT_PATH))
tag_weight_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tag_weight_module)
TAG_W = getattr(tag_weight_module, "TAG_W", {})

# prerequisite 경로 등록
if str(PREREQ_DIR) not in sys.path:
    sys.path.insert(0, str(PREREQ_DIR))
from cwe_similarity_v8_variant_creation import build_variant
from cwe_similarity_v8_report import explainable_search_report
# UI 블록 경로 등록
if str(UI_DIR) not in sys.path:
    sys.path.insert(0, str(UI_DIR))
from tag_block import render_left_panel
from topk_block import render_mid_panel
from signature_block import render_right_panel


# 공통적으로 사용하는 variant_db에 대한 데이터를 캐시데이터 로딩으로 함수화 하여, i/o 개선   
@st.cache_data
def load_variant_db(path):
    with open(path, "r") as f:
        return json.load(f)
variant_db = load_variant_db(DATA_DIR / "variant_db.json")

# variant_db의 조회를 빠르게 수행하기 위한 index화
if '_variant_index' not in st.session_state:
    st.session_state['_variant_index'] = {v.get('variant_id'): v for v in variant_db}
variant_index = st.session_state['_variant_index']


# ==== TEMP DIR 준비 ====
def clear_temp_dir(temp_dir):
    for f in os.listdir(temp_dir):
        try:
            (temp_dir / f).unlink()
        except Exception:
            pass

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

def find_generated_json(temp_dir, c_path):
    json_path = c_path.with_suffix(".json")
    if json_path.exists():
        return json_path
    candidates = sorted(temp_dir.glob("*.json"), key=os.path.getmtime, reverse=True)
    if candidates:
        return candidates[0]
    return None

def get_latest_result_dir(result_root):
    # result_root: Path 객체(C-AST-Generator-main/result)
    candidates = [d for d in result_root.iterdir() if d.is_dir()]
    if not candidates:
        return None
    # 디렉토리명에 timestamp 정보가 있으므로, 최근 것(사전순 마지막) 선택
    latest = sorted(candidates)[-1]
    return latest

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

def extract_ui_data(query_variant, report, top_k=3):
    query_code = ""
    # critical slice, block은 [CRITICAL] 태그를 기반으로 생성이 되기 때문에 해당 Tagging 기준에 준하지 않는 코드는 아직 이 부분이 생성되지 않음
    if "critical_blocks" in query_variant and len(query_variant["critical_blocks"]) >= 1:
        tokens = (query_variant["critical_slices"][1].get("tokens", []))
        query_code = "\n".join(tokens)
    else: 
        query_code = query_variant.get("code", "")
    tags1 = list(set(tag for s in query_variant.get("statement_slices", []) for tag in s.get("tags", [])))
    tag_weight_map = {}
    for tag in tags1:
        w = TAG_W.get(tag, 1.0)
        tag_weight_map[tag] = tag_weight_map.get(tag, 0) + w
    tags2 = [x[0] for x in sorted(tag_weight_map.items(), key=lambda x: x[1], reverse=True)][:5]

    topk_table = []
    topk_candidates = []
    if report and "top_matched_variants" in report and len(report["top_matched_variants"]) > 0:
        for idx, cand in enumerate(report["top_matched_variants"][:top_k]):
            db_info = cand.get('db_variant_info', {})
            sig_ref = cand.get('signature_ref', {})
            # 패턴매치 판정
            match_info = cand.get('signature_pattern_matching', {})
            pattern_match = "🟢 O" if match_info.get('tags_match', False) else "🔴 X"
            sim = cand.get('similarity_breakdown', {})
            hybrid_sim = sim.get('hybrid', 0.0)
            topk_table.append({
                "Rank": idx+1,
                "CWE": db_info.get('cwe_id', ''),
                "Pattern ID": db_info.get('pattern_id', ''),
                "File": db_info.get('file', ''),
                "Description": sig_ref.get('description', ''),
                "Hybrid Similarity": hybrid_sim,
                "Pattern Match": pattern_match   # 새 컬럼
            })
            topk_candidates.append(cand)
            
    return query_code, tags1, tags2, topk_table, topk_candidates, tag_weight_map

# 선택한 DB의 코드를 불러오기 위한 함수
def _extract_code_from_variant(variant: dict) -> str:
    if not variant:
        return ""
    # 1) critical_slices return
    # tokens = (variant["critical_slices"][1].get("tokens", []))
    # db_critical_slices = "\n".join(tokens)
    if "critical_blocks" in variant and len(variant["critical_blocks"]) >= 1:
        db_critical_slices = (variant["critical_blocks"][0].get("block_code", []))
    return db_critical_slices


st.title("함수 쿼리 및 분석")

query_temp_dir = Path(__file__).parent.parent.parent / "temp" / "query_code"
ast_temp_dir   = Path(__file__).parent.parent.parent / "temp" / "ast"
os.makedirs(query_temp_dir, exist_ok=True)
os.makedirs(ast_temp_dir, exist_ok=True)
clear_temp_dir(query_temp_dir)
clear_temp_dir(ast_temp_dir)

st.write("""
1. 분석할 C 함수를 아래 텍스트 창에 입력하세요.
2. [분석 실행] 버튼을 누르면 자동으로 코드가 AST로 변환·분석됩니다.
3. 결과로 Top-3 유사 취약점 패턴과 상세 패턴 매칭 리포트가 표시됩니다.
""")
user_code = st.text_area("분석할 C 함수를 입력하세요.", height=220, help="함수 형태의 c/c++ 코드를 입력하세요"
                        , placeholder="예시:\nvoid FUNC1() \n{\n\tint data;\n\t...\n}")
analyze_clicked = st.button("분석 실행")

if analyze_clicked:
    try:
        # 임시파일, AST 디렉토리 정리
        clear_temp_dir(query_temp_dir)
        clear_temp_dir(ast_temp_dir)

        # (2) 임시 C 파일 생성
        ts = time.strftime("%Y%m%d-%H%M%S")
        rand = random.randint(1000, 9999)
        c_path = query_temp_dir / f"query_{ts}_{rand}.c"
        with open(c_path, "w") as f:
            f.write(user_code)
        st.write(f"임시 C파일: `{c_path.name}` 생성됨.")

        # (3) AST Generator 실행
        st.write("AST 생성 중...")
        result = run_ast_generator(query_temp_dir)
        if result.returncode != 0:
            st.error(f"AST 생성 실패!\n\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")
            st.stop()

        # (4) result 하위 최신 결과 폴더에서 templateTree.json 복사(→ ast_temp_dir)
        generator_dir = Path("/home/devel02/data/C-AST-Generator-main")
        result_root = generator_dir / "result"
        result_dir = get_latest_result_dir(result_root)
        if not result_dir:
            st.error("결과 result 디렉토리를 찾을 수 없습니다.")
            st.stop()
        try:
            ast_json_path = move_template_json(result_dir, ast_temp_dir, c_path)
        except Exception as e:
            st.error(f"templateTree.json 복사 오류: {e}")
            st.stop()

        # (5) 복사된 json 파일 사용
        if not ast_json_path.exists():
            st.error("AST JSON 파일을 찾을 수 없습니다.")
            st.stop()
        with open(ast_json_path) as f:
            ast_json = json.load(f)
        st.write(f"AST 파일: `{ast_json_path.name}` 생성됨.")

        # (6) FunctionDefinition 노드 추출
        func_node = extract_funcdef_from_ast_json(ast_json)

        # (7) variant 생성
        variant = build_variant(
            func_node, 
            cwe_id="Query", pattern_id="Query",
            window=3, src="Query", file_name=ast_json_path.name, desc="입력 함수 분석"
        )

        # (8) report 생성
        report = explainable_search_report(
            variant,
            variant_db=variant_db,
            signature_yaml=str(SIGNATURE_DB_PATH),
            top_k=3
        )

        # 세션에 결과 저장
        st.session_state['query_report'] = report
        st.session_state['query_variant'] = variant

        st.success("분석이 완료되었습니다. 아래에서 TopK 결과 및 상세 분석을 선택/확인할 수 있습니다.")

    except Exception as e:
        st.error(f"전체 파이프라인 오류:\n{traceback.format_exc()}")

# 분석 결과가 세션에 있으면 UI 표시
if 'query_report' in st.session_state and 'query_variant' in st.session_state:
    report = st.session_state['query_report']
    variant = st.session_state['query_variant']

    query_code, tag_cloud1, tag_cloud2, topk_table, topk_candidates, tag_weight_map = \
        extract_ui_data(variant, report, top_k=3)


    if topk_table:
        func_choices = [f"{c['Rank']}. {c['Pattern ID']} ({c['File']})" for c in topk_table]
        selected_k = st.selectbox(
            "TopK Candidate 선택", 
            range(len(func_choices)), 
            format_func=lambda x: func_choices[x], 
            key="query_topk_select"
        )
    else:
        selected_k = 0

    if topk_candidates:
        # cand: topk중 선택된 함수
        cand = topk_candidates[selected_k]
        sim = cand.get('similarity_breakdown', {})
        sim_breakdown = {
            "Embedding": sim.get('embedding', 0.0),
            "TAGs": sim.get('tag_one_hot_cosine', 0.0),
            "TF-IDF": sim.get('tag_tfidf_cosine', 0.0),
            "Jaccard": sim.get('tag_jaccard', 0.0),
            "Hybrid": sim.get('hybrid', 0.0),
            "tag_details": sim.get('tag_details', {})
        }
        sig_ref = cand.get('signature_ref', {})
        signature_info = {
            "Required Tags": sig_ref.get('required_tags', []),
            "Sequence": sig_ref.get('required_sequence', ""),
            "Description": sig_ref.get('description', "")
        }
           
        struct_match = cand.get('signature_pattern_matching', {})
        structure_raw = struct_match.get('block_structure_match', None)
        if isinstance(structure_raw, tuple) and len(structure_raw) == 2:
            overall_match, block_names = structure_raw
            structure_info = [(name, overall_match) for name in block_names]
        elif isinstance(structure_raw, list):
            structure_info = [(f"Block{i+1}", match) for i, match in enumerate(structure_raw)]
        elif isinstance(structure_raw, bool):
            structure_info = [("Overall", structure_raw)]
        else:
            structure_info = []
        evidence = struct_match.get('fail_details', "")
        risk_level = cand.get('risk_level', "")
        try:
            vid = cand.get('db_variant_info', {}).get('variant_id')
            if vid is not None:
                db_variant = variant_index.get(vid)
                db_code = _extract_code_from_variant(db_variant) if db_variant else ""
        except Exception:
            db_code = ""
    else:
        sim_breakdown = {}
        signature_info = {"Required Tags": [], "Sequence": "", "Description": ""}
        structure_info = []
        evidence = ""
        risk_level = ""
        db_code = ""



    col1, col2, col3 = st.columns([2, 6, 2])

    with col1:
        st.markdown("### 🧩 입력 함수/패턴 코드")
        st.info("입력된 함수(또는 추출된 코드 블록)의 주요 영역입니다.")
        render_left_panel(query_code, tag_cloud1, tag_cloud2, tag_weight_map)

    with col2:
        st.markdown("### 🏆 TopK 유사 패턴/테이블")
        st.info("DB 내에 저장된 가장 높은 유사도를 가진 3개의 함수 패턴 및 상세 비교 결과입니다.")
        render_mid_panel(topk_table, sim_breakdown, 3, selected_k)

    with col3:
        st.markdown("### 📝 패턴 Signature 및 상세")
        st.info("선택한 패턴의 signature, structure 등의 세부 비교 분석 정보입니다.")
        render_right_panel(signature_info, structure_info, evidence, risk_level, db_code=db_code)