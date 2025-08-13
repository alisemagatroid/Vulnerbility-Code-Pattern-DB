import streamlit as st
import json, yaml, sys
from pathlib import Path

# Pattern_Viewer.py 최상단 어딘가(렌더 전에)
st.session_state["_active_page"] = "pattern_viewer"

st.set_page_config(page_title="패턴 뷰어", layout="wide")
# ==== BASE경로 세팅 ====
BASE_DIR = Path(__file__).parent.parent.parent

# ==== 각종 디렉토리 경로 세팅 === 
PREREQ_DIR = BASE_DIR / "prerequisite"
DATA_DIR   = BASE_DIR / "data"
UI_DIR = Path(__file__).parent.parent / "ui"
sys.path.insert(0, str(UI_DIR))

from tag_block import render_left_panel
from topk_block import render_mid_panel
from signature_block import render_right_panel

VARIANT_DB_PATH = DATA_DIR / 'variant_db.json'
SIGNATURE_DB_PATH = DATA_DIR / 'signature_db.yaml'
TAG_WEIGHT_PATH = DATA_DIR / 'tag_weight.py'



def import_module_from_file(module_name, filepath):
    import importlib.util
    spec = importlib.util.spec_from_file_location(module_name, filepath)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

st.title("코드 패턴 DB 분석")
st.write("""
1. 분석할 DB 내의 함수를 왼쪽 사이드 바에서 선택하세요.
2. 함수를 선택하면, 자동으로 해당 함수에 대한 Tag, Code Info가 표시됩니다.
3. DB 내의 Top-k 유사 취약점 패턴과 상세 패턴 매칭 리포트가 표시됩니다.
4. 하단의 선택바를 통해 DB내의 함수간의 Signature를 비교한 결과가 우측에 출력됩니다.
""")
report_module = import_module_from_file('report', str(PREREQ_DIR) + '/cwe_similarity_v8_report.py')
tag_weight_module = import_module_from_file('tag_weight', str(TAG_WEIGHT_PATH))
TAG_W = getattr(tag_weight_module, "TAG_W", {})


@st.cache_data
def load_variant_db(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f)
@st.cache_data
def load_signature_db(path):
    with open(path, encoding='utf-8') as f:
        return list(yaml.safe_load_all(f))

variant_db = load_variant_db(VARIANT_DB_PATH)
signature_db = load_signature_db(SIGNATURE_DB_PATH)

# variant_db의 조회를 빠르게 수행하기 위한 index화
if '_variant_index' not in st.session_state:
    st.session_state['_variant_index'] = {v.get('variant_id'): v for v in variant_db}
variant_index = st.session_state['_variant_index']

variant_choices = [f"[{v.get('variant_id')}] {v['meta'].get('file','')}" for v in variant_db]
query_idx = st.sidebar.selectbox(
    'DB 내 함수 선택 (샘플 함수 단위)', list(range(len(variant_choices))),
    format_func=lambda i: variant_choices[i]
)
query_variant = variant_db[query_idx]
top_k = st.sidebar.slider('Top-K 결과', min_value=1, max_value=10, value=3)

selected_func = query_variant.get('meta', {}).get('file', '')  # 함수명 또는 파일명
st.markdown(f"#### 선택한 코드 패턴 함수: `{selected_func}`")
col1, col2, col3 = st.columns([2, 6, 2])

with st.spinner('분석 중...'):
    report = report_module.explainable_search_report(
        query_variant=query_variant,
        variant_db=variant_db,
        signature_yaml=str(SIGNATURE_DB_PATH),
        top_k=top_k
    )


def extract_ui_data(query_variant, report, top_k=1):
    query_code = ""
    # 여기서 critical_blocks의 첫번째 인덱스의 block_code는 전체 코드를 가져온다.
    if "critical_blocks" in query_variant and len(query_variant["critical_blocks"]) >= 1:
        query_code = (query_variant["critical_blocks"][0].get("block_code", []))
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
            sim = cand.get('similarity_breakdown', {})
            hybrid_sim = sim.get('hybrid', 0.0)
            topk_table.append({
                "Rank": idx+1,
                "CWE": db_info.get('cwe_id', ''),
                "Pattern ID": db_info.get('pattern_id', ''),
                "File": db_info.get('file', ''),
                "Description": sig_ref.get('description', ''),
                "Hybrid Similarity": hybrid_sim
            })
            topk_candidates.append(cand)
    return query_code, tags1, tags2, topk_table, topk_candidates, tag_weight_map

# 선택한 DB의 코드를 불러오기 위한 함수
def _extract_code_from_variant(variant: dict) -> str:
    if not variant:
        return ""
    # 1) critical_slices return
    tokens = (variant["critical_slices"][1].get("tokens", []))
    db_critical_slices = "\n".join(tokens)
    return db_critical_slices


query_code, tag_cloud1, tag_cloud2, topk_table, topk_candidates, tag_weight_map = extract_ui_data(query_variant, report, top_k)
if topk_table:
    func_choices = [f"{c['Rank']}. {c['Pattern ID']} ({c['File']})" for c in topk_table]
    selected_k = st.selectbox("TopK Candidate 선택", range(len(func_choices)), format_func=lambda x: func_choices[x])
else:
    selected_k = 0

if topk_candidates:
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

with col1:
    st.markdown("### 🧩 입력 함수/패턴 코드")
    st.info("DB 내에서 선택한 함수의 코드 및 Tag의 정보입니다.")
    render_left_panel(query_code, tag_cloud1, tag_cloud2, tag_weight_map)
with col2:
    st.markdown("### 🏆 TopK 유사 패턴/테이블")
    st.info("선택한 함수를 기준으로, DB 내에 저장된 가장 높은 유사도를 가진 3개의 함수 패턴 및 상세 비교 결과입니다.")
    render_mid_panel(topk_table, sim_breakdown, 3, selected_k)
with col3:
    st.markdown("### 📝 패턴 Signature 및 상세")
    st.info("선택한 패턴의 signature, structure 등의 세부 비교 분석 정보입니다.")
    render_right_panel(signature_info, structure_info, evidence, risk_level, db_code)