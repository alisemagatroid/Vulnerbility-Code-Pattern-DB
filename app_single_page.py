import streamlit as st
from pathlib import Path
import importlib.util
import sys, json, yaml


# ==== 경로 세팅 ====
PREREQ_DIR = str(Path(__file__).parent.parent / 'prerequisite')
DATA_DIR = Path(__file__).parent.parent / 'data'
VARIANT_DB_PATH = DATA_DIR / 'variant_db.json'
SIGNATURE_DB_PATH = DATA_DIR / 'signature_db.yaml'

# ==== UI 그리드 배치 ====
st.set_page_config(layout="wide")
st.title("Vulnerable Code Pattern Search Dashboard")



if PREREQ_DIR not in sys.path:
    sys.path.insert(0, PREREQ_DIR)

def import_module_from_file(module_name, filepath):
    spec = importlib.util.spec_from_file_location(module_name, filepath)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

# ==== report.py의 함수 import ====  
report_module = import_module_from_file(
    'report', str(Path(__file__).parent.parent / 'prerequisite' / 'cwe_similarity_v8_report.py')
)

tag_weight_module = import_module_from_file(
    'tag_weight', str(Path(DATA_DIR) / 'tag_weight.py')
)

TAG_W = getattr(tag_weight_module, "TAG_W", {})

# ==== 데이터 로드 ====
@st.cache_data
def load_variant_db(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f)
@st.cache_data
def load_signature_db(path):
    with open(path, encoding='utf-8') as f:
        return list(yaml.safe_load_all(f))

# 블록, statement를 통해 추출한 embedding 벡터를 저장한 json 파일 유사도 매칭에 활용
variant_db = load_variant_db(VARIANT_DB_PATH)

# 각 코드 패턴의 Tag, sequence 정보를 가지고 있으며
signature_db = load_signature_db(SIGNATURE_DB_PATH)

# ==== 쿼리 선택 사이드 바 ====
variant_choices = [f"[{v.get('variant_id')}] {v['meta'].get('file','')}" for v in variant_db]
query_idx = st.sidebar.selectbox(
    'Query Variant 선택 (샘플 함수 단위)', list(range(len(variant_choices))),
    format_func=lambda i: variant_choices[i]
)
query_variant = variant_db[query_idx]
top_k = st.sidebar.slider('Top-K 결과', min_value=1, max_value=10, value=3)

# === Query 선택 후 함수명 출력 ===
selected_func = query_variant.get('meta', {}).get('file', '')  # 함수명 또는 파일명
st.markdown(f"#### Query로 선택한 함수: `{selected_func}`")  # 강조를 위해 백틱 사용
col1, col2, col3 = st.columns([2, 6, 2])


# ==== 유사도 검색/리포트 생성 DB 참조 ====
with st.spinner('분석 중...'):
    # 실제 데이터를 가진 json, 코드 패턴을 정의한 yaml을 동시에 가져와서 report라는 변수로 사용
    report = report_module.explainable_search_report(
        query_variant=query_variant, # slect box에 index에 따라(query) 해당 함수 하나만 가지는 변수
        variant_db=variant_db, # variant_db.json 전체의 데이터를 가져온다
        signature_yaml=str(SIGNATURE_DB_PATH), # 화면에 출력할 코드 패턴 설명 및 태그 등의 정보를 담은 Signature_db.yaml을 가져온다.
        top_k=top_k
    )

# ==== 블록별 모듈 import ====
from ui.tag_block import render_left_panel
from ui.topk_block import render_mid_panel
from ui.signature_block import render_right_panel

# ==== 리포트/데이터 가공 ====
def extract_ui_data(query_variant, report, top_k=1):
    # 좌측 패널
    query_code = ""
    if "critical_slices" in query_variant and len(query_variant["critical_slices"]) >= 2:
        # 2번째 critical_slices의 tokens 전체를 줄바꿈으로 합쳐 출력
        query_code = "\n".join(query_variant["critical_slices"][1].get("tokens", []))
    else:
        # fallback: code 필드나 tokens 필드 등
        query_code = query_variant.get("code", "")
    tags1 = list(set(tag for s in query_variant.get("statement_slices", []) for tag in s.get("tags", [])))
    TAG_W = globals().get("TAG_W", {})
    tag_weight_map = {}
    for tag in tags1:
        w = TAG_W.get(tag, 1.0)
        tag_weight_map[tag] = tag_weight_map.get(tag, 0) + w
    tags2 = [x[0] for x in sorted(tag_weight_map.items(), key=lambda x: x[1], reverse=True)][:5]

    # 중앙 패널: TopK
    # 중앙 패널/TopK 후보 전체 리스트
    topk_table = []
    topk_candidates = []
    if report and "top_matched_variants" in report and len(report["top_matched_variants"]) > 0:
        for idx, cand in enumerate(report["top_matched_variants"][:top_k]):
            db_info = cand.get('db_variant_info', {})
            sig_ref = cand.get('signature_ref', {})
            topk_table.append({
                "Rank": idx+1,
                "CWE": db_info.get('cwe_id', ''),
                "Pattern ID": db_info.get('pattern_id', ''),
                "File": db_info.get('file', ''),
                "Description": sig_ref.get('description', '')
            })
            topk_candidates.append(cand)
    
    # topk_table,
    return query_code, tags1, tags2, topk_table, topk_candidates, tag_weight_map

# 실제로는 아래처럼 사용
query_code, tag_cloud1, tag_cloud2, topk_table, topk_candidates, tag_weight_map = extract_ui_data(query_variant, report, top_k)

# 후보 선택 selectbox (선택 UI)
if topk_table:
    func_choices = [f"{c['Rank']}. {c['Pattern ID']} ({c['File']})" for c in topk_table]
    selected_k = st.selectbox("TopK Candidate 선택", range(len(func_choices)), format_func=lambda x: func_choices[x])
else:
    selected_k = 0

# 선택된 후보 상세 추출
if topk_candidates:
    cand = topk_candidates[selected_k]
    # 중앙 패널 Breakdown
    sim = cand.get('similarity_breakdown', {})
    sim_breakdown = {
        "Embedding": sim.get('embedding', 0.0),
        "TAGs": sim.get('tag_one_hot_cosine', 0.0),
        "TF-IDF": sim.get('tag_tfidf_cosine', 0.0),
        "Hybrid": sim.get('hybrid', 0.0)
    }
    # Signature/Structure Info
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
else:
    sim_breakdown = {}
    signature_info = {"Required Tags": [], "Sequence": "", "Description": ""}
    structure_info = []
    evidence = ""
    risk_level = ""

with col1:
    render_left_panel(query_code, tag_cloud1, tag_cloud2, tag_weight_map)
with col2:
    render_mid_panel(topk_table, sim_breakdown, top_k, selected_k)
with col3:
    render_right_panel(signature_info, structure_info, evidence, risk_level)
