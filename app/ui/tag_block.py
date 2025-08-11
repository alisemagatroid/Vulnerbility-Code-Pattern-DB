# ui/tag_block.py
import json, html
from pathlib import Path
import streamlit as st

# ==== 경로/데이터 ====
BASE_DIR = Path(__file__).parent.parent.parent
DATA_DIR = BASE_DIR / "data"
TAG_DESC_PATH = DATA_DIR / "tag_desc.json"
CSS_PATH = Path(__file__).parent / "tag_tooltip.css"

def _load_tag_desc():
    try:
        with open(TAG_DESC_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

TAG_DESC = _load_tag_desc()

# ui/tag_block.py (교체)
def _inject_css():
    try:
        css = CSS_PATH.read_text(encoding="utf-8")
        # components.html을 쓰면 head에 더 안정적으로 주입되지만, markdown도 충분합니다.
        st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)
    except Exception as e:
        st.warning(f"CSS 주입 실패: {e}")


# ==== 색상/등급 ====
def tag_color_by_weight(weight: float) -> str:
    if weight >= 4.0: return "#E95757"  # 빨강
    if weight >= 3.0: return "#ECAB4A"  # 주황
    if weight >= 2.0: return "#F9D423"  # 노랑
    if weight >= 1.0: return "#A7DD4F"  # 연두
    return "#B0B0B0"                    # 회색

def _weight_class(w) -> str:
    try:
        wf = float(w)
    except (TypeError, ValueError):
        return "w-weak"
    if wf >= 3.0: return "w-strong"
    if wf >= 1.8: return "w-medium"
    return "w-weak"

def _extra_tag_class(tag: str) -> str:
    t = (tag or "").upper()
    cls = []
    if "[CRITICAL]" in t: cls.append("is-critical")
    if t.startswith("[SINK") or "[SINK:" in t: cls.append("is-sink")
    return " ".join(cls)

# ==== chip 생성 ====
def _chip_html(tag: str, weight: float | None = None) -> str:
    desc = TAG_DESC.get(tag, "설명 없음")
    tip_lines = [desc]
    if weight is not None:
        tip_lines.append(f"Weight: {weight:g}")
    tip = html.escape("\n".join(tip_lines))
    label = html.escape(tag)

    bg = tag_color_by_weight(weight or 1.0)      # 배경은 인라인 스타일로
    # 배경 대비용 글자색(간단 계산)
    text_color = "#111" if weight and weight < 3.5 else "#fff"

    classes = f"tag-chip {_weight_class(weight)} {_extra_tag_class(tag)}".strip()
    return (
        f"<span class='{classes}' style='background:{bg};color:{text_color}' "
        f"data-tip='{tip}' title='{html.escape(desc)}'>{label}</span>"
    )

# ==== 공개 API ====
def render_left_panel(query_code: str, tag_cloud1: list, tag_cloud2: list, tag_weight_map: dict = None):
    """
    query_code: code string
    tag_cloud1: 전체 태그 리스트
    tag_cloud2: 중요 태그 리스트
    tag_weight_map: {tag: weight}
    """
    _inject_css()

    st.subheader("Query Code")
    st.code(query_code or "", language="c")

    st.subheader("Tag Cloud")
    tag_weight_map = tag_weight_map or {}
    chips1 = "".join(_chip_html(t, tag_weight_map.get(t, 1.0)) for t in sorted(set(tag_cloud1)))
    st.markdown(f"<div class='tag-chips'>{chips1}</div>", unsafe_allow_html=True)

    st.subheader("Tag Cloud (중요 태그)")
    chips2 = "".join(_chip_html(t, tag_weight_map.get(t, 1.0)) for t in tag_cloud2)
    st.markdown(f"<div class='tag-chips'>{chips2}</div>", unsafe_allow_html=True)
