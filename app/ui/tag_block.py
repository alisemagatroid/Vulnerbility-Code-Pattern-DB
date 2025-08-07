# ui/left_panel.py
import streamlit as st

def tag_color_by_weight(weight):
    # 주요 구간별 색상 선택
    if weight >= 4.0:
        return "#E95757"
    elif weight >= 3.0:
        return "#ECAB4A"
    elif weight >= 2.0:
        return "#F9D423"  # 노랑-주황 사이
    elif weight >= 1.0:
        return "#A7DD4F"  # 연두 등
    else:
        return "#B0B0B0"  # 회색


def render_left_panel(query_code: str, tag_cloud1: list, tag_cloud2: list, tag_weight_map: dict = None):
    
    # print(tag_weight_map)
    
    st.subheader("Query Code")
    print(query_code)
    st.code(query_code, language="c")

    st.subheader("Tag Cloud")
    # tag_weight_map이 있을 경우 가중치 기반 강조
    tag_htmls = []
    for tag in tag_cloud1:
        weight = tag_weight_map.get(tag, 1.0) if tag_weight_map else 1.0
        color = tag_color_by_weight(weight)
        tag_htmls.append(f"<span style='background-color:{color}; color:black; padding:2px 7px; border-radius:4px; margin:2px; font-size:14px'>{tag}</span>")
    st.markdown(" ".join(tag_htmls), unsafe_allow_html=True)
    st.markdown(" ")

    st.subheader("Tag Cloud (중요 태그)")
    tag2_htmls = []
    for tag in tag_cloud2:
        weight = tag_weight_map.get(tag, 1.0) if tag_weight_map else 1.0
        color = tag_color_by_weight(weight)
        font_weight = "bold" if weight >= 4.0 else "normal"
        tag2_htmls.append(f"<span style='color:{color}; font-weight:{font_weight}; font-size:18px'>{tag}</span>")
    st.markdown(" ".join(tag2_htmls), unsafe_allow_html=True)


