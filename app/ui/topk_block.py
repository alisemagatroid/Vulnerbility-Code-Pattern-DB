import streamlit as st
import pandas as pd

def render_mid_panel(topk_table: list, sim_breakdown: dict, top_k: int, selected_k: int):
    """
    - topk_table: [{CWE, Pattern ID, Desc, Severity}, ...]
    - sim_breakdown: {"Hybrid": float, "Embedding": float, ...}
    """
    st.subheader(f"Top-{top_k} Similar Variants")
    if topk_table:
        # 리스트(dict) → DataFrame 변환
        df = pd.DataFrame(topk_table)

        # 스타일 적용 함수
        def highlight_alternate_rows(row):
            color = '#21242b' if row.name % 2 == 0 else '#383b42'
            return ['background-color: {}'.format(color) for _ in row]

        styler = df.style.apply(highlight_alternate_rows, axis=1)\
            .set_properties(**{'color': 'white', 'font-size': '16px', 'font-family': 'Inter, sans-serif'})\
            .set_table_styles([
                {'selector': 'thead', 'props': [('background-color', '#282a36'), ('color', '#ffffff'), ('font-size', '18px')]},
            ])\
                .hide(axis="index")
        # HTML로 렌더링
        st.markdown(styler.to_html(), unsafe_allow_html=True)
    else:
        st.write("No similar variants found.")
    st.header(f"Similarity Breakdown")
    st.markdown(f"#### 비교를 위해 선택한 DB내의 함수: `{topk_table[selected_k].get('File','')}`") 
    for name, score in sim_breakdown.items():
        st.write(f"#### {name}: {score}")
        st.progress(score)