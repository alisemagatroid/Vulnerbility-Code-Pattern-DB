import streamlit as st
import pandas as pd

import streamlit as st
import pandas as pd

def render_mid_panel(topk_table: list, sim_breakdown: dict, top_k: int, selected_k: int):
    """
    - topk_table: [{CWE, Pattern ID, Desc, Severity, ...}, ...]
    - sim_breakdown: 예)
        {
          "Embedding": 1.0,
          "TAGs": 0.87,
          "TF-IDF": 0.91,
          "Jaccard": 0.76,
          "Hybrid": 0.93,
          "tag_details": {
              "overlap": {"db_count": M, "matched_count": n, ...}
          }
        }
    """
    st.subheader(f"Top-{top_k} Similar Variants")

    if topk_table:
        df = pd.DataFrame(topk_table)

        def highlight_alternate_rows(row):
            color = '#21242b' if row.name % 2 == 0 else '#383b42'
            return [f'background-color: {color}' for _ in row]

        styler = (
            df.style
              .apply(highlight_alternate_rows, axis=1)
              .set_properties(**{'color': 'white', 'font-size': '16px', 'font-family': 'Inter, sans-serif'})
              .set_table_styles([{'selector': 'thead', 'props': [('background-color', '#282a36'), ('color', '#ffffff'), ('font-size', '18px')]}])
              .hide(axis="index")
        )
        st.markdown(styler.to_html(), unsafe_allow_html=True)
    else:
        st.write("No similar variants found.")

    st.header("Similarity Breakdown")
    st.markdown(f"#### 비교를 위해 선택한 DB내의 함수: `{topk_table[selected_k].get('File','')}`")

    # TAG 겹침 정보(있으면 사용)
    tag_details = sim_breakdown.get("tag_details") or {}
    overlap = tag_details.get("overlap") or {}
    db_count = overlap.get("db_count", 0)
    matched_count = overlap.get("matched_count", 0)

    # 기존 키-값 그대로 돌되, 숫자만 표시 + TAGs 라벨 보강
    for name, score in sim_breakdown.items():
        if not isinstance(score, (int, float)):
            continue  # tag_details 같은 dict는 스킵

        # 0~1 → 0~100 정수 변환
        pct = int(round(max(0.0, min(float(score), 1.0)) * 100))

        # 라벨 구성: TAGs 라인만 "(M개 중 n개 매치)" 추가
        if name in ("TAGs", "tag_one_hot_cosine", "tag_one_hot"):
            if db_count > 0:
                st.write(f"#### {name}: {score:.3f}  ( {db_count}개 중 {matched_count}개 매치 )")
            else:
                st.write(f"#### {name}: {score:.3f}")
        else:
            st.write(f"#### {name}: {score:.3f}")

        st.progress(pct)
