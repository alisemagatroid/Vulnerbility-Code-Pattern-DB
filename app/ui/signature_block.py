# ui/right_panel.py
import streamlit as st

# yaml 상의 signature 내부의 부분을 string으로 변환해주는 함수
def tag_display_string(tag_item):
    # tag_item: str or dict (예: {'or': [ ... ]})
    if isinstance(tag_item, dict):
        if "or" in tag_item:
            return " or ".join(tag_item["or"])
        elif "and" in tag_item:
            return " and ".join(tag_item["and"])
        else:
            # 기타 dict 조건은 str로 변환
            return str(tag_item)
    return str(tag_item)


def render_right_panel(signature_info: dict, structure_info: list, evidence: dict, risk_level: str):
    st.subheader("Signature Match")
    # Required Tags
    req_tags = signature_info.get('Required Tags', [])
    req_tags_str = []
    for tag in req_tags:
        if isinstance(tag, dict) and 'or' in tag:
            tag_str = " | ".join(tag['or'])
        else:
            tag_str = tag
        req_tags_str.append(f"**{tag_str}**")
    st.markdown("#### Required Tags: " )
    st.markdown(" ".join(req_tags_str))
    # Sequence
    req_seq = signature_info.get('Sequence', [])
    seq_tags_str = []
    if isinstance(req_seq, (list, tuple)):
        for tag in req_seq:
            if isinstance(tag, dict) and 'or' in tag:
                tag_str = " | ".join(tag['or'])
            else:
                tag_str = tag
            seq_tags_str.append(f"**{tag_str}**")
        st.markdown("#### Sequence Tags: " )
        st.markdown(" ".join(seq_tags_str), unsafe_allow_html=True)
    else:
        st.markdown("**Sequence:**")

    st.markdown("#### Structure:")
    # TAG가 매치되는 Block이 있으면, 해당 Block의 인덱스와 함께 출력
    st.write(" | ".join([f"{name}: {'🟩' if match else '⬜'}" for name, match in structure_info]))

    # === Critical evidence: Missing required_tags / sequence만 출력 ===
    reasons = evidence.get('fail_reason', []) if isinstance(evidence, dict) else []
    tags_reason = [r for r in reasons if r.startswith("Missing required_tags")]
    seq_reason = [r for r in reasons if r.startswith("Missing required_sequence")]

    st.markdown("#### Critical evidence (Missing Signature Only):")
    if not tags_reason and not seq_reason:
        st.markdown("- (No missing tags/sequence)")
    for r in tags_reason:
        st.markdown(f"<span style='color:#D9534F;font-weight:bold'>{r}</span>", unsafe_allow_html=True)
    for r in seq_reason:
        st.markdown(f"<span style='color:#f0ad4e;font-weight:bold'>{r}</span>", unsafe_allow_html=True)

    color = {"High": "red", "Medium": "#ECAB4A", "Low": "green"}.get(risk_level, "gray")
    st.markdown(f"**Structure Similarity:** <span style='color:{color}; font-weight:bold'>{risk_level}</span>", unsafe_allow_html=True)
