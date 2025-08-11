import streamlit as st

st.set_page_config(page_title="취약점 패턴 검색 대시보드", layout="wide")

st.title("취약점 패턴 검색 대시보드")

st.write("#### 좌측 사이드 바 메뉴에서 원하는 페이지를 선택하세요")

st.markdown("""
- **app** : 메인 화면으로 돌아옵니다.           
- **Pattern Viewer** : Variant DB에 등록된 함수 및 패턴을 조회하고, 상세 분석 결과를 볼 수 있습니다.
- **Query Code** : 임의의 C/C++ 코드를 입력하면, 내부적으로 AST 파서와 변환을 거쳐 Variant DB와 동일하게 분석 결과를 제공합니다.
""")
