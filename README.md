네, README를 구조적으로 깔끔하게 정리하면서
아직 utils 분리/리팩토링을 **적용 중인 단계임을 명확히 안내**하고
**전체 폴더 구조, 주요 모듈 설명, 사용법, 리팩토링 상태**도 모두 포함하는
최신 실무형 README 예시를 아래에 제시합니다.

---

# 📖 README.md 예시

(*Streamlit CWE/패턴 분석 프로젝트 기준*)

---

## 🔥 프로젝트 개요

본 프로젝트는 **C/C++ 함수 기반 취약점 패턴 분석 및 검색 시스템**입니다.

* Streamlit 기반 대시보드(UI)에서 코드 패턴 탐색, 임의 코드 분석, 패턴 매칭 리포트 등 제공
* 외부 AST 파서(C-AST-GENERATOR)와 연동, 분석 파이프라인 구현
* Variant DB/Signature DB 기반 유사도 분석, TopK 매칭 결과 제공
* **Python 3.11+**, Streamlit, pandas, st-aggrid 등 사용

---

## 📂 폴더/파일 구조

```
signature_vul_db/
├── .gitignore
├── README.md
├── app/
│   ├── app.py                # Streamlit 메인 앱
│   └── pages/
│       ├── Pattern_Viewer.py # DB 기반 패턴 탐색 페이지
│       └── Query_code.py     # 코드 입력/분석 페이지
│   └── ui/
│       ├── tag_block.py      # 태그/워드클라우드 등 UI 블록
│       ├── topk_block.py     # TopK 유사도 UI 블록
│       └── signature_block.py# 패턴 시그니처/상세 UI 블록
├── data/
│   ├── signature_db.yaml     # 패턴 시그니처/설명 DB
│   ├── tag_weight.py         # 태그 가중치 사전
│   └── query_variant.json    # 예시 입력/분석 variant
├── prerequisite/
│   ├── cwe_similarity_v8_variant_creation.py # variant 생성 로직
│   └── cwe_similarity_v8_report.py           # 패턴 매칭/리포트 생성
├── utils/
│   ├── config.py             # 경로/설명/컬러 등 공통 상수/설정
│   ├── ast_utils.py          # AST 파서, 임시파일/이동, 함수추출 등
│   ├── io_utils.py           # 파일 입출력, 임시파일 클리어 등
│   └── data_utils.py         # UI/데이터 가공, 태그 정리 등
├── temp/                     # 입력코드, AST 임시파일 (git 제외)
├── output/                   # 분석 산출물 (git 제외)
└── C-AST-GENERATOR-main/     # 외부 AST 파서(js/ts), git 제외
```

---

## 🚦 주요 기능

* **DB 기반 패턴 탐색:**

  * 등록된 함수/패턴 검색, 상세 구조/태그/시그니처 분석
* **코드 직접 분석(Query Code):**

  * C/C++ 함수 입력 → AST 변환 → Variant 생성 → DB 패턴과 TopK 유사도 비교/리포트 제공
* **리포트/테이블/워드클라우드 등 시각화**
* **utils 모듈 분리/리팩토링 적용 중**

  * *일부 로직(app/pages 등)에서 utils 함수 사용 방식이 아직 미완성/이관 중일 수 있음*

---

## 🛠️ 설치 및 실행

1. **(Python 3.11+ 가상환경 권장)**

   ```bash
   python3.11 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Node, npm 설치** (C-AST-GENERATOR 사용 시 필요)

3. **Streamlit 실행**

   ```bash
   streamlit run app/app.py
   ```

---

## ⚙️ 주요 의존성

* `streamlit`
* `pandas`
* `st-aggrid`
* `pyyaml`
* 기타: (requirements.txt 참고)

---

## 📝 리팩토링/구현 현황

* **utils 모듈 분리 진행 중**

  * `utils/ast_utils.py`, `data_utils.py`, `io_utils.py`, `config.py` 등 생성
  * 일부 로직(app/pages/Query\_code.py 등)에서 *기존 직접 구현과 utils 함수 혼재 사용*
    → *점진적으로 통일/리팩토링 중*
* **외부 파서(C-AST-GENERATOR)는 git 추적에서 완전 제외**

  * `.gitignore`로 전체 폴더 무시, 필요 파일만 사용
* **data/ 폴더는 전체 제외, signature\_db.yaml/tag\_weight.py 등만 예외 포함**

---

## ⚠️ 주의사항

* **외부 AST 파서(C-AST-GENERATOR-main)는 오픈소스/사내 별도 관리!**
  → 리포에 올리지 않고 로컬에서만 사용
* **임시파일, output, temp, data 등 대용량/민감/생성 파일은 git에 올라가지 않음**
  → 필요시 `.gitignore` 예외 확인
* **아직 전체 코드/유틸 일원화가 완료된 상태는 아니며,
  실험적 리팩토링과 신규 함수 반영을 지속 중**
  → 코드 구조가 수시로 변경될 수 있음

---

## 💡 기타/협업

* `README.md`, 주석, 함수 docstring 등으로 **구현 현황, utils 적용 범위** 주기적 공유 필요
* 추가 문의/이슈는 github issue 또는 사내 Slack 등 협업 채널 이용

---

## 🔗 참고

* [Streamlit 공식문서](https://docs.streamlit.io/)
* [st-aggrid 문서](https://pypi.org/project/streamlit-aggrid/)
* [PyYAML](https://pyyaml.org/)
* [Git submodule 안내](https://git-scm.com/book/ko/v2/Git-도구-서브모듈)
