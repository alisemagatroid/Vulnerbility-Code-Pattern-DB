# Vulnerable Code Pattern Search Dashboard

AI 기반 코드 취약점 유형/패턴 검색 및 유사도 대시보드

---

## 📁 프로젝트 구조
.
├── app/
│ ├── app.py # Streamlit 메인 실행(전체 데이터 로딩/UI 분배)
│ └── ui/
│ ├── signature_block.py # 우측 Signature 상세 패널
│ ├── tag_block.py # 좌측 Tag Cloud/Query 코드 패널
│ └── topk_block.py # 중앙 Top-K 유사 함수/유사도 패널
├── data/
│ ├── variant_db.json # 함수/패턴별 임베딩/블록/태그 등 DB
│ ├── query_variant.json # (테스트용) 단일 쿼리 함수 데이터
│ ├── signature_db.yaml # 패턴별 설명/필수 태그/시퀀스 등 시그니처 DB
│ └── tag_weight.py # 태그별 위험도 가중치(dict)
├── output/ # (추가) 분석 결과/리포트 저장
└── prerequisite/
├── cwe_similarity_v8_report.py # DB+시그니처+리포트 생성(핵심)
└── cwe_similarity_v8_variant_creation.py # DB/시그니처/태그 등 생성 유틸리티

---

## 🚦 실행/사용 방법

1. **데이터 준비**
   - `/data/variant_db.json`, `/data/signature_db.yaml`, `/data/tag_weight.py` 등 최신화

2. **대시보드 실행**
   - `streamlit run app/app.py`