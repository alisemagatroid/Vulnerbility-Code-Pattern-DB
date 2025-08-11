# UI 화면상에서 보여질 데이터들을 만들어주는 코드

import numpy as np
import yaml
from collections import Counter
from sklearn.metrics.pairwise import cosine_similarity

QUERY_VARIANT = "/home/devel02/ast/ast_dir/vulnerability_DB/code/signature_vul_db/data/query_variant.json"
VARIANT_DB = "/home/devel02/ast/ast_dir/vulnerability_DB/code/signature_vul_db/data/variant_db.json"
SIG_DB_YAML = "/home/devel02/ast/ast_dir/vulnerability_DB/code/signature_vul_db/data/signature_db.yaml"

# 1. TAG를 one-hot 벡터의 인덱스로 변환하기 위한 TAG 인덱스 맵(tag_to_idx) 생성 함수
#  "전체 TAG 집합을 고정된 인덱스 벡터 공간에 맵핑해주는 TAG→벡터인덱스 변환 사전(dictionary) 생성
#
# 반환값 예시
# {
#  "[SOURCE]": 0,
#  "[SINK]": 1,
#  "[VALIDATION]": 2,
#  "[UNVALIDATED]": 3,
#  ...
# 이 딕셔너리는 태그를 숫자 인덱스로 변환하는 데 사용됨 (예: one-hot encoding, embedding, 분류 등)
#


def build_tag_to_idx(*variant_dicts):
    all_tags = set()
    for vdict in variant_dicts:
        for s in vdict.get("statement_slices", []):
            all_tags.update(s.get("tags", []))

        for b in vdict.get("blocks", []):
            all_tags.update(b.get("tags", []))
    tag_list = sorted(all_tags)
    return {tag: idx for idx, tag in enumerate(tag_list)}

# TF-IDF 벡터라이저 빌더
# "TAG들의 희소성/중요도까지 고려해서 각 코드조각을 수치 벡터(TF-IDF)로 만들어 유사도 계산에 활용하는 함수!


def build_tag_tfidf_vectorizer(variant_db, query_variant=None):
    from sklearn.feature_extraction.text import TfidfVectorizer
    all_variants = variant_db[:]
    if query_variant is not None:
        all_variants = [query_variant] + all_variants
    corpus = [" ".join(t for s in v["statement_slices"] for t in s.get("tags", []))
              for v in all_variants]
    vectorizer = TfidfVectorizer(token_pattern=r"\[.*?\]")
    X = vectorizer.fit_transform(corpus)
    return vectorizer, X


# 2. 벡터 유사도
def cosine_sim(vec1, vec2):
    if np.linalg.norm(vec1) == 0 or np.linalg.norm(vec2) == 0:
        return 0.0
    return float(cosine_similarity([vec1], [vec2])[0, 0])

# 3. 슬라이스/블록 매칭
# 각 쿼리 구간별로 best match인(가장 유사한 sim을 가진) DB 구간의 태그, 임베딩 유사도를 구한다.


def match_units(query_units, sig_units, tag_to_idx, is_block=False, top_k=2):

    matches = []
    for q in query_units:   # 쿼리 구간(statement/block)별로 루프
        qvec = np.zeros(len(tag_to_idx))
        for tag in q.get("tags", []):
            if tag in tag_to_idx:
                qvec[tag_to_idx[tag]] = 1

        # 쿼리 슬라이스/블록의 임베딩
        q_embedding = np.array(q.get("embedding", []))

        # 각 Variant DB 시그니처의 슬라이스/블록과 비교
        best_sim, best_sig, best_tags, best_embedding_sim = 0, None, [], 0

        for s in sig_units:  # 시그니처의 모든 구간과 비교
            svec = np.zeros(len(tag_to_idx))

            for tag in s.get("tags", []):
                if tag in tag_to_idx:
                    svec[tag_to_idx[tag]] = 1

            # TAG(tag_to_idx) 기반 코사인 유사도
            sim = cosine_sim(qvec, svec)

            # 임베딩 기반 코사인 유사도
            s_embedding = np.array(s.get("embedding", []))
            if len(q_embedding) == len(s_embedding) and len(q_embedding) > 0:
                emb_sim = cosine_sim(q_embedding, s_embedding)
            else:
                emb_sim = None

            # 최상위 TAG 기반 매칭(임베딩이 아닌 TAG 기반으로 가장 높은 유사도 비교)
            if sim > best_sim:
                best_sim, best_sig, best_tags, best_embedding_sim = sim, s, s.get(
                    "tags", []), emb_sim

        if is_block:
            result = {
                "query_block": q.get("block_code", ""),
                "db_varinat_block": best_sig.get("block_code", "") if best_sig else "",
                "similarity": round(best_sim, 2),
                "embedding_similarity": round(best_embedding_sim, 2) if best_embedding_sim is not None else None,
                "matched_tags": list(set(q.get("tags", [])) & set(best_tags)),
                "missing_tags": list(set(best_tags) - set(q.get("tags", []))),
                "extra_tags": list(set(q.get("tags", [])) - set(best_tags)),
            }
        else:
            result = {
                "query_slice": q.get("tokens", ""),
                "db_variant_slice": best_sig.get("tokens", "") if best_sig else "",
                "similarity": round(best_sim, 2),
                "embedding_similarity": round(best_embedding_sim, 2) if best_embedding_sim is not None else None,
                "matched_tags": list(set(q.get("tags", [])) & set(best_tags)),
                "missing_tags": list(set(best_tags) - set(q.get("tags", []))),
                "extra_tags": list(set(q.get("tags", [])) - set(best_tags)),
            }

        # 각 쿼리 구간별로 "가장 유사한" 시그니처 구간(best_sig)만 추가
        matches.append(result)

    return matches[:top_k]

# 4. Critical Evidence 추출 (예시: STRUCT_OVERRUN)


def get_db_critical_evidence(db_variant):
    # DB/시그니처에서 critical_evidence 필드를 읽어서 리스트로 반환
    return db_variant.get("critical_evidence", [])


# Critical Evidence를 빈값을 리턴할 수 밖에 없는 데이터구조이기에, 이부분은 작동을 하지 않음
def match_critical_evidence(query_variant, db_variant, level="tag"):
    """
    level:
      - "tag"  : evidence_tags 기준만 비교 (CWE 패턴 탐지)
      - "code" : evidence_slice(코드문)까지 완전 일치 필요 (CVE/패치 검증용)
    """
    # 근데 이미, critical_evidence는 값이 빈 str이다.
    db_critical_evidence = get_db_critical_evidence(db_variant)

    matched_evidence = []

    # 1. 태그 집합 준비
    if level == "tag":
        query_tags_set = [set(s.get("tags", []))
                          for s in query_variant.get("statement_slices", [])]

    # 2. 코드 조각 집합 준비
    elif level == "code":
        query_slices = [s.get("code")
                        for s in query_variant.get("statement_slices", [])]
    else:
        raise ValueError(f"Unknown level: {level}")

    for idx, evidence in enumerate(db_critical_evidence):
        evidence_tags_set = set(evidence.get("evidence_tags", []))
        evidence_code_slices = evidence.get("evidence_slice", [])

        # "tag" 모드: 태그 완전 포함만 확인
        if level == "tag":
            for i, qtags in enumerate(query_tags_set):
                if evidence_tags_set and evidence_tags_set.issubset(qtags):
                    matched_evidence.append({
                        "evidence_type": evidence.get("evidence_type"),
                        "evidence_tag": evidence_code_slices,
                        "explanation": evidence.get("explanation"),
                        "query_slice": query_variant["statement_slices"][i].get("code", ""),
                        "matched_tags": list(evidence_tags_set)
                    })
        # "code" 모드: 코드(문자열)까지 완전 일치 필요
        elif level == "code":
            # evidence_slice가 여러 줄일 수 있음
            for i, qs in enumerate(query_slices):
                # 둘 다 리스트인 경우
                if isinstance(evidence_code_slices, list):
                    if qs in evidence_code_slices:
                        matched_evidence.append({
                            "evidence_type": evidence.get("evidence_type"),
                            "evidence_slice": evidence_code_slices,
                            "explanation": evidence.get("explanation"),
                            "query_slice": qs,
                            "matched_tags": evidence_tags_set
                        })
                else:
                    # evidence_code_slices가 단일 문자열일 경우
                    if qs == evidence_code_slices:
                        matched_evidence.append({
                            "evidence_type": evidence.get("evidence_type"),
                            "evidence_slice": evidence_code_slices,
                            "explanation": evidence.get("explanation"),
                            "query_slice": qs,
                            "matched_tags": evidence_tags_set
                        })
    return matched_evidence


# 5. TAG 차이 요약
def tag_diff_summary(query_tags, sig_tags):
    all_tags = set(query_tags) | set(sig_tags)
    summary = []
    for tag in all_tags:
        if tag in query_tags and tag in sig_tags:
            summary.append(
                {"tag": tag, "status": "match", "explanation": "둘 다 존재"})
        elif tag in query_tags:
            summary.append({"tag": tag, "status": "query_only",
                           "explanation": "Query에만 존재"})
        else:
            summary.append(
                {"tag": tag, "status": "signature_only", "explanation": "시그니처에만 존재"})
    return summary

# 6. Penalty 정책


def calc_penalty(emb_sim: float,
                 critical_total: int,
                 matched_total: int,
                 *,
                 full_miss_penalty: float = 0.25,
                 partial_coef: float = 0.10,
                 emb_floor: float = 0.3) -> float:
    """
    ▸ emb_sim              : 임베딩 기반(또는 hybrid) 유사도
    ▸ critical_total       : DB critical evidence 총 개수
    ▸ matched_total        : 매칭된 개수
    ▸ full_miss_penalty    : 완전 누락 시 최대 감점(기본 0.25)
    ▸ partial_coef         : 누락비율에 곱할 계수
    ▸ emb_floor            : emb_sim 이 이 값보다 낮으면 패널티 비율 완화
    """
    if critical_total == 0:
        return 0.0

    miss_ratio = (critical_total - matched_total) / critical_total

    if miss_ratio == 0:
        return 0.0                    # 100 % 일치
    elif miss_ratio == 1:
        penalty = -full_miss_penalty  # 전부 누락
    else:
        penalty = -partial_coef * miss_ratio

    # 유사도가 낮으면 패널티 절반만 적용 (이미 낮으므로)
    if emb_sim < emb_floor:
        penalty *= 0.5

    return penalty


def count_unique_evidence_matches(matches, db_critical_evidence):
    # evidence_tags 또는 evidence_slice로 unique 판별
    unique_keys = set()
    for m in matches:
        # evidence_tags tuple 또는 evidence_slice tuple로 key 생성
        if "matched_tags" in m:
            key = tuple(sorted(m["matched_tags"]))
        elif "evidence_slice" in m:
            key = tuple(m["evidence_slice"])
        else:
            key = str(m)
        unique_keys.add(key)
    return len(unique_keys)

# 7. YAML signature pattern 로드/매칭


def load_signature_patterns(yaml_path):
    with open(yaml_path, encoding="utf-8") as f:
        patterns = yaml.safe_load(f)
    return {p["pattern_id"]: p for p in patterns}


def tag_rule_match(query_tags, rule_entry):
    """
    query_tags: set 또는 list (query 또는 pattern의 tag)
    rule_entry: str, 또는 dict {"or": [...]} 또는 {"in": [...]}
    """
    if isinstance(rule_entry, str):
        # 단일 태그는 prefix 매칭 (e.g., "[SINK:ARRAY")
        return any(tag.startswith(rule_entry.rstrip("]")) for tag in query_tags)
    elif isinstance(rule_entry, dict):
        if "or" in rule_entry:
            # OR 조건: 하나라도 match면 True
            return any(tag_rule_match(query_tags, sub) for sub in rule_entry["or"])
        elif "in" in rule_entry:
            # IN 조건: 모두 순서대로 포함
            cur = query_tags
            for sub in rule_entry["in"]:
                if not tag_rule_match(cur, sub):
                    return False
            return True
    return False


def block_structure_rule_match(blocks, rule_entry, level=0, parent_idxs=None, debugMode=False):
    """
    blocks: variant의 block 리스트 [{"block_type", "idx", ...}, ...]
    rule_entry: str, dict("or" or "in"), 혹은 list
    parent_idxs: None or [idx 리스트], 현재 계층에서 탐색 중인 parent idx 집합
    """
    block_infos = [f"{b['idx']}:{b['block_type']}" for b in blocks]
    block_types = [b["block_type"] for b in blocks]  # 리스트로
    prefix = "  " * level  # for indentation

    if debugMode:
        print(
            f"{prefix}[DEBUG] Rule: {rule_entry} / Block Types: {block_infos}")

    def _is_tag_string(s: str) -> bool:
        return isinstance(s, str) and s.startswith('[') and s.endswith(']')

    # 1. 단일 타입이면 (최상위 레벨에서만) 존재 여부
    if isinstance(rule_entry, str):
       # 문자열 규칙: 태그인지 구조블록인지 구분
        if rule_entry.startswith('[') and rule_entry.endswith(']'):
            if debugMode:
                print(f"{prefix}[DEBUG] TAG Entry: {rule_entry['or']}")
            tag = rule_entry
            found_idxs = [
                b["idx"] for b in blocks
                if tag in b.get("tags", []) and
                (parent_idxs is None or any(str(b["idx"]).startswith(
                    f"{pid}.") for pid in parent_idxs))
            ]
            return bool(found_idxs), found_idxs

        if parent_idxs is None:
            found_idxs = [b["idx"]
                          for b in blocks if b["block_type"] == rule_entry]
            found = bool(found_idxs)
        else:
            found_idxs = [
                b["idx"] for b in blocks
                for pid in parent_idxs
                if str(b["idx"]).startswith(str(pid)+".") and b["block_type"] == rule_entry
            ]
            found = bool(found_idxs)

        if debugMode:
            print(f"{prefix}[DEBUG] '{rule_entry}' FOUND: {found_idxs}")
        return found, found_idxs

    # 2. OR 연산
    elif isinstance(rule_entry, dict) and "or" in rule_entry:
        if debugMode:
            print(f"{prefix}[DEBUG] OR block: {rule_entry['or']}")
        for sub in rule_entry["or"]:
            ok, idxs = block_structure_rule_match(
                blocks, sub, level+1, parent_idxs=parent_idxs)
            if ok:
                if debugMode:
                    print(
                        f"{prefix}[DEBUG] OR result: True (matched: {sub} with idxs: {idxs})")
                return True, idxs
        if debugMode:
            print(f"{prefix}[DEBUG] OR result: False")
        return False, []

    # 3. IN (계층적) 연산: e.g., {in: [A, B, C]} → A→B→C로 내려가는 체인
    elif isinstance(rule_entry, dict) and "in" in rule_entry:
        chain = rule_entry["in"]
        if parent_idxs is None:
            # root부터: parent 후보들 모두 돌면서 하나라도 full chain 만족하면 True
            all_parent_idxs = [b["idx"]
                               for b in blocks if b["block_type"] == chain[0]]
            for pid in all_parent_idxs:
                ok, idxs = block_structure_rule_match(
                    blocks, {"in": chain}, level+1, parent_idxs=[pid], debugMode=debugMode)
                if ok:
                    return True, idxs
            return False, []
        else:
            if not parent_idxs:
                return False, []
            if len(chain) == 1:
                if debugMode:
                    print(
                        f"{prefix}[DEBUG] End of chain, found parent_idxs={parent_idxs}")
                return True, parent_idxs
            # 여기 아래는 len(chain) >= 2일 때만 실행되어야 함!
            next_type = chain[1]
            next_idxs = []
            for pid in parent_idxs:
                pstr = str(pid) + "."
                for b in blocks:
                    if str(b["idx"]).startswith(pstr):
                        # TAG인지, 블록타입인지 분기!
                        if (isinstance(next_type, str) and next_type.startswith("[") and next_type.endswith("]")):
                            if next_type in b.get("tags", []):
                                if debugMode:
                                    print(
                                        f"{prefix}[DEBUG] TAG MATCH: {b['idx']} has {next_type}")
                                next_idxs.append(b["idx"])
                        elif b["block_type"] == next_type:
                            next_idxs.append(b["idx"])
            if not next_idxs:
                return False, []
            if len(chain) == 1:
                return True, next_idxs
            return block_structure_rule_match(blocks, {"in": chain[1:]}, level+1, parent_idxs=next_idxs, debugMode=debugMode)

    # 4. AND 연산: 모든 조건 만족해야 함
    elif isinstance(rule_entry, list):
        if debugMode:
            print(f"{prefix}[DEBUG] AND block: {rule_entry}")
        ok, parent_idxs = block_structure_rule_match(
            blocks, rule_entry[0], level+1, parent_idxs=parent_idxs, debugMode=debugMode)
        if not ok:
            if debugMode:
                print(f"{prefix}[DEBUG] AND result: False (first condition)")
            return False, []
        for sub in rule_entry[1:]:
            ok, parent_idxs = block_structure_rule_match(
                blocks, sub, level+1, parent_idxs=parent_idxs, debugMode=debugMode)
            if not ok:
                return False, []
        return True, parent_idxs

    if debugMode:
        print(f"{prefix}[DEBUG] Unmatched type for rule_entry: {rule_entry}")

    return False


# pid에 매칭되는 패턴의 'signature'에 접근
# signature에는 required_tag,
def signature_pattern_match(query_variant, signature_pattern, debugMode=False):
    """
    query_variant: dict (쿼리 variant)
    pattern_signature: dict (SignatureDB의 signature 부분)
    """
    if debugMode:
        print(
            f"DEBUG:[signature_pattern_match]::signature_pattern: {signature_pattern}")

    q_tags = set()
    for s in query_variant["statement_slices"]:
        q_tags.update(s.get("tags", []))

    q_blocks = query_variant["blocks"]
    fail_reason = []

    # 1. Required Tags
    required_tags = signature_pattern.get("required_tags", [])
    tags_ok_list = [tag_rule_match(q_tags, t) for t in required_tags]
    tags_ok = all(tags_ok_list)
    missing_tags = [t for t, ok in zip(required_tags, tags_ok_list) if not ok]
    if not tags_ok:
        fail_reason.append(f"Missing required_tags: {missing_tags}")

    # 2. Required Sequence
    required_seq = signature_pattern.get("required_sequence", [])

    q_seq = []
    for s in query_variant["statement_slices"]:
        q_seq += s.get("tags", [])

    # if debugMode: print(f"DEBUG:[signature_pattern_match]::required_seq = {required_seq}")
    # if debugMode: print(f"DEBUG:[signature_pattern_match]::q_seq(len={len(q_seq)}) = {q_seq}")

    seq_ptr = 0
    for i, tag in enumerate(q_seq):
        if seq_ptr < len(required_seq) and tag_rule_match([tag], required_seq[seq_ptr]):
            seq_ptr += 1
        if seq_ptr == len(required_seq):
            break
    seq_match = (seq_ptr == len(required_seq))
    if debugMode:
        print(
            f"DEBUG::sequence_matched_up_to = {seq_ptr}, seq_match = {seq_match}")
    if not seq_match:
        missing_seq = required_seq[seq_ptr:]
        fail_reason.append(f"Missing required_sequence: {missing_seq}")

    # 3. Block Structure
    block_struct = signature_pattern.get("block_structure", None)
    block_ok = True
    if block_struct:
        block_ok = block_structure_rule_match(
            q_blocks, block_struct, debugMode=False)
        if not block_ok:
            fail_reason.append(
                f"Block structure not matched. (required: {block_struct})")

    result = {
        "tags_match": tags_ok,
        "sequence_match": seq_match,
        "block_structure_match": block_ok,
        "overall_match": tags_ok and seq_match and block_ok,
        # 해당 값을 Critical evidence로 사용하고 이를 화면에 출력한다.
        "fail_details": {
            "fail_reason": fail_reason,
            "missing_tags": missing_tags,
            "missing_sequence": required_seq[seq_ptr:] if not seq_match else []
        }
    }
    return result


# 7.22일 추가 : gpt-o3 가이드
# ───────────────────────────────────────
# 1) one-hot TAG 코사인 유사도
# ───────────────────────────────────────
def tag_cosine(query_tags: list[str],
               db_tags: list[str],
               tag_to_idx: dict[str, int]) -> float:
    """
    TAG 집합을 one-hot 벡터로 변환한 뒤 코사인 유사도 계산.
      ▸ query_tags, db_tags : ["[SINK:ARRAY]", "[UNVALIDATED]", ...]
      ▸ tag_to_idx          : build_tag_to_idx(...) 로 얻은 {tag: idx}
    """
    if not query_tags or not db_tags:
        return 0.0

    q_vec = np.zeros(len(tag_to_idx), dtype=np.float32)
    d_vec = np.zeros(len(tag_to_idx), dtype=np.float32)

    for t in query_tags:
        idx = tag_to_idx.get(t)
        if idx is not None:
            q_vec[idx] = 1
    for t in db_tags:
        idx = tag_to_idx.get(t)
        if idx is not None:
            d_vec[idx] = 1

    # 둘 중 하나라도 0-벡터면 유사도 0
    if q_vec.sum() == 0 or d_vec.sum() == 0:
        return 0.0

    return float(cosine_similarity([q_vec], [d_vec])[0, 0])

# ───────────────────────────────────────
# 2) TAG Jaccard 유사도
# ───────────────────────────────────────


def tag_jaccard(query_tags: list[str],
                db_tags: list[str]) -> float:
    """
    두 TAG 집합의 Jaccard 계수 (교집합/합집합).
    """
    q_set = set(query_tags)
    d_set = set(db_tags)
    if not q_set and not d_set:
        return 0.0
    return len(q_set & d_set) / len(q_set | d_set)

# ───────────────────────────────────────
# 3) TAG TF-IDF 유사도
# ───────────────────────────────────────


def get_tag_tfidf_vector(variant, vectorizer):
    # variant: 단일 dict
    tags = [t for s in variant["statement_slices"] for t in s.get("tags", [])]
    tag_str = " ".join(tags)
    return vectorizer.transform([tag_str])

# ③ TF-IDF 기반 TAG 코사인 유사도


def tag_tfidf_cosine_sim(query_variant, db_variant, vectorizer):
    from sklearn.metrics.pairwise import cosine_similarity
    q_vec = get_tag_tfidf_vector(query_variant, vectorizer)
    db_vec = get_tag_tfidf_vector(db_variant, vectorizer)
    if q_vec.nnz == 0 or db_vec.nnz == 0:
        return 0.0
    return float(cosine_similarity(q_vec, db_vec)[0, 0])

# 각 유사도 수치에 설명을 더하기 위한 함수
def _collect_tags(variant):
    # statement_slices에서 tag 수집
    return [t for s in variant.get("statement_slices", []) for t in s.get("tags", [])]

def _tag_overlap_summary(query_tags_list, db_tags_list):
    q_set = set(query_tags_list)
    d_set = set(db_tags_list)
    inter = q_set & d_set
    union = q_set | d_set
    # 간단한 프리시전/리콜(선택)
    precision = (len(inter) / len(q_set)) if q_set else 0.0
    recall    = (len(inter) / len(d_set)) if d_set else 0.0
    jaccard   = (len(inter) / len(union)) if union else 0.0
    return {
        "query_count": len(q_set),
        "db_count": len(d_set),
        "matched_count": len(inter),
        "matched_examples": sorted(list(inter))[:10],  # 너무 길면 샘플만
        "precision": precision,
        "recall": recall,
        "jaccard": jaccard,
    }


# 8. 전체 유사도 검색 리포트
# 7.22, 24일 수정 : gpt-o3 가이드
# 현재 각각의 수치에 대한 가중치가 이렇게 설정되어있음
def explainable_search_report(
    query_variant: dict,
    variant_db: list,
    signature_yaml: str,
    top_k: int = 3,
    tag_sim_weight: float = 0.2,
    jaccard_weight: float = 0.1,
    tfidf_weight: float = 0.2,
    evidence_level: str = "tag"
) -> dict:
    import numpy as np
    from collections import Counter

    # ── helpers ─────────────────────────────────────────────────────────
    def _collect_tags(variant):
        """statement_slices에서 tag 리스트 평탄화."""
        return [t for s in variant.get("statement_slices", []) for t in s.get("tags", [])]

    def _tag_overlap_summary(query_tags_list, db_tags_list):
        """TAG 교집합 기반 부가정보(Jaccard/Precision/Recall/개수/샘플)."""
        q_set = set(query_tags_list)
        d_set = set(db_tags_list)
        inter = q_set & d_set
        union = q_set | d_set
        precision = (len(inter) / len(q_set)) if q_set else 0.0
        recall    = (len(inter) / len(d_set)) if d_set else 0.0
        jaccard   = (len(inter) / len(union)) if union else 0.0
        return {
            "query_count": len(q_set),
            "db_count": len(d_set),
            "matched_count": len(inter),
            "matched_examples": sorted(list(inter)),  # 과도한 크기 방지
            "precision": precision,
            "recall": recall,
            "jaccard": jaccard,
        }

    # ── (1) TAG를 one-hot 벡터 인덱스로 변환 (TAG 인덱스 맵)
    tag_to_idx = build_tag_to_idx(query_variant, *(variant_db or []))

    # ── (2) TF-IDF 벡터라이저 준비
    vectorizer, _ = build_tag_tfidf_vectorizer(variant_db, query_variant)
    query_tfidf = get_tag_tfidf_vector(query_variant, vectorizer)
    query_tfidf_empty = (getattr(query_tfidf, "nnz", 0) == 0)

    # variant의 전체 TAG 집합(기존 로직 유지)
    query_all_tags = [t for s in query_variant["statement_slices"] for t in s["tags"]]
    q_tags_list = _collect_tags(query_variant)

    # ── 3) 각 DB variant와의 최종 유사도 계산
    scored_variants = []
    for db in variant_db:
        # a) representative embedding 코사인 유사도
        emb_sim = cosine_sim(
            np.asarray(query_variant["representative_embedding"]),
            np.asarray(db["representative_embedding"])
        )

        # b) One-hot TAG 코사인
        db_tags = [t for s in db["statement_slices"] for t in s["tags"]]
        tag_sim = tag_cosine(query_all_tags, db_tags, tag_to_idx)

        # c) TAG Jaccard
        jac_sim = tag_jaccard(query_all_tags, db_tags)

        # d) TF-IDF cosine
        tfidf_sim = tag_tfidf_cosine_sim(query_variant, db, vectorizer)

        # e) Hybrid
        hybrid_sim = (
            emb_sim * (1 - tag_sim_weight - jaccard_weight - tfidf_weight)
            + tag_sim * tag_sim_weight
            + jac_sim * jaccard_weight
            + tfidf_sim * tfidf_weight
        )

        scored_variants.append({
            "db_variant": db,
            "emb_sim": emb_sim,
            "tag_sim": tag_sim,
            "jac_sim": jac_sim,
            "tfidf_sim": tfidf_sim,
            "hybrid_sim":  hybrid_sim,
        })

    # ── 4) Top-N 선택 (hybrid 기준)
    scored_variants = sorted(scored_variants, key=lambda x: -x["hybrid_sim"])[:top_k]

    # ── 5) Signature DB 로드
    sig_db = load_signature_patterns(signature_yaml)

    # ── 6) Top-N 상세 비교
    results = []
    for sv in scored_variants:
        db_var = sv["db_variant"]
        pid = db_var.get("pattern_id", "")
        hybrid = sv["hybrid_sim"]

        # 6-1) Critical evidence 매칭·패널티
        matches = match_critical_evidence(query_variant, db_var, level=evidence_level)
        matched_cnt = count_unique_evidence_matches(matches, db_var.get("critical_evidence", []))
        penalty = calc_penalty(hybrid, len(db_var.get("critical_evidence", [])), matched_cnt)
        overall = max(0.0, hybrid + penalty)

        # 6-2) YAML signature 매칭
        sig_match, sig_ref = {}, {}
        if pid and pid in sig_db:
            sig_match = signature_pattern_match(query_variant, sig_db[pid]["signature"])
            sig_ref = {
                "pattern_id": pid,
                "cwe_id": sig_db[pid]["cwe_id"],
                "description": sig_db[pid]["description"],
                "required_tags": sig_db[pid]["signature"].get("required_tags", []),
                "optional_tags": sig_db[pid]["signature"].get("optional_tags", []),
                "required_sequence": sig_db[pid]["signature"].get("required_sequence", []),
                "block_structure": sig_db[pid]["signature"].get("block_structure", []),
            }

        # 6-3) 슬라이스/블록 매칭
        slice_match = match_units(query_variant["statement_slices"],
                                  db_var["statement_slices"],
                                  tag_to_idx, is_block=False, top_k=2)
        block_match = match_units(query_variant["blocks"],
                                  db_var["blocks"],
                                  tag_to_idx, is_block=True, top_k=1)

        # ── 추가: TAG overlap 상세 계산
        d_tags_list = _collect_tags(db_var)
        tag_overlap = _tag_overlap_summary(q_tags_list, d_tags_list)

        # TF-IDF 입력 희소 여부(표시용)
        db_tfidf = get_tag_tfidf_vector(db_var, vectorizer)
        db_tfidf_empty = (getattr(db_tfidf, "nnz", 0) == 0)

        # 6-4) 리포트 항목
        results.append({
            "db_variant_info": {
                "variant_id": db_var["variant_id"],
                "source": db_var["meta"]["source"],
                "file": db_var["meta"]["file"],
                "cwe_id": db_var["cwe_id"],
                "pattern_id": pid,
            },
            "similarity_breakdown": {
                "embedding": round(sv["emb_sim"], 3),
                "tag_one_hot_cosine": round(sv["tag_sim"], 3),
                "tag_jaccard": round(sv["jac_sim"], 3),
                "tag_tfidf_cosine": round(sv["tfidf_sim"], 3),
                "hybrid": round(hybrid, 3),
                "penalty": round(penalty, 3),
                "overall": round(overall, 3),
                # ── 새로 추가된 상세 섹션
                "tag_details": {
                    "overlap": {
                        "query_count": tag_overlap["query_count"],
                        "db_count": tag_overlap["db_count"],
                        "matched_count": tag_overlap["matched_count"],
                        "matched_examples": tag_overlap["matched_examples"],
                        "precision": round(tag_overlap["precision"], 3),
                        "recall": round(tag_overlap["recall"], 3),
                        "jaccard": round(tag_overlap["jaccard"], 3),
                    },
                    "tfidf": {
                        "query_empty": bool(query_tfidf_empty),
                        "db_empty": bool(db_tfidf_empty),
                    }
                }
            },
            "signature_ref": sig_ref,
            "signature_pattern_matching": sig_match,
            "critical_evidence_matched": matches,
            "slice_matches": slice_match,
            "block_matches": block_match,
            "risk_level": "High" if overall > 0.7 else "Medium",
        })

    # ── 7) 쿼리 시그니처 요약
    query_sig = {
        "query_tags": [list(set(query_all_tags))],
        "query_blocks": [f"{b['idx']}:{b['block_type']}" for b in query_variant["blocks"]],
    }

    return {
        "query_info": {
            "file":   query_variant["meta"]["file"],
            "meta":   query_variant["meta"],
            "query_signature": query_sig
        },
        "top_matched_variants": results
    }


# ==== 사용법 예시 ====
# query_func: 분석 대상 함수(슬라이스/임베딩 등 포함, JSON)
# signature_db: 임베딩 기반 DB (list)
# signature_pattern_yaml: YAML 경로
# tag_to_idx: 전체 태그 인덱스(dict)
# result = explainable_search_report(query_func, signature_db, "signature_patterns.yaml", tag_to_idx, top_k=1)
# print(json.dumps(result, indent=2, ensure_ascii=False))

# query_variant 및 db_variants는 build_variant 등으로 생성된 dict 리스트


if __name__ == "__main__":
    import yaml
    import os
    import json

    print("현재 작업 디렉토리:", os.getcwd())

    with open(QUERY_VARIANT, "r", encoding="utf-8") as f:
        query_variant = json.load(f)

    with open(VARIANT_DB, "r", encoding="utf-8") as f:
        db_variants = json.load(f)

    # report를 return하는 함수
    report_json = explainable_search_report(
        query_variant, db_variants, SIG_DB_YAML, top_k=1)

    print(json.dumps(report_json, indent=2, ensure_ascii=False))
