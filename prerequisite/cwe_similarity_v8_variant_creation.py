
import torch, numpy as np, uuid, json, sys

from transformers import AutoTokenizer, AutoModel
from pathlib import Path

#####################################################################
# ── 모듈: 정책 (TAG, BLOCK)
#####################################################################
INPUT_FUNCS  = {"fgets","fscanf","gets","recv","read"}
COMMAND_FUNCS = {"system", "popen", "execl", "execvp", "execve", "SINK", "SYSTEM"} # 커맨드 관련
DANG_FUNCS   = {"strcpy","strcat","memcpy","memmove"}
CONVERT_FUNCS= {"atoi","strtol","atol"}
INDEX_NAMES  = {"i","j","idx","index","data"}


# -------------------------------
# 1. TAG 및 BLOCK 가중치 정책 정의
# -------------------------------
# 7.22 GPT-O3에서 제시한 기준(CodeBert 임베딩 기반 취약점-7)TAG 및 SIGNATURE최적화)
TAG_W = {
    
    "[INIT]"                                : 0.8,  # 일반 초기화, 중요도 보통, Slice 가중치 희석 방지 
    "[CONSTANT_INIT]"                       : 0.5,  # 상수 값으로 초기화"- 명확히 구분하기 위해 붙이는 태그: 코드 전체에 잦은 보일러플레이트—정보량이 적음
    "[TAINTED_INIT]"                        : 3.0,  # 외부 입력 기반 초기화 → 데이터 유입의 핵심 표식, 희소성이 높음
    "[SOURCE]"                              : 2.2,  # CWE 대부분에서 시작점으로 결정적
    "[CONVERT]"                             : 1.1,  # 형 변환 자체는 중간 연결 고리—과도 가중치 완화
    "[VALIDATION]"                          : 1.8,  # 범용 검증 문장, 패턴 판별에 유효성 검사 존재 여부가 중요
    "[VALIDATION_INDEX_BOUNDS]"             : 2.0,  # 상·하한 양쪽 모두 확인 → 일반 검증보다 정보량·패턴 분류 기여도
    "[UNVALIDATED]"                         : 3.2,  # 검증 자체 부재(임의 값 사용
    "[UNVALIDATED_INDEX]"                   : 3.2,  # 인덱스 범위 검증 부재:“검증 부재”는 취약 신호 → 안전 태그보다 확실히 높아야 함수
    "[BRANCH]"                              : 1.0, 	# 제어 분기(If, Switch 등)
    "[LOOP]"                                : 0.8,  # For / While 구문 헤더
    "[SINK]"                            	: 3.0,	# 위험 수행 지점 (상세 태그로 세분)
    "[SINK:STACK_ARRAY]"                    : 3.2,  # 메모리 쓰기 인덱스 취약점군에서 최중요
    "[SINK:HEAP_ARRAY]"                     : 3.2,  # 메모리 쓰기 인덱스 취약점군에서 최중요
    "[SINK:LOOP_COPY]"                      : 3.0,  # 반복 복사 싱크 : for (…) { dst[i]=src[i]; } 패턴. 배열-쓰기와 동일 레벨 위험. [SINK](3.0)과 동일 가중치로 두어 정규화.
    "[SINK:FUNC:STD:memmove:struct.member]" : 3.2,  # memcpy/memmove Type-Overrun 특화 — 함수+구조체 멤버 식별 시 가중치 추가
    "[SINK:FUNC:STD:memcpy:struct.member]"  : 3.2,  # memcpy/memmove Type-Overrun 특화 — 함수+구조체 멤버 식별 시 가중치 추가
    "[ASSIGN]"                              : 0.8,	# 일반 대입
    "[ASSIGN:STACK_ARRAY] "                 : 3.0,  # 스택 영역 배열 접근.스택 버퍼(int buf[10], alloca 반환 포인터) 에 대한 buf[i] 접근
    "[ASSIGN:HEAP_ARRAY]"                   : 3.0,  # 힙 영역 배열(포인터) 접근, 힙 버퍼(malloc 포인터) 에 대한 ptr[i] 접근  
    "[INDEX]"                               : 1.6,	#인덱스 식별용 보조
    "[UNINITIALIZED]"                       : 2.2,	#미초기화 변수 사용
    "[DECL]"                                : 0.1,	#선언 전용(노이즈 억제)
    "[SAFE]"                                : 0.0,	#안전 코드(패널티 회피)
    "[STACK_ALLOC]"                      	: 1.4,	#지역 배열 선언·ALLOCA
    "[HEAP_ALLOC]"                          : 1.4,  # 힙 영역 확보  │ malloc/calloc/realloc/new 호출 
    "[SAFE_ALLOC_SIZEOF]"                   : 0.0,  # 안전신호 : 올바른 sizeof(type) 사용. 정보량은 있으나 취약 신호는 아님 → [VALIDATION](1.8)보다 낮게.                          
    "[UNSAFE_ALLOC_NO_SIZEOF]"              : 3.2,  # 취약 신호 : sizeof 누락 → Type/Stack Overrun 치명 조건. 위험도·희소성 모두 [UNVALIDATED_INDEX](3.2)와 동급으로 설정
    "[STRUCT_OVERRUN]"                      : 3.8,  # 멤버 대신 구조체 전체 크기로 복사한다” 는 원인을 나타냄
    "[TYPE_OVERRUN]"                        : 3.8,  # 타입 불일치 복사
    "[STACK_OVERRUN]"                       : 3.8,  # 스택-버퍼 대상 오버런: 스택 메모리(지역 변수, ALLOCA 등)에서 할당된 버퍼의 크기를 잘못 계산하거나, 할당 이상으로 접근할 때
    "[HEAP_OVERRUN]"                        : 3.8,  # 힙-버퍼 대상 오버런
    "[OVERFLOW_LOOP_COPY]"                  : 3.6,  # 특화 취약 싱크 : “루프-복사+사이즈 미검증” 복합 조건. 
    "[CRITICAL]"                            : 5.0,  # “핵심 증거” 슬라이스 강조—대표 임베딩 집계 시 확실히 부각
     # OS 명령 실행 취약점 (CWE-78)
    "[SINK:COMMAND_EXECUTION]" : 3.5, 
    "[SINK:FUNC:STD:system]"   : 3.5,
    "[SINK:FUNC:STD:popen]"    : 3.5,
    "[SINK:FUNC:STD:exec]"     : 3.5,
}


# CRITICAL 부여 조건: 해당 조건은, 취약점이 많아질 수록 추가된다.
# [1] 취약 함수 내 SINK 태그(예: [SINK:ARRAY:*], [SINK:FUNC:*], [STRUCT_OVERRUN], [STACK_OVERRUN]... 등)가 있으면서
#   [UNVALIDATED], [UNVALIDATED_INDEX] 등 검증 부재 태그가 동시에 등장
#   1. {"memcpy", "memmove"}, STRUCT_OVERRUN :  
#   2. AssignmentExpression(Arrary) UNVALIDATED_INDEX, UNVALIDATED
# [2] 취약 할당 구문(잘못된 ALLOCA/할당)은 항상 [CRITICAL]로 지정
#   [UNSAFE_ALLOC_NO_SIZEOF]
# 
#

#가중치 정책 요약
# 5.0 ≥ w ≥ 3.0 → 패턴 식별에 결정적(취약·핵심)
# 3.0 > w ≥ 1.4 → 중요하지만 상황 의존(배열 쓰기, 할당 종류 등)
# 1.3 > w ≥ 0.5 → 문맥 보조(초기화/일반 분기)
# w = 0         → 안전·패널티 제거 표식 또는 노이즈

INCLUDE_FUNCTION_DEF = False

BLOCK_TYPES = {
    "CompoundStatement",
    "IfStatement",
    "ForStatement",
    "WhileStatement",
    "SwitchStatement"
}

BLOCK_BASE_W = {
    "CompoundStatement": 0.7,
    "IfStatement": 1.0,
    "ForStatement": 1.0,
    "WhileStatement": 1.0,
    "SwitchStatement": 1.0,
    "AssignmentExpression(ArraySubscript)": 2.0,  # 중첩 statement-level block
    # 필요시 기타 block 추가
}

# ---- 글로벌 컨텍스트 선언 ----
TAG_CONTEXT = {
    "func_args": set(),
    "unsafe_stack_alloc_vars":[],
    "unsafe_heap_alloc_vars":[],
    "safe_stack_alloc_vars":[],
    "safe_heap_alloc_vars":[]
}


tokenizer = AutoTokenizer.from_pretrained("microsoft/graphcodebert-base")
model = AutoModel.from_pretrained("microsoft/graphcodebert-base").eval()

@torch.no_grad()
def mean_pool_embed(code: str, max_len: int = 256):
    ids = tokenizer(code, truncation=True, max_length=max_len, return_tensors="pt")
    out = model(**ids).last_hidden_state          # [1, L, 768]
    mask = ids.attention_mask.unsqueeze(-1)       # [1, L, 1]
    pooled = (out * mask).sum(dim=1) / mask.sum(dim=1)  # masked mean pooling
    return pooled.squeeze().cpu().numpy()

# -------------------------------
# 2. Weight 계산 함수
# -------------------------------

from math import log1p
import logging

LOG = logging.getLogger(__name__)

#w1 = get_statement_weight(s, base=0.1, mode="sum")  # 기존과 가장 유사
#w2 = get_statement_weight(s, base=0.1, mode="log")  # 태그 다수일 때 완만

def get_statement_weight(obj, base=0.1, mode="log"):
    """
    obj : dict(슬라이스 항목) 또는 tag list
    base: 태그 매칭이 하나도 없을 때 부여하는 최소 weight
    mode: "sum" | "avg" | "log"
      - sum : 가중치 단순 합 (default)
      - avg : 태그당 평균값으로 정규화
      - log : 합계에 log 스케일 적용
    """
    tags = obj.get("tags", []) if isinstance(obj, dict) else obj
    matched = []          # 매칭된 태그 목록
    weight_acc = 0.0

    for tag in tags:
        # prefix 단계적으로 잘라가며 매칭
        part = tag
        while True:
            if part in TAG_W:
                # 중복 방지를 위해 동일 TAG 재가산 금지
                if part not in matched:
                    matched.append(part)
                    weight_acc += TAG_W[part]
                break
            # prefix 축소:  [ASSIGN:VAR:data] → [ASSIGN:VAR] → [ASSIGN]
            if ":" in part:
                part = part.rsplit(":", 1)[0] + "]"
            else:
                break
    
    # print(f"DEBUG:[get_statement_weight] :  tags = {tags}")
    # print(f"  DEBUG:[get_statement_weight] :  matched = {matched}")


    # ① 매칭된 태그 없으면 최소값만 반환
    if not matched:
        return base

    # ② 스케일링 모드별 처리
    if mode == "avg":
        weight_acc /= len(matched)
    elif mode == "log":
        weight_acc = log1p(weight_acc)  # ln(1+x)

    return base + weight_acc


# w_block = get_block_weight(block_dict)                  # 기본(log 스케일)
# w_block_sum = get_block_weight(block_dict, mode="sum")  # 단순 합산

def get_block_weight(block: dict,
                     base_block_map: dict = BLOCK_BASE_W,
                     base: float = 0.2,
                     mode: str = "log") -> float:
    """
    ▸ block         : {"block_type": str, "tags": [...]} 형태
    ▸ base_block_map: 블록 타입별 기본 가중치(BLOCK_BASE_W)
    ▸ base          : 태그 매칭이 전혀 없을 때 더해 줄 최소값
    ▸ mode          : 태그 누적 스케일링 방식
                      "sum"  : 단순 합
                      "avg"  : 태그당 평균
                      "log"  : log1p(합계)  ← 기본
    """
    btype = block.get("block_type", "")
    tags  = block.get("tags", [])

    # 1) 블록 타입 자체에 부여하는 기본 가중치
    weight_acc = base_block_map.get(btype, 0.8)

    # 2) 태그별 가중치 누적 (중복 태그는 1회만)
    matched = set()
    for tag in tags:
        part = tag
        while True:
            if part in TAG_W:
                matched.add(part)
                break
            if ":" in part:
                part = part.rsplit(":", 1)[0] + "]"
            else:
                break

    # print(f"DEBUG:[get_block_weight] :  tags = {tags}")
    # print(f"  DEBUG:[get_block_weight] :  matched = {matched}")


    tag_sum = sum(TAG_W[t] for t in matched)

    # 3) 스케일 모드
    if mode == "avg" and matched:
        tag_sum /= len(matched)
    elif mode == "log":
        tag_sum = log1p(tag_sum)

    return weight_acc + base + tag_sum

# -------------------------------
# 3. 대표 임베딩 계산 함수 : GPT-o3가 제공한 코드
# -------------------------------
def calc_representative_embedding(
        slices: list,
        blocks: list,
        *,
        crit_bonus: float = 1.5,
        block_factor: float = 0.5,
        eps: float = 1e-8
    ) -> list:
    """
    ▸ slices       : [{ "embedding": [...], "weight": float, "tags":[...] }, ...]
    ▸ blocks       : [{ "embedding": [...], "weight": float, "tags":[...] }, ...]
    ▸ crit_bonus   : 슬라이스에 `[CRITICAL]` 포함 시 곱해 줄 배수
    ▸ block_factor : 블록 weight를 statement 총합 대비 몇 배로 반영할지 (0.5 = 50%)
    ▸ eps          : Divide-by-zero 방지용 작은 값
    """
    if not slices and not blocks:
        raise ValueError("slices, blocks 둘 다 비어 있습니다.")

    # ── 임베딩 차원 길이 검증
    vec_len = len(slices[0]["embedding"] if slices else blocks[0]["embedding"])

    agg_vec = np.zeros(vec_len, dtype=np.float32)
    total_w = 0.0

    # ── 1) 슬라이스 집계
    for s in slices:
        w = s["weight"]
        if "[CRITICAL]" in s.get("tags", []):
            w *= crit_bonus
        agg_vec += w * np.asarray(s["embedding"], dtype=np.float32)
        total_w += w

    # ── 2) 블록 집계
    for b in blocks:
        w = block_factor * b["weight"]
        agg_vec += w * np.asarray(b["embedding"], dtype=np.float32)
        total_w += w

    # ── 3) 정규화 & 리스트 반환
    return list(agg_vec / max(total_w, eps))

    
def parent_chain_str(chain, typeAttributeAlias):
    # 각 노드의 타입과, name/code 등 주요 속성 출력
    descs = []
    for n in chain:
        if not isinstance(n, dict):
            continue
        t = n.get(typeAttributeAlias)
        name = n.get("name")
        code = n.get("code")

        if name:
            descs.append(f"{t}[name:{name}]")
        elif code:
            code_short = code.strip().replace('\n', ' ')[:20] + ('...' if len(code) > 20 else '')
            descs.append(f"{t}[code:{code_short}]")
        else:
            descs.append(f"{t}")
    return " > ".join(descs)

def find_nearest_assignment_expr(parent_chain):
    # 역순으로 가장 가까운 Assignment 반환
    for parent in reversed(parent_chain):
        if parent.get("nodeType") == "AssignmentExpression":
            return parent
    return None

def find_nearest_ifstatement(parent_chain):
    # 역순으로 가장 가까운 IfStatement 반환
    for parent in reversed(parent_chain):
        if isinstance(parent, dict) and parent.get("nodeType") == "IfStatement":
            return parent
    return None

def contains_var(node, var_name):
    """ AST의 서브트리에서 var_name이 등장하는지 재귀적으로 탐색 """
    if not node:
        return False
    if isinstance(node, dict):
        # 변수 노드이면 이름 매칭
        if node.get("nodeType") == "Identifier" and node.get("name") == var_name:
            return True
        # 자식 노드 모두 순회
        for v in node.values():
            if isinstance(v, (dict, list)):
                if contains_var(v, var_name):
                    return True
    elif isinstance(node, list):
        for item in node:
            if contains_var(item, var_name):
                return True
    return False

# Command injection 관련 코드의 태깅을 위한 함수
def _subtree_contains_identifier(node, ident_name: str) -> bool:
    """서브트리에 Identifier(ident_name)가 등장하는지 재귀 확인"""
    if not isinstance(node, (dict, list)):
        return False
    if isinstance(node, dict):
        if node.get("nodeType") == "Identifier" and node.get("name") == ident_name:
            return True
        for v in node.values():
            if isinstance(v, (dict, list)) and _subtree_contains_identifier(v, ident_name):
                return True
    else:  # list
        for item in node:
            if _subtree_contains_identifier(item, ident_name):
                return True
    return False


def _has_shell_metachar_in_code(code_str: str) -> bool:
    """
    간단한 셸 메타문자 휴리스틱.
    - 실제 셸 파싱을 완벽히 대체하진 않지만, 위험 신호 감지용 태그로 충분.
    """
    if not code_str:
        return False
    # ;, |, &, `, $, <, >, *, ?, (), {}, [], \, "
    # (문자열 리터럴 내부만 분리하는 정교함은 여기서 생략)
    import re
    return bool(re.search(r'[;&|`$<>*?(){}\[\]\\"]', code_str))


def tag_command_injection(ast_node: dict, parent_chain=None) -> list:
    """
    StandardLibCall/UserDefinedCall 노드에서 COMMAND_FUNCS(system/popen/exec*) 호출을 탐지하여
    - [SINK:COMMAND_EXECUTION]
    - [SINK:FUNC:STD:{name}]
    - (옵션) [SOURCE:ARG:x] / [SHELL_META]
    - [CRITICAL]
    태그를 부여한다.
    """
    tags = []
    if not isinstance(ast_node, dict):
        return tags

    t = ast_node.get("nodeType")
    if t not in ("StandardLibCall", "UserDefinedCall"):
        return tags

    name = ast_node.get("name", "")
    print("CMD 관련 태그 예상 후보", name)
    if name not in COMMAND_FUNCS:
        return tags

    # 기본 SINK 태그
    tags.append("[SINK:COMMAND_EXECUTION]")
    # 표기 일관성을 위해 STD로 태깅(필요시 USER/LIB 등 세분도 가능)
    tags.append(f"[SINK:FUNC:STD:{name}]")

    # --- 인자 오염(함수 인자) 여부 체크
    try:
        params = (ast_node.get("children", [{}])[0]).get("children", [])
    except Exception:
        params = []

    tainted = False
    arg_names = TAG_CONTEXT.get("func_args", set())
    arg_hits = []
    for arg in (arg_names or []):
        for p in params:
            if _subtree_contains_identifier(p, arg):
                arg_hits.append(arg)
                tainted = True
                break

    for hit in arg_hits:
        tags.append(f"[SOURCE:ARG:{hit}]")

    # --- 셸 메타문자 휴리스틱
    code_str = ast_node.get("code", "")
    if _has_shell_metachar_in_code(code_str):
        tags.append("[SHELL_META]")

    # 정책: OS 명령 실행 호출은 **항상** critical 로 승격
    # (추후 정책을 바꾸고 싶다면 tainted or shell_meta 일 때만 CRITICAL 로 조정 가능)
    tags.append("[CRITICAL]")

    return list(dict.fromkeys(tags))


def is_loop_index(index_var_name, parent_chain): 
    #Returns:
    #    True  - 상위에 for/while/doWhile 조건에 index_var가 등장하면
    #    False - 그렇지 않으면
   
    for parent in reversed(parent_chain):
        t = parent.get("nodeType")
        if t in ("ForStatement", "WhileStatement", "DoWhileStatement"):
            # ForStatement/WhileStatement 조건부에 index_var 등장 여부
            # 보통 children[0]이 조건
            cond = parent.get("children", [None])[0]
            if cond and contains_var(cond, index_var_name):
                return True
    return False


def is_all_constant(node):
    """
    AST 노드가 '상수 식'(즉, 리터럴, sizeof, 리터럴들만으로 조합된 연산 등)인지 재귀적으로 판별
    - Literal
    - SizeOfExpression (즉, sizeof(...))
    - BinaryExpression/UnaryExpression: 하위가 전부 상수면 True
    """
    if node is None:
        return False
    node_type = node.get("nodeType", "")

    # (1) 상수 리터럴
    if node_type == "Literal":
        return True
    # (2) sizeof(x): 타입 이름/식에 상관없이 모두 상수로 처리
    if node_type == "SizeOfExpression":
        return True
    # (3) (음수 등) 단항 연산: 하위가 상수면 상수
    if node_type == "UnaryExpression":
        children = node.get("children", [])
        return all(is_all_constant(child) for child in children)
    # (4) 이항 연산(+, -, *, / 등): 하위가 전부 상수면 상수
    if node_type == "BinaryExpression":
        children = node.get("children", [])
        return all(is_all_constant(child) for child in children)
    # (5) (추가) 타입 캐스트도 상수로 허용할지 필요시 추가
    if node_type == "CastExpression":
        children = node.get("children", [])
        return all(is_all_constant(child) for child in children)
    # (6) 그 외 식별자, 

def is_constant_index(subscript_node):

    idx = subscript_node.get("children")[1]    
    # Literal이면 상수
    if idx.get("nodeType") == "Literal":
        return True
    
    # SizeOfExpression 등 수식도 상수로 볼 수 있음 (더 추가 가능)

    if idx.get("nodeType") in {"BinaryExpression", "UnaryExpression"}:
        # ...이하 AST 트리 내려가며 전부 상수 성분인지 재귀적 확인 구현 가능
        return is_all_constant(idx)
    return False

def is_sizeof_used(node):
    if not node:
        return False
    if node.get("nodeType") == "SizeOfExpression":
        return True
    # BinaryExpression 등에서 재귀 탐색
    for child in node.get("children", []):
        if is_sizeof_used(child):
            return True
    return False

def malloc_contained(node):
    """하위에서 malloc/ALLOCA 함수 호출이 있는지 재귀적으로 체크"""
    t = node.get("nodeType")

    if t == "StandardLibCall":
        # 함수 이름이 malloc인지 확인
        if node.get('name', None) == 'malloc':
            return 'malloc'
    elif t == "UserDefinedCall":
        # 함수 이름이 ALLOCA인지 확인
        if node.get('name', None) == 'ALLOCA':
            return 'ALLOCA'

    # 모든 자식 노드에 대해 재귀적으로 체크
    children = node.get("children", [])
    if isinstance(children, list):
        for c in children:
            result = malloc_contained(c)
            if result:
                return result
    return None

def analyze_index_validation(cond_node):
    """
    AST 조건 노드에서 인덱스 검증 여부를 판별
    하한만: UNVALIDATED_INDEX
    하한+상한: VALIDATION_INDEX_BOUNDS
    """
    # 하한/상한 확인용 플래그
    has_lower = False
    has_upper = False
      
    def walk(node):
        nonlocal has_lower, has_upper

        if node["nodeType"] == "BinaryExpression":
            op = node.get("operator") 

            left = node.get("children")[0]
            right = node.get("children")[1]
            # data >= 0
            
            val = right.get("value") if right else None
            # 문자열일 수도 있으니 int 변환
            try:
                num_val = int(val)
            except:
                num_val = val

            if op in (">=", ">"):
                if left and right and \
                   left.get("nodeType") == "Identifier" and right.get("nodeType") == "Literal" and \
                   num_val == 0:
                    has_lower = True
            # data < N
            elif op == "<":
                if left and right and \
                   left.get("nodeType") == "Identifier" and right.get("nodeType") == "Literal":
                    has_upper = True
            # AND 연산이면 재귀로 탐색
            elif op == "&&":
                walk(left)
                walk(right)

    walk(cond_node)

    if has_lower and has_upper:
        return "VALIDATION_INDEX_BOUNDS"
    elif has_lower:
        return "UNVALIDATED_INDEX"
    else:
        return None

#예를 들어 free 함수의 경우 단순 free가 될 수 있고 한편으로는 use_after_free 등 취약점을 유발할 수 있는 함수암
#따라서 sink를 부여할 만한 문맥을 가지고 있는지 판단하는 함수임
#아래는 free 함수에 대해 SINK를 부여할만한 문맥을 가지고 있는지의 예시임. 
#이 함수는 상황에 따라 다양하게 정의가 가능
def is_sink_context(ast_node, parent_chain=None, signature=None):
    """
    ast_node: 현재 노드 (예: StandardLibCall with name 'free')
    parent_chain: 상위 노드 리스트 (optional)
    signature: 시그니처 요구 정보 (optional)
    """
    # 1. 시그니처에서 SINK 요구 시점에만 TRUE
    if signature and '[SINK:FUNC:STD:free]' in signature.get('required_tags', []):
        return True
    
    # 2. 상위 노드 중 UAF/Double Free 패턴이 감지되면 TRUE
    if parent_chain:
        for parent in reversed(parent_chain):
            # 예시: free 바로 전에 포인터가 사용(Write/Read) 되었는지 등
            if parent.get('nodeType') in ('UseAfterFree', 'DoubleFreePattern'):
                return True
    
    # 3. 취약 패턴 내에서, free가 흐름의 끝 또는 예외 처리 블록이면 TRUE
    # (특정 컨텍스트 추가 가능)
    
    return False  # 기본은 False (단순 free는 SINK 아님)

def _find_alloc_call(node, targets=("malloc", "ALLOCA")):
    """
    AST 서브트리에서 malloc / ALLOCA 호출 노드를 찾아 돌려준다.
    반환: (call_node | None)
    """
    if not isinstance(node, dict):
        return None
    if node.get("nodeType") in ("StandardLibCall", "UserDefinedCall") \
       and node.get("name") in targets:
        return node
    for ch in node.get("children", []):
        res = _find_alloc_call(ch, targets)
        if res:
            return res
    return None


def _uses_sizeof(expr_node) -> bool:
    """
    할당 크기 인자에 sizeof 가 적어도 한 번 등장하면 True.
    •   BinaryExpression '*' 형태(10 * sizeof(int)) 도 허용
    •   단독 SizeOfExpression 도 허용 (sizeof(struct S))
    """
    if not isinstance(expr_node, dict):
        return False

    nt = expr_node.get("nodeType")
    if nt == "SizeOfExpression":
        return True
    if nt == "BinaryExpression" and expr_node.get("operator") == "*":
        left, right = expr_node.get("children", [None, None])
        return _uses_sizeof(left) or _uses_sizeof(right)
    return False

def tag_alloc_assignment(assign_node,tags_out):
    """
    AssignmentExpression 노드에 대해 
    • STACK_ALLOC / HEAP_ALLOC
    • (un)safe 크기계산
    • CRITICAL 여부
    태그를 tags_out(list)에 append 한다.
    """
    # ① LHS / RHS 분리
    children = assign_node.get("children", [])
    if len(children) < 2:
        return
    lhs, rhs = children[0], children[1]

    # ② RHS 에서 malloc/ALLOCA 호출 찾기
    call = _find_alloc_call(rhs)
    if not call:                                   # 할당 호출 없음
        return

    func_name = call["name"]                       # 'malloc' or 'ALLOCA'

    # ③ LHS 식별자 이름 추출 (Identifier | PointerDereference)
    if lhs.get("nodeType") == "PointerDereference":
        ident = (lhs.get("children", [{}])[0]).get("name", "")
    else:
        ident = lhs.get("name", "")

    # ④ SAFE/UNSAFE 여부
    params = call.get("children", [{}])[0].get("children", [])
    size_expr = params[0] if params else {}
    is_safe   = _uses_sizeof(size_expr)

    # ⑤ TAG 부여
    if func_name == "ALLOCA":
        tags_out += [f"[STACK_ALLOC:{ident}]"]
    else:  # malloc
        tags_out += [f"[HEAP_ALLOC:{ident}]"]
    

    if is_safe:
        tags_out.append("[SAFE_ALLOC_SIZEOF]")
        if func_name == "ALLOCA":
            TAG_CONTEXT["safe_stack_alloc_vars"].append(ident)
        else :
           TAG_CONTEXT["safe_heap_alloc_vars"].append(ident)
    else:
        tags_out += ["[UNSAFE_ALLOC_NO_SIZEOF]", "[CRITICAL]"]
        if func_name == "ALLOCA":
            TAG_CONTEXT["unsafe_stack_alloc_vars"].append(ident)
        else :
           TAG_CONTEXT["unsafe_heap_alloc_vars"].append(ident)


def tag_node_statement(ast_node, parent_chain = None):
    
    func_args = TAG_CONTEXT["func_args"]
   
    t = ast_node.get("nodeType")    
    name = ast_node.get("name", "")
    if t in ("StandardLibCall",  "UserDefinedCall") :
        if t == "StandardLibCall":
            func_type = 'STD'
        elif "UserDefinedCall":
            func_type = 'USER'
        else:
            func_type = 'LIB'

    tag = []
    var_name = ast_node.get("name","unknown") 
 
    
    # (1) Memory Allocation  (STACK: 배열선언, 구조체 선언, ALLOCA로 메모리 할당, HEAP : malloc 등 호출)
    if t == "ArrayDeclaration":
        tag.append(f"[STACK_ALLOC:{var_name}]")   
    elif t == "VariableDeclaration" and ast_node.get("type","") == "charVoid":
        tag.append(f"[STACK_ALLOC:{var_name}]")   
    elif t== "AssignmentExpression":  
        #ALLOCA, malloc 호출할 경우 해당 TAG 추가
        alloc_tag = []
        tag_alloc_assignment(ast_node,alloc_tag)           
        if alloc_tag:
            tag += alloc_tag


    # (2) 위험 함수  
    if t in ("StandardLibCall",  "UserDefinedCall") :
        # 커맨드 인젝션 rule
        cmd_tags = tag_command_injection(ast_node, parent_chain)
        if cmd_tags:
            # 커맨드 실행이면 여기서 끝 — 다른 함수 카테고리(memcpy, INPUT_FUNCS 등)로 내리지 않음
            tag += cmd_tags
            return list(dict.fromkeys(tag))
        
        params = (ast_node.get("children")[0]).get("children")
        if name in {"memcpy", "memmove"} and len(params) >= 1:
            dst = params[0]
            # 목적지가 구조체 멤버
            if dst.get("nodeType") == "MemberAccess":
                if dst.get("children")[0].get("nodeType") == "PointerDereference":
                    tag.append(f"[SINK:FUNC:{func_type}:{name}:struct.member]")
                    isStackAccess = False
                else:
                    tag.append(f"[SINK:FUNC:{func_type}:{name}:struct.member]")
                    isStackAccess = True
                # 구조체 전체 크기 복사(오버런 위험)
                if len(params) >= 3:
                    size_arg = params[2]
                    # (a) size_arg가 SizeOfExpression인지
                    if size_arg.get("nodeType") == "SizeOfExpression":
                        if size_arg.get("children")[0].get("nodeType") == "PointerDereference":
                            size_inner = size_arg.get("children", [None])[0].get("children")[0]
                        else :
                            size_inner = size_arg.get("children", [None])[0]
                        # (b) 구조체 전체 크기: Identifier, UnaryOperator(*struct), etc.
                        if size_inner:
                            if size_inner.get("nodeType") in {"Identifier", "UnaryOperator"} :
                                # 복사 함수→오버런 증거→CRITICAL까지 순차 (Signature Pattern과의 일관성)
                                tag.append("[STRUCT_OVERRUN]")
                                if isStackAccess:
                                    tag.append("[STACK_OVERRUN]")
                                else:
                                    tag.append("[HEAP_OVERRUN]")
                                tag.append("[CRITICAL]")
                            elif size_inner.get("nodeType") == "MemberAccess":
                                # struct.member면 안전 → 태그 부여하지 않음
                                pass
            
            # 목적지가 일반변수 및 포인터 변수
            elif dst.get("nodeType") in {"Identifier","PointerDereference"} :
                dst_name = ""
                if dst.get("nodeType") == "Identifier":
                    dst_name = dst.get('name', '')
                else:
                    dst_name = dst.get("children")[0].get("name")
                tag.append(f"[SINK:FUNC:{func_type}:{name}:{dst_name}]")
                if dst_name in TAG_CONTEXT.get("unsafe_stack_alloc_vars", []):
                    tag.append("[STACK_OVERRUN]")
                    tag.append("[CRITICAL]")
                elif dst_name in TAG_CONTEXT.get("unsafe_heap_alloc_vars", []):
                    tag.append("[HEAP_OVERRUN]")
                    tag.append("[CRITICAL]")
            else:
                tag.append(f"[SINK:FUNC:{func_type}:{name}:unknown]")

        elif name in INPUT_FUNCS:
            tag.append(f"[SOURCE:INPUT:{name}]")
        elif name in DANG_FUNCS:
            tag.append(f"[SINK:FUNC:{func_type}:{name}]")            
        elif name in CONVERT_FUNCS:
            tag.append(f"[CONVERT:{name}]")
        else:
            tag.append(f"[CALL:{func_type}:{name}]")
            if name == "free" and is_sink_context(ast_node):
               tag.append(f"[SINK:FUNC:{func_type}:{name}]")       

            
    # (2) AssignmentExpression
    if t == "AssignmentExpression":
        children = ast_node.get("children", [])
        left = children[0]
        right = children[1]
        if malloc_contained(right) in ("malloc","ALLOCA"):
            pass
        else:
            # [ASSIGN] 태그
            # (a) 배열  
            if left.get("nodeType") == "ArraySubscriptExpression":
                array = left.get("children")[0]
                
                if array.get("nodeType") == "Identifier":
                    tag.append(f"[ASSIGN:STACK_ARRAY:{array.get('name','')}]")
                elif array.get("nodeType") == "PointerDereference":
                    tag.append(f"[ASSIGN:HEAP_ARRAY:{ array.get('children')[0].get('name', 'unknown')}]")        
                elif array.get("nodeType") == "MemberAccess":
                    if array.get("children")[0].get("nodeType") == "PointerDereference":
                        obj = array.get("children")[0].get("children", {})[0].get("name", "")
                        member = array.get("children", {})[1].get("name", "")
                        tag.append(f"[ASSIGN:HEAP_ARRAY:{obj}.{member}]")
                    else:
                        obj = array.get("children", {})[0].get("name", "")
                        member = array.get("children", {})[1].get("name", "")
                        tag.append(f"[ASSIGN:STACK_ARRAY:{obj}.{member}]")
                else:
                    tag.append("[ASSIGN:ARRAY:unknown]")
           
            # (b) 구조체 멤버 
            elif isinstance(left, dict) and left.get("nodeType") == "MemberAccess":
                if left.get("children")[0].get("nodeType") == "PointerDereference":
                    obj = left.get("children")[0].get("children", {})[0].get("name", "")
                    member = left.get("children", {})[1].get("name", "")
                    tag.append(f"[ASSIGN:MEMBER:{obj}->{member}]")
                else:
                    obj = left.get("children", {})[0].get("name", "")
                    member = left.get("children", {})[1].get("name", "")
                    tag.append(f"[ASSIGN:MEMBER:{obj}.{member}]")
            
            # (c) 일반/포인터 변수  (Identifier)
            elif isinstance(left, dict) and left.get("nodeType") in ("Identifier", "PointerDereference") :
                if left.get("nodeType") == "PointerDereference":
                    identifier = left.get('children')[0].get('name','')
                    tag.append(f"[ASSIGN:VAR:{identifier}]")
                else: 
                    identifier = left.get('name','')
                    tag.append(f"[ASSIGN:VAR:{identifier}]")

            initFlag = False
            if left.get("nodeType") == "ArraySubscriptExpression":
               # [INIT, CONSTANT_ININT] 태그
                if is_loop_index(left.get("children")[1].get("name"), parent_chain):
                   if right.get("nodeType") == "Literal":
                      tag += ["[INIT]", "[CONSTANT_INIT]"]
                      initFlag = True
                elif is_constant_index(left) and right.get("nodeType") == "Literal":
                       tag += ["[INIT]", "[CONSTANT_INIT]"]
                       initFlag = True

                if initFlag == False:
                    #[SINK ARRAY] 태그    
                    #가능한 [SINK] 태그 전에 [SOURCE] 태그를 위치 시킴 
                    if func_args and left.get("children")[1].get("name") in func_args:
                        tag.append(f"[SOURCE:ARG:{left.get('children')[1].get('name')}]") 

                    array = left.get("children")[0]
                    # 단일 배열 변수 (정적배열)
                    if array.get("nodeType") == "Identifier":
                        tag.append(f"[SINK:STACK_ARRAY:{array.get('name','')}]")
                        array_var_name = array.get('name','')
                    # 포인터 배열 : 일반변수와 동일하게 (동적배열)
                    elif array.get("nodeType") == "PointerDereference":
                        array_var_name = array.get("children", {})[0].get("name", "unknown")
                        if (array_var_name in TAG_CONTEXT.get("unsafe_stack_alloc_vars", [])) or \
                           (array_var_name in TAG_CONTEXT.get("safe_stack_alloc_vars", [])):
                            tag.append(f"[SINK:STACK_ARRAY:{array.get('children', {})[0].get('name', 'unknown')}]") 
                        else :
                            tag.append(f"[SINK:HEAP_ARRAY:{array.get('children', {})[0].get('name', 'unknown')}]") 
                       
                    # 구조체 멤버 배열
                    elif array.get("nodeType") == "MemberAccess":
                        if array.get("children")[0].get("nodeType") == "PointerDereference":
                            obj = array.get("children")[0].get("children", {})[0].get("name", "")
                            member = array.get("children", {})[1].get("name", "")
                            tag.append(f"[SINK:HEAP_ARRAY:{obj}->{member}]")
                            array_var_name = obj + "->" + member                            
                        else:
                            obj = array.get("children", {})[0].get("name", "")
                            member = array.get("children", {})[1].get("name", "")
                            tag.append(f"[SINK:STACK_ARRAY:{obj}.{member}]")
                            array_var_name = obj + "." + member
                    else:
                        tag.append("[SINK:ARRAY:unknown]") 
                        array_var_name ="", "unknow"
                    
                    loop_flag = False
                    if is_loop_index(left.get("children")[1].get("name"), parent_chain): 
                        tag.append(f"[SINK:LOOP_COPY:{array_var_name}]")     
                        loop_flag = True                         

                    # STACK_OVERRUN, HEAP_OVERRUN, OVERFLOW_LOOP_COPY (CWE121/122_131등, _129는 해당 안됨)
                    
                    if array_var_name in TAG_CONTEXT.get("unsafe_stack_alloc_vars", []):
                        tag += ["[STACK_OVERRUN], [CRITICAL]"]
                        if loop_flag: 
                            tag.append(f"[OVERFLOW_LOOP_COPY]")
                    elif array_var_name in TAG_CONTEXT.get("unsafe_heap_alloc_vars", []):
                        tag += ["[HEAP_OVERRUN], [CRITICAL]"]
                        if is_loop_index(left.get("children")[1].get("name"), parent_chain): 
                            tag.append(f"[OVERFLOW_LOOP_COPY]")

    
            else:
                if right.get("nodeType") == "Literal":
                    tag += ["[INIT]", "[CONSTANT_INIT]"]
                elif right.get("nodeType") == "CastExpression":
                    if right.get("children")[0].get("nodeType") == "Literal":
                        tag += ["[INIT]", "[CONSTANT_INIT]"]    
                else:
                   if right.get("nodeType") == "StandardLibCall" and right.get("name") in CONVERT_FUNCS:
                      tag.append("[TAINTED_INIT]")
       
    if t == "IfStatement":
        #children에서 BinaryExpression 같은 조건을 추출 (AST 구조에서 condition이 children[0])
        children = ast_node.get("children", [])
        cond =  ast_node.get("children")[0]

        if cond:
            validation_type = analyze_index_validation(cond)
        
        # then/else 블록에 배열 접근이 있는지 확인
        def get_then_else_blocks(ast_node):
            # children[1]이 then, children[2]가 else(있을 경우)로 
            then_block=""
            else_block=""
            if len(children) > 1:
                then_block = children[1]
            if len(children) > 2:
                else_block = children[2]
            return then_block, else_block

        # 배열 접근이 있는 경우에만 태그 부여
        then_block, else_block = get_then_else_blocks(ast_node)

        def contains_array_access(node):
            """
            node (dict or list): AST node or list of nodes
            Returns True if any ArraySubscriptExpression is found in subtree.
            """
            if isinstance(node, dict):
                if node.get("nodeType") == "ArraySubscriptExpression":
                    return True
                for v in node.values():
                    if contains_array_access(v):
                        return True
            elif isinstance(node, list):
                for item in node:
                    if contains_array_access(item):
                        return True
            return False

        if contains_array_access(then_block) or contains_array_access(else_block):
            if validation_type == "VALIDATION_INDEX_BOUNDS":
                tag.append("[VALIDATION_INDEX_BOUNDS]")
            elif validation_type == "UNVALIDATED_INDEX":
                tag.append("[UNVALIDATED_INDEX]")
    
    # (신규 추가) 반복문에 LOOP 태그 부여
    if t in ("ForStatement", "WhileStatement", "DoWhileStatement"):
            tag.append("[LOOP]")

    return list(dict.fromkeys(tag))

def extract_statements(ast_node, rootstmt_parent_chain, res=None,  parent_chain=None, debug=False):
   
   
    if res is None: res = []
    if not isinstance(ast_node, dict):
        return res
    if parent_chain is None: parent_chain = []
    
   
    def contains_node(node, target):
        if node is target:
            return True
        if isinstance(node, dict):
            for v in node.values():
                if isinstance(v, (dict, list)):
                    if contains_node(v, target):
                        return True
        elif isinstance(node, list):
            for item in node:
                if contains_node(item, target):
                    return True
        return False

    t = ast_node["nodeType"]
  

    # --- 1. 하위 태그 모두 모으기 ---
    child_tags = []
    for child in ast_node.get("children", []):
        if isinstance(child, dict):
            subres = extract_statements(child, rootstmt_parent_chain, res=None, parent_chain=parent_chain + [ast_node], debug=debug)
        if subres:
            for item in subres:
                child_tags += item.get("tags", [])
        
    # --- 2. 자기 노드 태깅 ---
    my_tags = tag_node_statement(ast_node, parent_chain=rootstmt_parent_chain)
    if debug: print(f"DEBUG:[extract_statements] : completed gathering tags: type : {t} : code: {ast_node.get('code')[0:20]}, child_tags: {child_tags}, my_tags: {my_tags}")

    total_tags = list(dict.fromkeys(my_tags + child_tags))  # 태그 중복제거 
    
    if debug: print(f"DEBUG:[extract_statements]  => sum of gathering tags: type : {t}, total_tags: {total_tags}")


   
    # --- 3. Assignment 후처리
    if t == "AssignmentExpression":
        left = ast_node.get("children")[0]
        right = ast_node.get("children")[1]

        #3-1. Assignment 후처리: 배열 접근
        if left.get("nodeType") == "ArraySubscriptExpression":
            #CRITICAL 부여: IfStatement 노드를 가져옴
            nearest_if = find_nearest_ifstatement(rootstmt_parent_chain)
            if nearest_if:
                ifstmts_tags = tag_node_statement(nearest_if)               
                if "[VALIDATION_INDEX_BOUNDS]" in ifstmts_tags:
                    total_tags.append("[VALIDATION_INDEX_BOUNDS]")
                elif "[UNVALIDATED_INDEX]" in ifstmts_tags:
                    total_tags.append("[UNVALIDATED_INDEX]")
                    total_tags.append("[CRITICAL]")
                else:
                    # IfStatement가 있지만, 검증 관련 태그가 없음
                    if any(tag.startswith("[SINK:") for tag in my_tags):
                        total_tags.append("[UNVALIDATED]")
                        total_tags.append("[CRITICAL]")

            
                
        #3-2.Assignment 후처리: ALLOCA가 호출된 할당문
        #if "[STACK_ALLOC]" in child_tags:
    

    if debug: print(f"DEBUG:[extract_statements]  : after Post processing of AssignmentExpression:: type : {t}, total_tags: {total_tags}")

    # res 채우기
    # --- 1. 복합문 헤더만 한 줄로 추가 : 자신노드의 TAG만  ---
    if t in {"IfStatement", "ForStatement", "WhileStatement", "SwitchStatement"}:
        code = ast_node.get("code", "")
        # ForStatement node의 경우 code속성에 이미 header  부분만 포함됨 
        if t == "ForStatement":
            res.append({"code": code, "tags": my_tags})
        else:
            header = code.split("{")[0].strip() if "{" in code else code.strip()
            if header:
                res.append({"code": header, "tags":my_tags})

    # ---2. 일반적인 Statement
    else:
        res.append({"code": ast_node["code"], "tags": total_tags})
   
    if debug: print(f"DEBUG:[extract_statements]  : just before return:: type : {t}, total_tags: {total_tags}")   

    return res


# 함수 AST에서 핵심 statement 노드만 1차원 리스트로 수집
# 재귀적으로 호출되며, 현재 노드가 statement(= 핵심 실행 단위)이면 stmts 리스트에 추가합니다 → 즉, 코드에서 실제 실행 단위가 될 만한 statement만 골라냄
# 그 후 자식(children) 노드에 대해서도 반복적으로 탐색 
def collect_statements(node, res=None, parent=None, parent_chain=None):
    if parent_chain is None:
            parent_chain = []
    if res is None:
        res = []
    if not isinstance(node, dict):
        return

    t = node.get("nodeType")
    
    if t in {"VariableDeclaration", "ArrayDeclaration", "PointerDeclaration", "AssignmentExpression", "StandardLibCall", "UserDefinedCall", "IfStatement", "ForStatement", "WhileStatement", "SwitchStatement"}:
        if t == "VariableDeclaration" :
            if node.get("storage") is not None:
                return # skip(append 안함)
        # AssignmentExpression이면서 parent가 ForStatement인지 체크
        if t == "AssignmentExpression":
            if parent and parent.get("nodeType") == "ForStatement":
                    print(f"AssignmentExpression의 바로 위 parent는 ForStatement 입니다. : {node.get('code')}")
                    return # skip(append 안함)

        if t in ("StandardLibCall", "UserDefinedCall"):
            # StandardLibCall이면서 가장가까운 parent로 AssignmentExpression 있는지 확인
            assign = find_nearest_assignment_expr(parent_chain)
            if assign:
                print(f"[build_variant][walk_statement] : StandardLibCall/UserDefinedCall parent로 AssignmentExpression이 있습니다. : {node.get('code')}")
                return # skip(append 안함)    

        # ★ node와 함께 parent_chain을 저장
        res.append({"node": node, "parent_chain": list(parent_chain)})

    children = node.get("children", [])
    if isinstance(children, list):
        for c in children:
            # parent_chain에는 항상 dict만 추가
            if isinstance(node, dict):
                collect_statements(c, res, parent=node, parent_chain=parent_chain + [node])
            else:
                collect_statements(c, res, parent=node, parent_chain=parent_chain)
    return res


# AssignmentExpression(ArraySubscript) 블록은 항상 CompoundStatement 블록의 자식이어야 하며, idx도 “IfStatement → CompoundStatement → AssignmentExpression(ArraySubscript)” 식의 네스팅을 보장해야 함
# 예시) IfStatement(0.A4.A0) → CompoundStatement(0.A4.A0.A0) → AssignmentExpression(ArraySubscript)(0.A4.A0.A0.A0) 구조
def add_assignment_array_blocks(node, block_nodes, parent_idx, parent_counter):
    if not isinstance(node, dict):
        return
    t = node.get("nodeType")

    # ONLY CompoundStatement에서만 AssignmentExpression(ArraySubscript)를 추가
    if t == "CompoundStatement":
        # idx 부여 (부모 idx + ".A0", ".A1", ...)
        child_counter = parent_counter.get(parent_idx, 0)
        compound_idx = f"{parent_idx}.A{child_counter}"
        parent_counter[parent_idx] = child_counter + 1 # parent_counter[2] = 1을 하게되면 parent_counter = {2:1}이 됨. 즉 idx가 2인 블록아래 1개의 자식이 있음, 자식블록이 추가됨에 따라  parent_counter[2]의 값이 1씩 증가
    
        print(f"DEBUG: [add_assignment_array_blocks][t == 'CompoundStatement'] : child_counter : {child_counter}, parent_idx:{parent_idx}, parent_counter:{parent_counter}, parent_counter[{parent_idx}]:{parent_counter[parent_idx]}, compound_idx:{compound_idx}")
    
        block_nodes.append({
            "idx": compound_idx,
            "block_type": "CompoundStatement",
            "code": node.get("code"),
            "node": node
        })
        # 이제 이 CompoundStatement의 children에서 AssignmentExpression(ArraySubscript)를 찾기
        for c in node.get("children", []):
            if isinstance(c, dict) and c.get("nodeType") == "AssignmentExpression":
                left = c.get("children", [{}])[0]
                if left.get("nodeType") == "ArraySubscriptExpression":
                    code_str = c.get("code")
                    # --- 중복 체크 ---
                    already_exists = any(
                        b["block_type"] == "AssignmentExpression(ArraySubscript)" and b["code"] == code_str
                        for b in block_nodes
                    )
                    if not already_exists:
                        # 이때 idx는 compound_idx의 하위 (ex: "0.A4.A0.A0")
                        array_counter = parent_counter.get(compound_idx, 0)
                        assign_idx = f"{compound_idx}.A{array_counter}"
                        parent_counter[compound_idx] = array_counter + 1
                        print(f"DEBUG: [add_assignment_array_blocks][t == 'CompoundStatement,ArraySubscriptExpression'] : parent_counter:{parent_counter}, compound_idx:{compound_idx}, assign_idx:{assign_idx}")

                        block_nodes.append({
                            "idx": assign_idx,
                            "block_type": "AssignmentExpression(ArraySubscript)",
                            "code": c.get("code"),
                            "node": c
                        })

    # 자식 블록에 대해서도 동일하게 재귀 탐색 (only CompoundStatement만 대상)
    for c in node.get("children", []):
        add_assignment_array_blocks(c, block_nodes, parent_idx, parent_counter)


def walk_blocks(node, block_nodes, parent_idx=None, parent_counter=None):
    if not isinstance(node, dict):
        return
    if parent_counter is None:
        parent_counter = {}

    t = node.get("nodeType")
    cur_idx = None

   # 1. 블록 타입 등록 (parent-child idx로!)
    if t in BLOCK_TYPES:

        # parent-child idx
            if parent_idx is None:
                # 최상위(루트)
                idx = len([b for b in block_nodes if "." not in str(b["idx"])])
                cur_idx = str(idx)
            else:
                child_counter = parent_counter.get(parent_idx, 0)
                cur_idx = f"{parent_idx}.A{child_counter}"
                parent_counter[parent_idx] = child_counter + 1

            block_nodes.append({
                "idx": cur_idx,
                "block_type": t,
                "code": node.get("code"),
                "node": node
            })

            # ForStatement/IfStatement 내부도 하위 블록으로 재귀적 처리
            # 자식들은 모두 cur_idx를 parent로 할당!
            for c in node.get("children", []):
                walk_blocks(c, block_nodes, parent_idx=cur_idx, parent_counter=parent_counter)
            return

    # 2. memcpy/memmove 블록(구조체 멤버) 등록
    if t == "StandardLibCall" and node.get("name") in {"memcpy", "memmove"}:
        params = node.get("children", [])
        # struct.member 인지 체크(실전 상황에 맞게 보완 가능)
        if params and params[0].get("children", []):
            first_param = params[0]["children"][0]
            if first_param.get("nodeType") == "MemberAccess":
                funcname = node.get("name")
                block_type = f"StandardLibCall({funcname}:struct.member)"
                # 계층 idx
                child_counter = parent_counter.get(parent_idx, 0)
                cur_idx = f"{parent_idx}.A{child_counter}"
                parent_counter[parent_idx] = child_counter + 1

                block_nodes.append({
                    "idx": cur_idx,
                    "block_type": block_type,
                    "code": node.get("code"),
                    "node": node
                })
    
    # 3. AssignmentExpression(ArraySubscript) 등록 (중복 방지!)
    if t == "AssignmentExpression":
        children = node.get("children", [])
        if children and children[0].get("nodeType") == "ArraySubscriptExpression":
            block_type = "AssignmentExpression(ArraySubscript)"
            code_str = node.get("code")
            # 중복 체크 (code + parent_idx)
            already_exists = any(
                b["block_type"] == block_type and b["code"] == code_str and b["idx"].startswith(str(parent_idx))
                for b in block_nodes
            )
            if not already_exists:
                child_counter = parent_counter.get(parent_idx, 0)
                cur_idx = f"{parent_idx}.A{child_counter}"
                parent_counter[parent_idx] = child_counter + 1
                block_nodes.append({
                    "idx": cur_idx,
                    "block_type": block_type,
                    "code": code_str,
                    "node": node
                })

    # 4-추가. COMMAND_FUNCS 블록 등록
    if t == "StandardLibCall" and node.get("name") in COMMAND_FUNCS:
        funcname = node.get("name")
        block_type = f"StandardLibCall({funcname})"
        child_counter = parent_counter.get(parent_idx, 0)
        cur_idx = f"{parent_idx}.A{child_counter}"
        parent_counter[parent_idx] = child_counter + 1

        # 태그는 statement 수집에서 다시 모으지만, block_code에 주석으로도 남겨 가독성 ↑
        block_code_with_tag = node.get("code", "") + "\n// [SINK:COMMAND_EXECUTION] [SINK:FUNC:STD:{}] [CRITICAL]".format(funcname)

        block_nodes.append({
            "idx": cur_idx,
            "block_type": block_type,
            "code": node.get("code"),
            "node": node
        })
    
    # 4. 모든 children을 재귀(최상위/기타 노드 포함)  
    for c in node.get("children", []):
        walk_blocks(c, block_nodes, parent_idx=parent_idx, parent_counter=parent_counter)   


#####################################################################
# ── 모듈: Variant JSON 빌더
#####################################################################
def build_variant(root_func, cwe_id="Qeury", pattern_id="Query", window=3, src="SARD", file_name="unknown.c", desc="",max_n=5, max_m=3):

    # ── 1.  함수 인자 추출 → 글로벌 컨텍스트에 저장
    set_func_args(root_func)   

    # ── 2. 함수 본문(CompoundStatement) 추출
    body = None
    for child in root_func.get("children", []):
        if child.get("nodeType") == "CompoundStatement":
            body = child
            break
    if body is None:
        raise ValueError("CompoundStatement(함수 본문)이 없습니다.")
    
    #================================================================================================================
    # 토큰 단위 임베딩
    #=================================================================================================================

    stmts = collect_statements(body)
    print(f"[DEBUG] collect_statements -> {len(stmts)} items", flush=True)


    # ── 1. 각 statement를 태깅
    count =0
    out_stmts = []
    for i, s in enumerate(stmts):
        n = s["node"]
        print(f"[DEBUG] stmt[{i}]: {n.get('nodeType')} | {n.get('code', '')[:80]!r}", flush=True)
              
        debugMode=False
        
        #if s['node'].get('nodeType') == "AssignmentExpression":
        #print(f"\n[DEBUG:[build_variant]  before extract_statements , {s['node'].get('nodeType')}:: {s['node'].get('code')} ")
        #    debugMode=True
        e_stmts = extract_statements(s["node"], s["parent_chain"], debug=debugMode )
        #print(f"[DEBUG:[build_variant] after extract_statements  : e_stmts :{e_stmts}\n")

        out_stmts += e_stmts
    
    # ── 2. tokens, slices
    tokens = []
    for s in out_stmts:
        if s["code"] is None:
            continue

        line = s["code"].strip()
        tag = " ".join(s["tags"])
        tokens.append(f"{line} // {tag}" if tag else line)

    slices = []
    for i in range(len(tokens) - window + 1):
        win = tokens[i:i+window]
        tags_in_slice = []
        for tokline in win:
            if "//" in tokline:
                tags_in_slice += [t for t in tokline.split() if t.startswith("[")]
        slices.append({
            "idx_range": [i, i+window-1],
            "tokens": win,
            "tags": tags_in_slice,
            "weight": get_statement_weight(tags_in_slice),
            "embedding": mean_pool_embed(" ".join(win))
        })

    #================================================================================================================
    # 블록 단위 임베딩  
    #================================================================================================================
    print("\n *********************** 블록단위 임베딩 **************************************************************(())")
    # ── 1. 블록 추출
    block_nodes = []
    walk_blocks(body, block_nodes)
    
    # ── 2.블록 내 실행단위 
    blocks = []

    for b in block_nodes:        
        block_root_node = b.get('node', b)
        stmt_nodes = collect_statements(block_root_node)
        #print(f"\n stmt_nodes: {stmt_nodes} ")  
       
        sum_tags = []
        for s_entry in stmt_nodes:
  
            stmts_for_tag = extract_statements(s_entry["node"], s_entry["parent_chain"], debug=False )
            for stmt in stmts_for_tag: 
                sum_tags += stmt.get("tags", [])

        sum_tags = list(dict.fromkeys(sum_tags))
        #print(f"sum_tags : {sum_tags}")

        t = block_root_node.get("nodeType")

        block_code_with_tag = ""
        if t == "ForStatement":
            for_header = block_root_node["code"]
            for_body = block_root_node.get("children")[3].get("code")
            block_code_with_tag = for_header + for_body
        else: 
          block_code_with_tag = block_root_node["code"]

        block_code_with_tag += "\n// " + " ".join(sum_tags)

        block_dict = {
            "block_type": b["block_type"],   # 또는 t
            "tags":       sum_tags
        }

        blocks.append({
                "idx": b["idx"],
                "block_type": block_dict["block_type"],
                "block_code": block_code_with_tag,
                "tags": sum_tags,
                "weight": get_block_weight(block_dict),  
                "embedding": mean_pool_embed(block_code_with_tag)
        })
    
    #================================================================================================================
    # 함수 단위 임베딩 
    #=================================================================================================================

    # 대표 임베딩
    rep = calc_representative_embedding(slices, blocks)

     #all_tags 수집 후 CWE 자동 매핑
    all_tags = set()
    for s in slices:
        for t in s.get("tags", []):
            all_tags.add(t)
    for b in blocks:
        for t in b.get("tags", []):
            all_tags.add(t)

    cwe_id_final = cwe_id
    if "[SINK:COMMAND_EXECUTION]" in all_tags:
        cwe_id_final = "CWE-78"
    
    return {
        "variant_id": str(uuid.uuid4())[:12],
        "cwe_id": "["+cwe_id_final+"]",
        "pattern_id": pattern_id,
        "meta": {"source": src, "file": file_name, "description": desc},
        "representative_embedding": rep,
        "statement_slices": slices,
        "blocks": blocks,
        "critical_slices": [s for s in slices if "[CRITICAL]" in s["tags"]][:max_n],
        "critical_blocks":  [b for b in blocks if "[CRITICAL]" in b["tags"]][:max_m]
    }



def set_func_args(func_node):
    """FunctionDefinition 노드에서 함수 인자 추출 후, 글로벌 컨텍스트에 저장"""
    args = set()
    if func_node.get("nodeType") == "FunctionDefinition":
        for child in func_node.get("children", []):
            if child.get("nodeType") == "ParameterList":
                args = set(p.get("name") for p in child.get("children", []) if "name" in p)
    
    print("ParameterList" ,  args)
    
    TAG_CONTEXT["func_args"] = args


def make_json_serializable(obj):
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, np.float32) or isinstance(obj, np.float64):
        return float(obj)
    elif isinstance(obj, dict):
        return {k: make_json_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [make_json_serializable(v) for v in obj]
    else:
        return obj
    
def remove_embeddings(obj):
    if isinstance(obj, dict):
        return {k: ([] if k in {"embedding", "representative_embedding"} else remove_embeddings(v))
                for k, v in obj.items()}
    elif isinstance(obj, list):
        return [remove_embeddings(v) for v in obj]
    else:
        return obj



#####################################################################
# ── Main: JSON variant 생성 
#####################################################################
if __name__ == "__main__":

    #CWE121_type_overrun_memmove_01_bad /CWE121_type_overrun_memmove_01_good 
    
    #KCWE121_CWE129_fgets_01_bad/ KCWE121_CWE129_fgets_01_goodG2B / KCWE121_CWE129_fgets_01_goodB2G,  
    #CWE121_CWE129_fscanf_21_badSink / CWE121_CWE129_fscanf_21_goodB2G1Sink / CWE121_CWE129_fscanf_21_goodB2G2Sink / CWE121_CWE129_fscanf_21_goodG2BSink
    
    #CWE121_CWE131_loop_01_bad / CWE121_CWE131_loop_01_goodG2B
    #CWE121_CWE131_memcpy_01_bad/ CWE121_CWE131_memcpy_01_goodG2B

    # --------------

    #CWE122_type_overrun_memmove_01_bad / CWE122_type_overrun_memmove_01_good
    
    #CWE122_CWE129_fgets_01_bad/ CWE122_CWE129_fgets_01_goodB2G / CWE122_CWE129_fgets_01_goodG2B
    #CWE122_CWE129_fscanf_21_badSink / CWE122_CWE129_fscanf_21_goodB2G1Sink / CWE122_CWE129_fscanf_21_goodB2G2Sink / CWE122_CWE129_fscanf_21_goodG2BSink
    #CWE122_CWE131_loop_01_bad / CWE122_CWE131_loop_01_goodG2B

    #CWE122_CWE131_memcpy_01_bad
    
    import os

    ast_json_file_path = os.path.join("data", "CWE121_CWE129_fscanf_21_goodB2G1Sink.json")

    with open(ast_json_file_path, "r", encoding="utf-8") as f:
        query_func = json.load(f)
  
  
    # JSON 저장 (임베딩 벡터) : DB용
    #pattern_variant = build_variant(query_func, "CWE-121", "CWE-121_TypeOverrun-Stack-P1", file_name="CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01.c", desc="구조체 복사 혹은 memcpy/memmove에서 구조체 전체로 복사되는 오버런 취약점 (Stack 기반)")
    #pattern_variant = build_variant(query_func, "CWE-121", "CWE-121_129-Stack-P1", file_name="CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_01.c", desc="입력값을 하한만 검증하고 스택 배열 인덱스로 사용하는 패턴")
    #pattern_variant = build_variant(query_func, "CWE-121", "CWE-121_129-ArgIndex-P1", file_name="CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_21.c", desc="함수 인자(예:data)로 전달받은 값을 검증 없이 입력값을 하한만 검증하고 스택 배열 인덱스로 사용하는 패턴 (상한 검증 누락)")
    #pattern_variant = build_variant(query_func, "CWE-121", "CWE-121_131-Stack-Loop-P1", file_name="CWE121_Stack_Based_Buffer_Overflow__CWE131_loop_01.c", desc="ALLOCA로 타입 크기 없이 배열 크기만큼 메모리 할당 후, for 루프를 통해 인덱싱하는 버퍼 오버플로우 패턴")
    #pattern_variant = build_variant(query_func, "CWE-121", "CWE-121_131-Stack-memcpy-P1", file_name="CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_01.c", desc="ALLOCA로 타입 크기 없이 배열 크기만큼 메모리 할당 후, memcpy 등 함수호출 버퍼 오버플로우 패턴")


    #pattern_variant = build_variant(query_func, "CWE-122", "CWE-122_TypeOverrun-Heap-P1", file_name="CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_01.c", desc="구조체 복사 혹은 memcpy/memmove에서 구조체 전체로 복사되는 오버런 취약점 (Heap 기반)")
    #pattern_variant = build_variant(query_func, "CWE-122", "CWE-122_129-Heap-P1", file_name="CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_01.c", desc="구조체 복사 혹은 memcpy/memmove에서 구조체 전체로 복사되는 오버런 취약점 (Heap 기반)")
    #pattern_variant = build_variant(query_func, "CWE-122", "CWE-122_129-ArgIndex-Heap-P1", file_name="CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_21.c", desc="함수 인자(예:data)로 전달받은 값을 검증 없이 입력값을 하한만 검증하고 스택 배열 인덱스로 사용하는 패턴 (상한 검증 누락)")
    #pattern_variant = build_variant(query_func, "CWE-122", "CWE-122_131-Heap-Loop-P1", file_name="CWE122_Heap_Based_Buffer_Overflow__CWE131_loop_01.c", desc="malloc로 타입 크기 없이 메모리 할당 후, for 루프를 통해 인덱싱하는 버퍼 오버플로우 패턴")
    #pattern_variant = build_variant(query_func, "CWE-122", "CWE-122_131-Heap-memcpy-P1", file_name="CWE122_Heap_Based_Buffer_Overflow__CWE131_memcpy_01.c", desc="malloc로 타입 크기 없이 메모리 할당 후, memcpy 등 함수호출 오버플로우 패턴")


    #with open("pattern_variant.json", "w", encoding="utf-8") as f:
    #    json.dump(make_json_serializable(pattern_variant), f, indent=2, ensure_ascii=False)

    # JSON 저장 (임베딩 벡터) : 쿼리용
    query_variant = build_variant(query_func)
    with open("query_variant.json", "w", encoding="utf-8") as f:
       json.dump(make_json_serializable(query_variant), f, indent=2, ensure_ascii=False)

    # JSON 저장 (embedding 제거): 디버그용
    with open("k_variant.json", "w", encoding="utf-8") as f:
       json.dump(remove_embeddings(query_variant), f, indent=2, ensure_ascii=False)
