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
    "[SINK:COMMAND_EXECUTION]"              : 3.5,  # CWE78의 system, popen, sprintf 등으로 취약한 쉘 문자열을 주입
    "[STRUCT_OVERRUN]"                      : 3.8,  # 멤버 대신 구조체 전체 크기로 복사한다” 는 원인을 나타냄
    "[TYPE_OVERRUN]"                        : 3.8,  # 타입 불일치 복사
    "[STACK_OVERRUN]"                       : 3.8,  # 스택-버퍼 대상 오버런: 스택 메모리(지역 변수, ALLOCA 등)에서 할당된 버퍼의 크기를 잘못 계산하거나, 할당 이상으로 접근할 때
    "[HEAP_OVERRUN]"                        : 3.8,  # 힙-버퍼 대상 오버런
    "[OVERFLOW_LOOP_COPY]"                  : 3.6,  # 특화 취약 싱크 : “루프-복사+사이즈 미검증” 복합 조건. 
    "[CRITICAL]"                            : 5.0,  # “핵심 증거” 슬라이스 강조—대표 임베딩 집계 시 확실히 부각   
}