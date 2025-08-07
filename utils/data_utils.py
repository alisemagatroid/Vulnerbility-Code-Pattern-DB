
def extract_ui_data(query_variant, report, top_k=3):
    query_code = ""
    # critical slice, block은 [CRITICAL] 태그를 기반으로 생성이 되기 때문에 해당 Tagging 기준에 준하지 않는 코드는 아직 이 부분이 생성되지 않음
    if "critical_blocks" in query_variant and len(query_variant["critical_blocks"]) >= 1:
        query_code = (query_variant["critical_blocks"][0].get("block_code", []))
    else: 
        query_code = query_variant.get("code", "")
    tags1 = list(set(tag for s in query_variant.get("statement_slices", []) for tag in s.get("tags", [])))
    tag_weight_map = {} 
    for tag in tags1:
        w = TAG_W.get(tag, 1.0)
        tag_weight_map[tag] = tag_weight_map.get(tag, 0) + w
    tags2 = [x[0] for x in sorted(tag_weight_map.items(), key=lambda x: x[1], reverse=True)][:5]

    topk_table = []
    topk_candidates = []
    if report and "top_matched_variants" in report and len(report["top_matched_variants"]) > 0:
        for idx, cand in enumerate(report["top_matched_variants"][:top_k]):
            db_info = cand.get('db_variant_info', {})
            sig_ref = cand.get('signature_ref', {})
            # 패턴매치 판정
            match_info = cand.get('signature_pattern_matching', {})
            pattern_match = "  🟢 O" if match_info.get('tags_match', False) else "  🔴 X"
            topk_table.append({
                "Rank": idx+1,
                "CWE": db_info.get('cwe_id', ''),
                "Pattern ID": db_info.get('pattern_id', ''),
                "File": db_info.get('file', ''),
                "Description": sig_ref.get('description', ''),
                "Pattern Match": pattern_match   # 새 컬럼
            })
            topk_candidates.append(cand)
            
    return query_code, tags1, tags2, topk_table, topk_candidates, tag_weight_map