def search_logs(logs, ip=None, url=None, status=None, start_time=None, end_time=None, min_ai_score=None, limit=200):
    """
    Search IDS logs with multiple filters.
    Args:
        logs (list): list of log dicts
        ip (str): source or destination IP to match
        url (str): substring of URL to match
        status (str): 'safe', 'suspicious', 'dangerous'
        start_time (float): epoch timestamp to filter logs
        end_time (float): epoch timestamp to filter logs
        min_ai_score (float): minimum AI score threshold
        limit (int): max number of logs to return
    Returns:
        list: matching logs, newest first
    """
    results = []

    for log in logs:
        if ip and ip not in (log.get("src_ip"), log.get("dst_ip")):
            continue
        if url and (not log.get("url") or url not in log.get("url")):
            continue
        if status and log.get("status") != status:
            continue
        if start_time and log.get("time") < start_time:
            continue
        if end_time and log.get("time") > end_time:
            continue
        if min_ai_score and log.get("ai_score", 0) < min_ai_score:
            continue
        results.append(log)

    # Sort newest first
    results.sort(key=lambda x: x.get("time", 0), reverse=True)

    return results[:limit]
