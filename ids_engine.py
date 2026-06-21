"""
IDS engine process — packet capture, AI analysis, persistence, telemetry.

Run standalone:  python ids_engine.py
Started by supervisor from main.py (separate OS process from uni-srver.py).
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path

import dotenv
from scapy.all import sniff

from ai.retrainer import retrain
from alerts.dangerous_burst import maybe_alert_dangerous_burst
from api_client.sender import start_sender
from engine.dns_behavior import detect_dns
from ids import metrics
from ids.ai_analysis import analyze_packet
from ids.event_timestamp import resolve_event_epoch_seconds
from ids.packet_capture import make_capture_callback, preprocess_packet
from ids.packet_queue import PacketQueues
from ids.worker_monitoring import WorkerMonitor
from intelligence.sensor_process import (
    register_sensor_pid_cleanup,
    touch_sensor_heartbeat,
    write_sensor_pid,
)
from logging_config import get_logger
from storage import persistence
from storage.memory_store import logs, sync_stats_from_persistence

dotenv.load_dotenv()
_perf_env = Path(__file__).resolve().parent / "config" / "ids-performance.env"
if _perf_env.is_file():
    dotenv.load_dotenv(_perf_env, override=False)

_CPU_COUNT = os.cpu_count() or 4
_DEFAULT_WORKERS = min(max(_CPU_COUNT, 4), 16)
_WORKER_COUNT = max(1, int(os.getenv("IDS_WORKER_COUNT", str(_DEFAULT_WORKERS)) or str(_DEFAULT_WORKERS)))
_PREPROCESS_WORKERS = max(
    0,
    int(os.getenv("IDS_PREPROCESS_WORKERS", str(min(4, _CPU_COUNT))) or str(min(4, _CPU_COUNT))),
)
_PERSIST_SAFE_LOGS = (os.getenv("IDS_PERSIST_SAFE_LOGS", "false") or "false").lower() == "true"
_HEARTBEAT_INTERVAL = float(os.getenv("IDS_HEARTBEAT_INTERVAL_SEC", "5") or "5")

logger = get_logger(__name__)

_queues = PacketQueues()
_monitor = WorkerMonitor()
_worker_threads: dict[str, threading.Thread] = {}
_stop_event = threading.Event()


def _should_persist_log(classification: str) -> bool:
    return classification != "safe" or _PERSIST_SAFE_LOGS


def _event_time_for_log(packet_dict: dict, data: dict) -> float:
    return resolve_event_epoch_seconds(
        packet_send_time=packet_dict.get("packet_send_time") or data.get("packet_send_time"),
        event_origin_time=packet_dict.get("event_origin_time") or data.get("event_origin_time"),
        device_timestamp=packet_dict.get("device_timestamp") or data.get("device_timestamp"),
        fallback_ingestion_time=packet_dict.get("captured_at") or data.get("server_time"),
    )


def _process_packet(packet_dict: dict) -> None:
    data = packet_dict.get("data")
    if not data:
        return

    captured_at = _event_time_for_log(packet_dict, data)
    url = packet_dict.get("url")
    http_meta = packet_dict.get("http")
    if http_meta:
        data["http"] = http_meta
        if not url and http_meta.get("url"):
            url = http_meta["url"]
    if url:
        data["url"] = url

    dns_event = packet_dict.get("dns_event")
    dns_reasons = detect_dns(data.get("src_ip"), dns_event) if dns_event else []
    if dns_event:
        data["dns"] = dns_event

    under_pressure = _queues.pressure() > 0.65

    result = analyze_packet(
        data,
        dns_reasons=dns_reasons,
        queue_pressure=_queues.pressure(),
        skip_heavy_enrichment=under_pressure,
    )

    ti_ip = result.get("ti_ip")
    ti_url = result.get("ti_url")

    label = result["classification"]
    reasons = result["reasons"]
    risk_score = result["risk_score"]

    persistence.record_analysis_result(label, src_ip=data.get("src_ip"), url=data.get("url"))

    maybe_alert_dangerous_burst(
        src_ip=data.get("src_ip"),
        classification=label,
        risk_score=risk_score,
        reasons=reasons,
    )

    log_entry = {
        "time": captured_at,
        "src_ip": data["src_ip"],
        "dst_ip": data["dst_ip"],
        "src_port": data.get("src_port"),
        "dst_port": data.get("dst_port"),
        "protocol": data.get("protocol"),
        "duration": data.get("duration"),
        "packets": data.get("packets"),
        "bytes": data.get("bytes"),
        "url": data.get("url"),
        "http": data.get("http"),
        "status": label,
        "reasons": reasons,
        "ai_label": result.get("ai_label"),
        "ai_score": result.get("ai_score"),
        "risk_score": risk_score,
        "confidence": result.get("confidence"),
        "anomaly_score": result.get("anomaly_score"),
        "ti_ip": ti_ip,
        "ti_url": ti_url,
        "dns": data.get("dns"),
        "ai_explanation": result.get("explanation"),
    }
    for k in ("packet_send_time", "event_origin_time", "device_timestamp"):
        v = packet_dict.get(k)
        if v is None:
            v = data.get(k)
        if v is not None:
            log_entry[k] = v

    logs.append(log_entry)

    if _should_persist_log(label):
        persistence.enqueue_packet_log(log_entry)

    persistence.enqueue_ai_history(
        {
            "analyzed_at": captured_at,
            "src_ip": data.get("src_ip"),
            "dst_ip": data.get("dst_ip"),
            "classification": label,
            "ai_score": result.get("ai_score"),
            "risk_score": risk_score,
            "rf_prob": result.get("rf_prob"),
            "anomaly_strength": result.get("anomaly_strength"),
            "explanation": result.get("explanation"),
        }
    )

    features = data.get("features")
    if features is not None:
        persistence.enqueue_training_sample(features, label, created_at=captured_at)

    metrics.inc("ids_packets_analyzed_total")
    metrics.set_gauge("ids_ai_score_last", float(result.get("ai_score") or 0))


def _preprocess_loop(worker_id: str) -> None:
    logger.info("IDS preprocess %s started", worker_id)
    while not _stop_event.is_set():
        pkt = _queues.dequeue_raw_packet(timeout=1.0)
        if pkt is None:
            continue
        try:
            item = preprocess_packet(pkt)
            if item is None:
                continue
            if not _queues.enqueue_packet(item):
                logger.debug("Packet dropped after preprocess enqueue")
        finally:
            _queues.raw_queue.task_done()


def _worker_loop(worker_id: str) -> None:
    logger.info("IDS worker %s started", worker_id)
    while not _stop_event.is_set():
        _monitor.heartbeat(worker_id)
        packet_dict = _queues.dequeue_packet(timeout=1.0)
        if packet_dict is None:
            continue
        try:
            _queues.process_with_retry(_process_packet, packet_dict)
        finally:
            _queues.packet_queue.task_done()


def _restart_worker(worker_id: str) -> None:
    old = _worker_threads.get(worker_id)
    if old and old.is_alive():
        return
    _monitor.register_restart(worker_id)
    t = threading.Thread(target=_worker_loop, args=(worker_id,), daemon=True, name=worker_id)
    _worker_threads[worker_id] = t
    t.start()


def _log_writer_loop() -> None:
    while not _stop_event.is_set():
        try:
            entry = _queues.log_queue.get(timeout=0.5)
        except Exception:
            persistence.flush_batches()
            continue
        if entry is None:
            break
        try:
            persistence.enqueue_packet_log(entry)
        except Exception:
            logger.error("Log writer enqueue failed", exc_info=True)
        finally:
            _queues.log_queue.task_done()


def _heartbeat_loop() -> None:
    while not _stop_event.is_set():
        touch_sensor_heartbeat()
        _stop_event.wait(_HEARTBEAT_INTERVAL)


def auto_retrain() -> None:
    while not _stop_event.is_set():
        try:
            if _stop_event.wait(3600 * 24):
                break
            logger.info("Starting scheduled model retraining")
            retrain()
        except Exception:
            logger.error("Scheduled model retraining failed", exc_info=True)


def start() -> None:
    logger.info("IDS engine starting")
    write_sensor_pid()
    register_sensor_pid_cleanup()
    touch_sensor_heartbeat()

    persistence.init_persistence()
    sync_stats_from_persistence()

    logger.info(
        "Pipeline: workers=%d preprocess=%d packet_queue=%d raw_queue=%d persist_safe=%s",
        _WORKER_COUNT,
        _PREPROCESS_WORKERS,
        _queues.packet_queue.maxsize,
        _queues.raw_queue.maxsize,
        _PERSIST_SAFE_LOGS,
    )

    threading.Thread(target=persistence.writer_loop, args=(_stop_event,), daemon=True).start()
    threading.Thread(target=_log_writer_loop, daemon=True).start()
    threading.Thread(target=start_sender, daemon=True).start()
    threading.Thread(target=auto_retrain, daemon=True).start()
    threading.Thread(target=_heartbeat_loop, daemon=True).start()

    worker_ids = [f"worker-{i}" for i in range(_WORKER_COUNT)]
    for wid in worker_ids:
        _restart_worker(wid)

    if _PREPROCESS_WORKERS > 0:
        for i in range(_PREPROCESS_WORKERS):
            threading.Thread(
                target=_preprocess_loop,
                args=(f"preprocess-{i}",),
                daemon=True,
                name=f"preprocess-{i}",
            ).start()

    _monitor.start(
        health_fn=lambda: {**_queues.health(), **persistence.load_statistics_for_api()},
        restart_worker_fn=_restart_worker,
        worker_ids=worker_ids,
    )

    on_captured = persistence.record_captured_event
    use_preprocess = _PREPROCESS_WORKERS > 0
    callback = make_capture_callback(
        on_captured=on_captured,
        enqueue=_queues.enqueue_packet,
        enqueue_raw=_queues.enqueue_raw_packet if use_preprocess else None,
        should_sample=_queues.should_sample_under_pressure,
    )

    iface = os.getenv("SNIFFER_INTERFACE", "eth0")
    bpf_filter = os.getenv("SNIFFER_BPF", "ip")
    logger.info("Starting packet capture on iface=%s filter=%s", iface, bpf_filter)
    sniff(prn=callback, store=False, iface=iface, filter=bpf_filter)


if __name__ == "__main__":
    from bootstrap_db import bootstrap_database

    bootstrap_database()
    try:
        start()
    except KeyboardInterrupt:
        _stop_event.set()
        persistence.shutdown_persistence()
