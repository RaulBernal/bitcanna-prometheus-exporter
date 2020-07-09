#!/usr/bin/env python3
# bitcannad-monitor.py
#
# Modified for BitCanna; Original work: 
# An exporter for Prometheus and Bitcoin Core.
#
# Copyright 2018 Kevin M. Gallagher
# Copyright 2019,2020 Jeff Stein
#
# Published at https://github.com/jvstein/bitcoin-prometheus-exporter
# Licensed under BSD 3-clause (see LICENSE).
#
# Dependency licenses (retrieved 2020-05-31):
#   prometheus_client: Apache 2.0
#   python-bitcoinlib: LGPLv3
#   riprova: MIT

import json
import logging
import time
import os
import signal
import sys
import socket

from datetime import datetime
from functools import lru_cache
from typing import Any
from typing import Dict
from typing import List
from typing import Union
from urllib.parse import quote

import riprova

from bitcanna.rpc import InWarmupError, Proxy
from prometheus_client import start_http_server, Gauge, Counter


logger = logging.getLogger("bitcanna-exporter")


# Create Prometheus metrics to track bitcannad stats.
bitcanna_BLOCKS = Gauge("bitcanna_blocks", "Block height")
bitcanna_DIFFICULTY = Gauge("bitcanna_difficulty", "Difficulty")
bitcanna_PEERS = Gauge("bitcanna_peers", "Number of peers")
bitcanna_HASHPS_NEG1 = Gauge(
    "bitcanna_hashps_neg1", "Estimated network hash rate per second since the last difficulty change"
)
bitcanna_HASHPS_1 = Gauge(
    "bitcanna_hashps_1", "Estimated network hash rate per second for the last block"
)
bitcanna_HASHPS = Gauge(
    "bitcanna_hashps", "Estimated network hash rate per second for the last 120 blocks"
)

bitcanna_ESTIMATED_SMART_FEE_GAUGES: Dict[int, Gauge] = {}

bitcanna_WARNINGS = Counter("bitcanna_warnings", "Number of network or blockchain warnings detected")
bitcanna_UPTIME = Gauge("bitcanna_uptime", "Number of seconds the bitcanna daemon has been running")

bitcanna_MEMINFO_USED = Gauge("bitcanna_meminfo_used", "Number of bytes used")
bitcanna_MEMINFO_FREE = Gauge("bitcanna_meminfo_free", "Number of bytes available")
bitcanna_MEMINFO_TOTAL = Gauge("bitcanna_meminfo_total", "Number of bytes managed")
bitcanna_MEMINFO_LOCKED = Gauge("bitcanna_meminfo_locked", "Number of bytes locked")
bitcanna_MEMINFO_CHUNKS_USED = Gauge("bitcanna_meminfo_chunks_used", "Number of allocated chunks")
bitcanna_MEMINFO_CHUNKS_FREE = Gauge("bitcanna_meminfo_chunks_free", "Number of unused chunks")

bitcanna_MEMPOOL_BYTES = Gauge("bitcanna_mempool_bytes", "Size of mempool in bytes")
bitcanna_MEMPOOL_SIZE = Gauge(
    "bitcanna_mempool_size", "Number of unconfirmed transactions in mempool"
)
bitcanna_MEMPOOL_USAGE = Gauge("bitcanna_mempool_usage", "Total memory usage for the mempool")

bitcanna_LATEST_BLOCK_HEIGHT = Gauge(
    "bitcanna_latest_block_height", "Height or index of latest block"
)
bitcanna_LATEST_BLOCK_WEIGHT = Gauge(
    "bitcanna_latest_block_weight", "Weight of latest block according to BIP 141"
)
bitcanna_LATEST_BLOCK_SIZE = Gauge("bitcanna_latest_block_size", "Size of latest block in bytes")
bitcanna_LATEST_BLOCK_TXS = Gauge(
    "bitcanna_latest_block_txs", "Number of transactions in latest block"
)

bitcanna_NUM_CHAINTIPS = Gauge("bitcanna_num_chaintips", "Number of known blockchain branches")

bitcanna_TOTAL_BYTES_RECV = Gauge("bitcanna_total_bytes_recv", "Total bytes received")
bitcanna_TOTAL_BYTES_SENT = Gauge("bitcanna_total_bytes_sent", "Total bytes sent")

bitcanna_LATEST_BLOCK_INPUTS = Gauge(
    "bitcanna_latest_block_inputs", "Number of inputs in transactions of latest block"
)
bitcanna_LATEST_BLOCK_OUTPUTS = Gauge(
    "bitcanna_latest_block_outputs", "Number of outputs in transactions of latest block"
)
bitcanna_LATEST_BLOCK_VALUE = Gauge(
    "bitcanna_latest_block_value", "bitcanna value of all transactions in the latest block"
)

bitcanna_BAN_CREATED = Gauge(
    "bitcanna_ban_created", "Time the ban was created", labelnames=["address", "reason"]
)
bitcanna_BANNED_UNTIL = Gauge(
    "bitcanna_banned_until", "Time the ban expires", labelnames=["address", "reason"]
)

bitcanna_SERVER_VERSION = Gauge("bitcanna_server_version", "The server version")
bitcanna_PROTOCOL_VERSION = Gauge("bitcanna_protocol_version", "The protocol version of the server")

bitcanna_SIZE_ON_DISK = Gauge("bitcanna_size_on_disk", "Estimated size of the block and undo files")

bitcanna_VERIFICATION_PROGRESS = Gauge(
    "bitcanna_verification_progress", "Estimate of verification progress [0..1]"
)

EXPORTER_ERRORS = Counter(
    "bitcanna_exporter_errors", "Number of errors encountered by the exporter", labelnames=["type"]
)
PROCESS_TIME = Counter(
    "bitcanna_exporter_process_time", "Time spent processing metrics from bitcanna node"
)


bitcanna_RPC_SCHEME = os.environ.get("bitcanna_RPC_SCHEME", "http")
bitcanna_RPC_HOST = os.environ.get("bitcanna_RPC_HOST", "localhost")
bitcanna_RPC_PORT = os.environ.get("bitcanna_RPC_PORT", "8332")
bitcanna_RPC_USER = os.environ.get("bitcanna_RPC_USER")
bitcanna_RPC_PASSWORD = os.environ.get("bitcanna_RPC_PASSWORD")
bitcanna_CONF_PATH = os.environ.get("bitcanna_CONF_PATH")
SMART_FEES = [int(f) for f in os.environ.get("SMARTFEE_BLOCKS", "2,3,5,20").split(",")]
REFRESH_SECONDS = float(os.environ.get("REFRESH_SECONDS", "300"))
METRICS_ADDR = os.environ.get("METRICS_ADDR", "")  # empty = any address
METRICS_PORT = int(os.environ.get("METRICS_PORT", "8334"))
RETRIES = int(os.environ.get("RETRIES", 5))
TIMEOUT = int(os.environ.get("TIMEOUT", 30))
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")


RETRY_EXCEPTIONS = (InWarmupError, ConnectionError, socket.timeout)

RpcResult = Union[Dict[str, Any], List[Any], str, int, float, bool, None]


def on_retry(err: Exception, next_try: float) -> None:
    err_type = type(err)
    exception_name = err_type.__module__ + "." + err_type.__name__
    EXPORTER_ERRORS.labels(**{"type": exception_name}).inc()
    logger.error("Retry after exception %s: %s", exception_name, err)


def error_evaluator(e: Exception) -> bool:
    return isinstance(e, RETRY_EXCEPTIONS)


@lru_cache(maxsize=1)
def rpc_client_factory():
    # Configuration is done in this order of precedence:
    #   - Explicit config file.
    #   - bitcanna_RPC_USER and bitcanna_RPC_PASSWORD environment variables.
    #   - Default bitcanna config file (as handled by Proxy.__init__).
    use_conf = (
        (bitcanna_CONF_PATH is not None)
        or (bitcanna_RPC_USER is None)
        or (bitcanna_RPC_PASSWORD is None)
    )

    if use_conf:
        logger.info("Using config file: %s", bitcanna_CONF_PATH or "<default>")
        return lambda: Proxy(btc_conf_file=bitcanna_CONF_PATH, timeout=TIMEOUT)
    else:
        host = bitcanna_RPC_HOST
        host = "{}:{}@{}".format(quote(bitcanna_RPC_USER), quote(bitcanna_RPC_PASSWORD), host)
        if bitcanna_RPC_PORT:
            host = f"{host}:{bitcanna_RPC_PORT}"
        service_url = f"{bitcanna_RPC_SCHEME}://{host}"
        logger.info("Using environment configuration")
        return lambda: Proxy(service_url=service_url, timeout=TIMEOUT)


def rpc_client():
    return rpc_client_factory()()


@riprova.retry(
    timeout=TIMEOUT,
    backoff=riprova.ExponentialBackOff(),
    on_retry=on_retry,
    error_evaluator=error_evaluator,
)
def bitcannarpc(*args) -> RpcResult:
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("RPC call: " + " ".join(str(a) for a in args))

    result = rpc_client().call(*args)

    logger.debug("Result:   %s", result)
    return result


def get_block(block_hash: str):
    try:
        block = bitcannarpc("getblock", block_hash, 2)
    except Exception:
        logger.exception("Failed to retrieve block " + block_hash + " from bitcannad.")
        return None
    return block


def smartfee_gauge(num_blocks: int) -> Gauge:
    gauge = bitcanna_ESTIMATED_SMART_FEE_GAUGES.get(num_blocks)
    if gauge is None:
        gauge = Gauge(
            "bitcanna_est_smart_fee_%d" % num_blocks,
            "Estimated smart fee per kilobyte for confirmation in %d blocks" % num_blocks,
        )
        bitcanna_ESTIMATED_SMART_FEE_GAUGES[num_blocks] = gauge
    return gauge


def do_smartfee(num_blocks: int) -> None:
    smartfee = bitcannarpc("estimatesmartfee", num_blocks).get("feerate")
    if smartfee is not None:
        gauge = smartfee_gauge(num_blocks)
        gauge.set(smartfee)


def refresh_metrics() -> None:
    uptime = int(bitcannarpc("uptime"))
    meminfo = bitcannarpc("getmemoryinfo", "stats")["locked"]
    blockchaininfo = bitcannarpc("getblockchaininfo")
    networkinfo = bitcannarpc("getnetworkinfo")
    chaintips = len(bitcannarpc("getchaintips"))
    mempool = bitcannarpc("getmempoolinfo")
    nettotals = bitcannarpc("getnettotals")
    latest_block = get_block(str(blockchaininfo["bestblockhash"]))
    hashps_120 = float(bitcannarpc("getnetworkhashps", 120))  # 120 is the default
    hashps_neg1 = float(bitcannarpc("getnetworkhashps", -1))
    hashps_1 = float(bitcannarpc("getnetworkhashps", 1))

    banned = bitcannarpc("listbanned")

    bitcanna_UPTIME.set(uptime)
    bitcanna_BLOCKS.set(blockchaininfo["blocks"])
    bitcanna_PEERS.set(networkinfo["connections"])
    bitcanna_DIFFICULTY.set(blockchaininfo["difficulty"])
    bitcanna_HASHPS.set(hashps_120)
    bitcanna_HASHPS_NEG1.set(hashps_neg1)
    bitcanna_HASHPS_1.set(hashps_1)
    bitcanna_SERVER_VERSION.set(networkinfo["version"])
    bitcanna_PROTOCOL_VERSION.set(networkinfo["protocolversion"])
    bitcanna_SIZE_ON_DISK.set(blockchaininfo["size_on_disk"])
    bitcanna_VERIFICATION_PROGRESS.set(blockchaininfo["verificationprogress"])

    for smartfee in SMART_FEES:
        do_smartfee(smartfee)

    for ban in banned:
        bitcanna_BAN_CREATED.labels(address=ban["address"], reason=ban["ban_reason"]).set(
            ban["ban_created"]
        )
        bitcanna_BANNED_UNTIL.labels(address=ban["address"], reason=ban["ban_reason"]).set(
            ban["banned_until"]
        )

    if networkinfo["warnings"]:
        bitcanna_WARNINGS.inc()

    bitcanna_NUM_CHAINTIPS.set(chaintips)

    bitcanna_MEMINFO_USED.set(meminfo["used"])
    bitcanna_MEMINFO_FREE.set(meminfo["free"])
    bitcanna_MEMINFO_TOTAL.set(meminfo["total"])
    bitcanna_MEMINFO_LOCKED.set(meminfo["locked"])
    bitcanna_MEMINFO_CHUNKS_USED.set(meminfo["chunks_used"])
    bitcanna_MEMINFO_CHUNKS_FREE.set(meminfo["chunks_free"])

    bitcanna_MEMPOOL_BYTES.set(mempool["bytes"])
    bitcanna_MEMPOOL_SIZE.set(mempool["size"])
    bitcanna_MEMPOOL_USAGE.set(mempool["usage"])

    bitcanna_TOTAL_BYTES_RECV.set(nettotals["totalbytesrecv"])
    bitcanna_TOTAL_BYTES_SENT.set(nettotals["totalbytessent"])

    if latest_block is not None:
        bitcanna_LATEST_BLOCK_SIZE.set(latest_block["size"])
        bitcanna_LATEST_BLOCK_TXS.set(latest_block["nTx"])
        bitcanna_LATEST_BLOCK_HEIGHT.set(latest_block["height"])
        bitcanna_LATEST_BLOCK_WEIGHT.set(latest_block["weight"])
        inputs, outputs = 0, 0
        value = 0
        for tx in latest_block["tx"]:
            i = len(tx["vin"])
            inputs += i
            o = len(tx["vout"])
            outputs += o
            value += sum(o["value"] for o in tx["vout"])

        bitcanna_LATEST_BLOCK_INPUTS.set(inputs)
        bitcanna_LATEST_BLOCK_OUTPUTS.set(outputs)
        bitcanna_LATEST_BLOCK_VALUE.set(value)


def sigterm_handler(signal, frame) -> None:
    logger.critical("Received SIGTERM. Exiting.")
    sys.exit(0)


def exception_count(e: Exception) -> None:
    err_type = type(e)
    exception_name = err_type.__module__ + "." + err_type.__name__
    EXPORTER_ERRORS.labels(**{"type": exception_name}).inc()


def main():
    # Set up logging to look similar to bitcanna logs (UTC).
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%SZ"
    )
    logging.Formatter.converter = time.gmtime
    logger.setLevel(LOG_LEVEL)

    # Handle SIGTERM gracefully.
    signal.signal(signal.SIGTERM, sigterm_handler)

    # Start up the server to expose the metrics.
    start_http_server(addr=METRICS_ADDR, port=METRICS_PORT)
    while True:
        process_start = datetime.now()

        # Allow riprova.MaxRetriesExceeded and unknown exceptions to crash the process.
        try:
            refresh_metrics()
        except riprova.exceptions.RetryError as e:
            logger.error("Refresh failed during retry. Cause: " + str(e))
            exception_count(e)
        except json.decoder.JSONDecodeError as e:
            logger.error("RPC call did not return JSON. Bad credentials? " + str(e))
            sys.exit(1)

        duration = datetime.now() - process_start
        PROCESS_TIME.inc(duration.total_seconds())
        logger.info("Refresh took %s seconds, sleeping for %s seconds", duration, REFRESH_SECONDS)

        time.sleep(REFRESH_SECONDS)


if __name__ == "__main__":
    main()
