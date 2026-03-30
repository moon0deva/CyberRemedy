"""
CyberRemedy ML — Auto-Training on Startup
==========================================
Detects missing models at startup and spawns training in the background.
Supports both TensorFlow (Python 3.9–3.12) and PyTorch (any version, 3.13+).
"""
import logging
import os
import subprocess
import sys
import threading
from pathlib import Path

logger = logging.getLogger("cyberremedy.ml.autotrain")

MODEL_FILES = [
    Path("models/anomaly_model.joblib"),
    Path("models/rf_attack_model.joblib"),
]
TRAINER_SCRIPT = Path("ml/lstm/trainer.py")

# Python version info for helpful log messages
_PY = sys.version_info
_PY_STR = f"{_PY.major}.{_PY.minor}.{_PY.micro}"


def models_exist() -> bool:
    return all(p.exists() and p.stat().st_size > 1000 for p in MODEL_FILES)


def _run_in_xterm() -> None:
    """Launch trainer inside an xterm window (falls back to background thread)."""
    script = Path("ml/lstm/trainer.py").resolve()
    python = sys.executable
    cmd_inner = (
        f"{python} {script} && "
        f"echo '' && echo '✅ Training complete — window closes in 5s' && sleep 5"
    )
    try:
        proc = subprocess.Popen(
            ["xterm", "-T", "CyberRemedy ML Training",
             "-geometry", "100x30",
             "-fg", "#00e5ff", "-bg", "#0a0e1a",
             "-fa", "Monospace", "-fs", "10",
             "-e", f"bash -c {repr(cmd_inner)}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        logger.info(f"[AutoTrain] xterm launched (PID {proc.pid})")
        proc.wait()
        logger.info("[AutoTrain] xterm closed")
    except FileNotFoundError:
        logger.info("[AutoTrain] xterm not available — running in background thread")
        _run_background()


def _run_background() -> None:
    """Run trainer in background subprocess; output goes to log."""
    python = sys.executable
    script = Path("ml/lstm/trainer.py").resolve()

    # Log a helpful message about which backend will be used
    if _PY >= (3, 13):
        logger.info(
            f"[AutoTrain] Python {_PY_STR} detected — "
            "trainer will use PyTorch backend (TensorFlow has no 3.13+ wheels)."
        )
    else:
        logger.info(
            f"[AutoTrain] Python {_PY_STR} detected — "
            "trainer will prefer TensorFlow, fallback to PyTorch."
        )

    try:
        result = subprocess.run(
            [python, str(script)],
            capture_output=True, text=True, timeout=600,
        )
        if result.returncode == 0:
            logger.info("[AutoTrain] Training completed successfully")
        else:
            logger.warning(f"[AutoTrain] Training failed:\n{result.stderr[-1000:]}")
    except subprocess.TimeoutExpired:
        logger.warning("[AutoTrain] Training timed out after 10 minutes")
    except Exception as exc:
        logger.error(f"[AutoTrain] Training error: {exc}")


def maybe_auto_train(force: bool = False) -> bool:
    """
    Called at server startup.
    If models are missing (or force=True), starts training in a background thread.
    """
    if not force and models_exist():
        logger.info("[AutoTrain] Models exist — skipping auto-training")
        return False

    if not TRAINER_SCRIPT.exists():
        logger.warning(f"[AutoTrain] Trainer not found: {TRAINER_SCRIPT}")
        return False

    logger.info("[AutoTrain] Models missing — starting auto-training in background …")
    Path("models").mkdir(exist_ok=True)

    t = threading.Thread(target=_run_in_xterm, daemon=True, name="ml-autotrainer")
    t.start()
    return True
