import logging
from pathlib import Path

from config.config_loader import config

LOG_FOLDER = Path(config["engine"]["log_directory"])

LOG_FOLDER.mkdir(exist_ok=True)

LOG_FILE = LOG_FOLDER / "audit.log"


logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

logger = logging.getLogger("AuditEngine")
