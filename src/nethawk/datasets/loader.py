"""Dataset loading with an explicit real-data / demo-data distinction."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from .. import config
from ..preprocessing.clean import prepare_dataframe
from ..schema import LABEL_COLUMN
from .synthetic import generate_dataset

SOURCE_CICIDS = "CIC-IDS2017"
SOURCE_DEMO = "DEMO_SYNTHETIC"


@dataclass
class LoadedDataset:
    frame: pd.DataFrame
    source: str
    files: list[str]

    @property
    def is_real(self) -> bool:
        return self.source == SOURCE_CICIDS

    def summary(self) -> str:
        label_counts = self.frame[LABEL_COLUMN].value_counts().to_dict()
        return (f"{self.source}: {len(self.frame)} rows from {len(self.files)} file(s); "
                f"labels={label_counts}")


def find_cicids_csvs(directory: Path | None = None) -> list[Path]:
    directory = Path(directory) if directory else config.CICIDS_DIR
    if not directory.exists():
        return []
    return sorted(p for p in directory.rglob("*.csv") if p.stat().st_size > 1024)


def load_cicids(directory: Path | None = None,
                max_rows_per_file: int | None = 150_000) -> LoadedDataset:
    """Load and clean every CIC-IDS2017 CSV found in the dataset directory."""
    files = find_cicids_csvs(directory)
    if not files:
        raise FileNotFoundError(
            f"No CIC-IDS2017 CSV files found in {directory or config.CICIDS_DIR}. "
            "See data/README.md for download instructions."
        )
    frames = []
    for path in files:
        raw = pd.read_csv(path, low_memory=False, nrows=max_rows_per_file,
                          encoding="latin-1", skipinitialspace=True)
        frames.append(prepare_dataframe(raw))
    frame = pd.concat(frames, ignore_index=True)
    return LoadedDataset(frame=frame, source=SOURCE_CICIDS,
                         files=[p.name for p in files])


def load_demo(rows_per_class: int = 1200, seed: int = 42,
              path: Path | None = None) -> LoadedDataset:
    """Load the bundled demo CSV, generating it first if it does not exist."""
    path = Path(path) if path else config.DEMO_DATASET_PATH
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        generate_dataset(rows_per_class=rows_per_class, seed=seed).to_csv(path, index=False)
    frame = prepare_dataframe(pd.read_csv(path))
    return LoadedDataset(frame=frame, source=SOURCE_DEMO, files=[path.name])


def load_training_data(prefer_real: bool = True) -> LoadedDataset:
    """Real CIC-IDS2017 if present, otherwise the clearly-labelled demo data."""
    if prefer_real and find_cicids_csvs():
        return load_cicids()
    return load_demo()
