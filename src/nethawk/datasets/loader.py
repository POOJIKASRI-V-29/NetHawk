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
    # Cross-file duplicate rows dropped before splitting (leakage guard).
    duplicates_removed: int = 0

    @property
    def is_real(self) -> bool:
        return self.source == SOURCE_CICIDS

    def summary(self) -> str:
        label_counts = self.frame[LABEL_COLUMN].value_counts().to_dict()
        extra = (f"; {self.duplicates_removed} duplicate rows dropped"
                 if self.duplicates_removed else "")
        return (f"{self.source}: {len(self.frame)} rows from {len(self.files)} file(s){extra}; "
                f"labels={label_counts}")


def find_cicids_csvs(directory: Path | None = None) -> list[Path]:
    directory = Path(directory) if directory else config.CICIDS_DIR
    if not directory.exists():
        return []
    return sorted(p for p in directory.rglob("*.csv") if p.stat().st_size > 1024)


def _read_csv_sampled(path: Path, max_rows: int | None, seed: int) -> pd.DataFrame:
    """Read a CSV, sampling RANDOMLY if it is larger than max_rows.

    Reading only the first N rows (`nrows=N`) would bias the sample badly: the
    CIC-IDS2017 CSVs are time-ordered and each day's attacks are clustered in a
    specific window, so truncation can drop an entire attack class.  We instead
    count the rows first and draw a uniform random sample of line numbers.
    """
    raw = pd.read_csv(path, low_memory=False, encoding="latin-1",
                      skipinitialspace=True)
    if max_rows is not None and len(raw) > max_rows:
        raw = raw.sample(n=max_rows, random_state=seed)
    return raw


def load_cicids(directory: Path | None = None,
                max_rows_per_file: int | None = 200_000,
                seed: int = 42) -> LoadedDataset:
    """Load and clean every CIC-IDS2017 CSV found in the dataset directory."""
    files = find_cicids_csvs(directory)
    if not files:
        raise FileNotFoundError(
            f"No CIC-IDS2017 CSV files found in {directory or config.CICIDS_DIR}. "
            "See data/README.md for download instructions."
        )
    frames = []
    for path in files:
        raw = _read_csv_sampled(path, max_rows_per_file, seed)
        frames.append(prepare_dataframe(raw))
    frame = pd.concat(frames, ignore_index=True)

    # De-duplicate ACROSS files as well as within them.  Without this, a flow
    # that appears in two CSVs can land in both the train and the test split,
    # which leaks test data into training and inflates the reported score.
    before = len(frame)
    frame = frame.drop_duplicates().reset_index(drop=True)
    removed = before - len(frame)

    dataset = LoadedDataset(frame=frame, source=SOURCE_CICIDS,
                            files=[p.name for p in files])
    dataset.duplicates_removed = removed
    return dataset


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
