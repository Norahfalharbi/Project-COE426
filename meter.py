"""Prepare and encrypt one day of household electricity readings.

Run from VS Code's terminal with:
    python meter.py

By default, the dataset must be named ``household_power_consumption.txt``
and placed in the same folder as this script.
"""

from argparse import ArgumentParser
from pathlib import Path
from time import perf_counter

import pandas as pd
from phe import paillier


DEFAULT_DATASET = Path(__file__).with_name("household_power_consumption.txt")


def load_dataset(file_path):
    """Read the UCI household electricity dataset."""
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(
            f"Dataset not found: {file_path}\n"
            "Place household_power_consumption.txt beside meter.py, "
            "or provide its path with --data-file."
        )

    return pd.read_csv(
        file_path,
        sep=";",
        na_values=["?"],
        low_memory=False,
    )


def prepare_meter_data(data):
    """Keep the required columns and convert minute power to energy in Wh."""
    required_columns = {"Date", "Time", "Global_active_power"}
    missing_columns = required_columns.difference(data.columns)
    if missing_columns:
        raise ValueError(f"Missing dataset columns: {sorted(missing_columns)}")

    meter_data = data[["Date", "Time", "Global_active_power"]].copy()
    meter_data["Datetime"] = pd.to_datetime(
        meter_data["Date"] + " " + meter_data["Time"],
        format="%d/%m/%Y %H:%M:%S",
    )
    meter_data = meter_data.dropna(subset=["Global_active_power"])

    # Global_active_power is the average kW during one minute.
    meter_data["Energy_Wh"] = meter_data["Global_active_power"] * (1000 / 60)

    return meter_data[["Datetime", "Global_active_power", "Energy_Wh"]]


def find_complete_days(meter_data):
    """Return dates containing all 1,440 one-minute readings."""
    readings_per_day = meter_data.groupby(meter_data["Datetime"].dt.date).size()
    return readings_per_day[readings_per_day == 1440]


def select_complete_day(meter_data, selected_date=None):
    """Select a requested complete date, or the first complete date available."""
    complete_days = find_complete_days(meter_data)
    if complete_days.empty:
        raise ValueError("The dataset does not contain a complete day.")

    if selected_date is None:
        selected_date = complete_days.index[0]
    else:
        selected_date = pd.to_datetime(selected_date, format="%Y-%m-%d").date()
        if selected_date not in complete_days.index:
            raise ValueError(
                f"{selected_date} is not a complete day with 1,440 readings."
            )

    one_day = meter_data[
        meter_data["Datetime"].dt.date == selected_date
    ].copy()

    return selected_date, one_day


def convert_to_hourly_readings(one_day):
    """Combine every 60 minute readings into one of 24 hourly readings."""
    if len(one_day) != 1440:
        raise ValueError(
            f"The day must contain 1,440 readings, but it contains {len(one_day)}."
        )

    hourly_data = (
        one_day.resample("h", on="Datetime")
        .agg(
            Energy_Wh=("Energy_Wh", "sum"),
            Number_of_readings=("Energy_Wh", "count"),
        )
        .reset_index()
    )

    if len(hourly_data) != 24:
        raise ValueError(
            f"Expected 24 hourly readings, but found {len(hourly_data)}."
        )

    if not hourly_data["Number_of_readings"].eq(60).all():
        raise ValueError("Some hours do not contain exactly 60 readings.")

    hourly_data["Energy_Wh_Integer"] = (
        hourly_data["Energy_Wh"].round().astype(int)
    )
    return hourly_data


def extract_readings(hourly_data):
    """Return the 24 integer energy readings that will be encrypted."""
    return hourly_data["Energy_Wh_Integer"].tolist()


def generate_keys(key_length=2048):
    """Generate a Paillier public/private key pair."""
    return paillier.generate_paillier_keypair(n_length=key_length)


def encrypt_readings(readings, public_key):
    """Encrypt every hourly reading with the Paillier public key."""
    return [public_key.encrypt(reading) for reading in readings]


def run_meter(data_file, selected_date=None):
    """Run the complete smart-meter preparation and encryption workflow."""
    data = load_dataset(data_file)
    meter_data = prepare_meter_data(data)
    selected_date, one_day = select_complete_day(meter_data, selected_date)
    hourly_data = convert_to_hourly_readings(one_day)
    readings = extract_readings(hourly_data)

    key_start = perf_counter()
    public_key, private_key = generate_keys()
    key_generation_time = perf_counter() - key_start

    encryption_start = perf_counter()
    encrypted_readings = encrypt_readings(readings, public_key)
    encryption_time = perf_counter() - encryption_start

    print(f"Selected date: {selected_date}")
    print(f"Minute readings: {len(one_day)}")
    print(f"Hourly readings: {len(readings)}")
    print(f"Hourly energy readings (Wh): {readings}")
    print(f"Encrypted readings created: {len(encrypted_readings)}")
    print(f"Key generation time: {key_generation_time:.4f} seconds")
    print(f"Encryption time: {encryption_time:.4f} seconds")
    print("Encryption completed successfully.")

    # The private key stays with the authorized party; never send it to the cloud.
    return {
        "selected_date": selected_date,
        "hourly_data": hourly_data,
        "readings": readings,
        "encrypted_readings": encrypted_readings,
        "public_key": public_key,
        "private_key": private_key,
    }


def parse_arguments():
    parser = ArgumentParser(
        description="Prepare and encrypt household electricity readings."
    )
    parser.add_argument(
        "--data-file",
        type=Path,
        default=DEFAULT_DATASET,
        help="Path to household_power_consumption.txt",
    )
    parser.add_argument(
        "--date",
        help="Optional complete date in YYYY-MM-DD format",
    )
    return parser.parse_args()


def main():
    args = parse_arguments()
    run_meter(args.data_file, args.date)


if __name__ == "__main__":
    main()
