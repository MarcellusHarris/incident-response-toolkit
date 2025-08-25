# Incident Response Toolkit

![Collection Flow Diagram](collection-flow.png)

The **Incident Response Toolkit** is a cross‑platform script that helps you collect
key forensic artifacts from a host during an incident. It is designed to run on
Windows, Linux and macOS and gathers system information, running processes,
network connections and file hashes. The collected data can be zipped and
optionally uploaded to Amazon S3 for safekeeping.

## Features

* Collects basic system information: hostname, OS version, boot time, and uptime.
* Enumerates running processes with their PID, name and command line.
* Captures active network connections (local/remote addresses and status).
* Computes SHA‑256 hashes for files in one or more specified directories.
* Stores outputs in a timestamped directory.
* Optionally compresses the output into a ZIP archive.
* Optionally uploads the ZIP archive to an S3 bucket (requires AWS credentials).

## Requirements

* Python 3.8 or later.
* [psutil](https://pypi.org/project/psutil/) (for system and process information).
* [boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) (for optional S3 uploads).

Install dependencies with:

```bash
pip install -r requirements.txt
```

## Usage

```bash
python ir_collect.py \
  --targets "C:\\Windows\\Temp" "/var/log" \
  --zip \
  --s3-bucket my-ir-bucket \
  --s3-prefix incidents/$(hostname)
```

### Arguments

| Argument | Required | Description |
|---------|---------|-------------|
| `--targets` | Yes | One or more directories to recursively hash. |
| `--zip` | No | Compress the output directory into a ZIP archive. |
| `--s3-bucket` | No | Name of an S3 bucket to upload the ZIP. Requires AWS credentials. |
| `--s3-prefix` | No | Key prefix within the S3 bucket to store the ZIP file. |

When the `--zip` flag is omitted, the script writes collected files into the
`output/` directory and does not create an archive. The `--s3-bucket` option
implies `--zip` because it uploads the ZIP archive.

## Example

Collect artifacts from `/home/user/Documents` and `/var/log`, compress them and
upload to S3:

```bash
python ir_collect.py --targets "/home/user/Documents" "/var/log" --zip \
  --s3-bucket forensics-collection --s3-prefix $(hostname)/$(date +%Y%m%dT%H%M%S)
```

## Outputs

The script creates a timestamped directory inside the `output/` folder. This
directory contains:

* `system_info.json` – basic system details.
* `processes.json` – list of running processes.
* `connections.json` – list of network connections.
* `hashes.csv` – SHA‑256 hashes for the specified target files.
* `log.txt` – a log of operations and any errors encountered.

If `--zip` is used, the directory is compressed into `<timestamp>.zip`. If
`--s3-bucket` is specified, the ZIP file is uploaded to S3 under the given
prefix.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE)
file for details.



## Diagram

[Collection Flow Diagram](collection-flow.png)

