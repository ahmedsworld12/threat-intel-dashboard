# Threat Intelligence Dashboard

A SOC automation tool built with Streamlit. It enriches IPs, domains, URLs, and file hashes using VirusTotal and AlienVault OTX.

## Features
- IOC enrichment (IP, Domain, URL, Hash)
- VirusTotal analysis stats
- AlienVault OTX pulse data
- Summary table + detailed results
- Clean Streamlit dashboard UI

## Project Structure
threat-intel-dashboard/
├─ app.py
├─ ioc_utils.py
├─ services/
│  ├─ virustotal.py
│  └─ otx.py
├─ requirements.txt
└─ README.md

## API Keys
Set your environment variables:

export VT_API_KEY="your key here"
export OTX_API_KEY="your key here"

## Run the App
pip install -r requirements.txt
streamlit run app.py

