# threat-intel-dashboard/

import streamlit as st
import pandas as pd

from ioc_utils import parse_iocs
from services.virustotal import vt_lookup
from services.otx import otx_lookup


def main():
    st.set_page_config(page_title="Threat Intelligence Dashboard", layout="wide")
    st.title(" Threat Intelligence Dashboard")
    st.write(
        "Enter IPs, domains, URLs, or hashes below (one per line) to enrich them "
        "using VirusTotal and AlienVault OTX."
    )

    with st.sidebar:
        st.header("Settings")
        use_vt = st.checkbox("Use VirusTotal", value=True)
        use_otx = st.checkbox("Use AlienVault OTX", value=True)
        st.markdown(
            " Make sure you set your API keys as environment variables:\n\n"
            "- `VT_API_KEY`\n"
            "- `OTX_API_KEY`\n"
        )

    ioc_input = st.text_area(
        "IOCs",
        height=200,
        placeholder="Example:\n8.8.8.8\ngoogle.com\nhttp://example.com\n44d88612fea8a8f36de82e1278abb02f",
    )

    if st.button("Analyze IOCs"):
        if not ioc_input.strip():
            st.warning("Please enter at least one IOC.")
            return

        if not use_vt and not use_otx:
            st.warning("Please select at least one intelligence source in the sidebar.")
            return

        iocs = parse_iocs(ioc_input)
        if not iocs:
            st.error("Could not parse any valid IOCs.")
            return

        st.info(f"Analyzing {len(iocs)} IOC(s)...")

        results = []
        errors = []

        for ioc in iocs:
            row = {
                "ioc": ioc["value"],
                "type": ioc["type"],
            }

            # VirusTotal
            if use_vt:
                try:
                    vt_result = vt_lookup(ioc["value"], ioc["type"])
                    row["vt_found"] = vt_result.get("found")
                    row["vt_malicious"] = vt_result.get("malicious")
                    row["vt_suspicious"] = vt_result.get("suspicious")
                    row["vt_harmless"] = vt_result.get("harmless")
                    row["vt_undetected"] = vt_result.get("undetected")
                except Exception as e:
                    errors.append(f"[VirusTotal] {ioc['value']}: {e}")
                    row["vt_found"] = None

            # AlienVault OTX
            if use_otx:
                try:
                    otx_result = otx_lookup(ioc["value"], ioc["type"])
                    row["otx_found"] = otx_result.get("found")
                    row["otx_pulse_count"] = otx_result.get("pulse_count")
                    row["otx_malicious"] = otx_result.get("malicious")
                except Exception as e:
                    errors.append(f"[OTX] {ioc['value']}: {e}")
                    row["otx_found"] = None

            results.append(row)

        if errors:
            with st.expander("Errors / Warnings"):
                for err in errors:
                    st.write("-", err)

        if results:
            df = pd.DataFrame(results)
            st.subheader("Summary Table")
            st.dataframe(df, use_container_width=True)

            st.subheader("Per-IOC Details")
            for row in results:
                with st.expander(f"{row['ioc']} ({row['type']})"):
                    st.write("**VirusTotal**")
                    st.write(
                        {
                            "found": row.get("vt_found"),
                            "malicious": row.get("vt_malicious"),
                            "suspicious": row.get("vt_suspicious"),
                            "harmless": row.get("vt_harmless"),
                            "undetected": row.get("vt_undetected"),
                        }
                    )
                    st.write("**AlienVault OTX**")
                    st.write(
                        {
                            "found": row.get("otx_found"),
                            "pulse_count": row.get("otx_pulse_count"),
                            "malicious": row.get("otx_malicious"),
                        }
                    )


if __name__ == "__main__":
    main()
