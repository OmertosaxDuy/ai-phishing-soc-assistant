
import json

import streamlit as st

from core.email_parser import parse_email


st.set_page_config(
    page_title="AI Phishing SOC Assistant",
    page_icon="🛡️",
    layout="wide"
)


def display_list(items, empty_message):
    """Display a list of strings."""
    if not items:
        st.info(empty_message)
        return

    for index, item in enumerate(items, start=1):
        st.code(f"{index}. {item}", language=None)


def main():
    st.title("🛡️ AI Phishing SOC Assistant")
    st.caption(
        "Week 1 — Email Forensics & IOC Extraction"
    )

    st.warning(
        "For investigation only. "
        "No URLs or attachments are executed. "
        "This version does not classify phishing."
    )

    st.sidebar.title("SOC Investigation")

    st.sidebar.markdown(
        """
        **Available Features**
        - EML Parsing
        - Email Header Analysis
        - IOC Extraction
        - Attachment SHA-256
        - JSON Export
        """
    )

    st.sidebar.info(
        "Week 2: Detection Rules & Risk Scoring"
    )

    uploaded_file = st.file_uploader(
        "Upload suspicious email (.eml)",
        type=["eml"],
        help="Maximum supported file size: 10 MB"
    )

    if uploaded_file is None:
        st.info(
            "Upload an .eml file to start investigation."
        )
        return

    try:
        raw = uploaded_file.getvalue()
        result = parse_email(raw)

    except (ValueError, TypeError) as error:
        st.error(f"Cannot parse email: {error}")
        return

    except Exception:
        st.error(
            "An unexpected error occurred while "
            "parsing the email."
        )
        return

    st.success("Email parsed successfully!")

    iocs = result["iocs"]

    st.subheader("Investigation Overview")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "URLs",
        len(iocs["urls"])
    )

    col2.metric(
        "Domains",
        len(iocs["domains"])
    )

    col3.metric(
        "Attachments",
        len(result["attachments"])
    )

    col4.metric(
        "Link Mismatches",
        len(iocs["link_mismatches"])
    )

    st.caption(
        "Counts are investigation indicators, "
        "not a phishing risk score."
    )

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "Overview",
        "Email Headers",
        "IOC Analysis",
        "Email Content",
        "Attachments"
    ])

    # ---------- OVERVIEW ----------
    with tab1:
        st.subheader("Email Information")

        st.write("**Subject:**", result["subject"])
        st.write("**From:**", result["from"])
        st.write("**To:**", result["to"])
        st.write("**Date:**", result["date"])
        st.write("**Reply-To:**", result["reply_to"])

        st.divider()

        st.write("**Email SHA-256:**")
        st.code(
            result["email_sha256"],
            language=None
        )

        st.write(
            "**Email Size:**",
            f'{result["email_size"]} bytes'
        )

    # ---------- HEADERS ----------
    with tab2:
        st.subheader("Email Header Analysis")

        headers = {
            "From": result["from"],
            "From Address": result["from_address"],
            "To": result["to"],
            "Reply-To": result["reply_to"],
            "Return-Path": result["return_path"],
            "Date": result["date"],
            "Message-ID": result["message_id"]
        }

        st.json(headers)

        st.subheader("Authentication Results")

        if result["authentication_results"]:
            for item in result["authentication_results"]:
                st.code(item, language=None)
        else:
            st.info(
                "No Authentication-Results header found."
            )

        st.caption(
            "Authentication-Results values are "
            "unverified header claims in this MVP."
        )

    # ---------- IOC ANALYSIS ----------
    with tab3:
        st.subheader("Extracted URLs")

        display_list(
            iocs["urls"],
            "No URLs detected."
        )

        st.subheader("Extracted Domains")

        display_list(
            iocs["domains"],
            "No domains detected."
        )

        st.subheader("Extracted IP Addresses")

        display_list(
            iocs["ips"],
            "No IP addresses detected."
        )

        st.subheader("Hyperlink Mismatch Analysis")

        mismatches = iocs["link_mismatches"]

        if mismatches:
            st.warning(
                f"{len(mismatches)} hyperlink mismatch(es) "
                "detected."
            )

            for mismatch in mismatches:
                with st.expander("Suspicious hyperlink"):
                    st.write("**Displayed URL:**")
                    st.code(
                        mismatch["displayed_url"],
                        language=None
                    )

                    st.write("**Actual URL:**")
                    st.code(
                        mismatch["actual_url"],
                        language=None
                    )

                    st.write("**Displayed Domain:**")
                    st.code(
                        mismatch["displayed_domain"],
                        language=None
                    )

                    st.write("**Actual Domain:**")
                    st.code(
                        mismatch["actual_domain"],
                        language=None
                    )
        else:
            st.success(
                "No displayed URL/domain mismatches found."
            )

    # ---------- EMAIL CONTENT ----------
    with tab4:
        st.subheader("Plain Text Body")

        if result["body_text"]:
            st.text_area(
                "Email Text",
                value=result["body_text"],
                height=300,
                disabled=True
            )
        else:
            st.info("No plain text body found.")

        st.subheader("Raw HTML Source")

        if result["body_html"]:
            st.code(
                result["body_html"],
                language="html"
            )
        else:
            st.info("No HTML body found.")

        st.caption(
            "HTML is displayed as source code "
            "and is not rendered as a web page."
        )

    # ---------- ATTACHMENTS ----------
    with tab5:
        st.subheader("Attachment Analysis")

        attachments = result["attachments"]

        if not attachments:
            st.info("No attachments detected.")
        else:
            for attachment in attachments:
                st.write(
                    "**Filename:**",
                    attachment["filename"]
                )

                st.write(
                    "**Content Type:**",
                    attachment["content_type"]
                )

                st.write(
                    "**Size:**",
                    attachment["size"]
                )

                st.write("**SHA-256:**")
                st.code(
                    attachment["sha256"],
                    language=None
                )

                st.divider()

    # ---------- EXPORT ----------
    st.divider()

    st.subheader("Export Investigation")

    json_result = json.dumps(
        result,
        indent=4,
        ensure_ascii=False
    )

    st.download_button(
        label="Download Investigation JSON",
        data=json_result,
        file_name="investigation_report.json",
        mime="application/json"
    )

    st.caption(
        "Week 1 completed: Email parsing "
        "and IOC extraction."
    )


if __name__ == "__main__":
    main()
