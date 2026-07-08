import streamlit as st


#define the pages

SIEM = st.Page("pages/SIEM.py", title="SIEM")
LLM = st.Page("pages/analyzer.py", title="LLM Log Analyzer")

pg = st.navigation({
    "SIEM": [SIEM],
    "LLM Log Analyzer": [LLM]
})

pg.run()
