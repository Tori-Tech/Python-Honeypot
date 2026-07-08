import streamlit as st
import json
import pandas as pd
import matplotlib.pyplot as plot

st.set_page_config(page_title="SIEM Dashboard", layout="wide")
st.title("SIEM Dashboard")



#safely loading log data and storing in the cache
@st.cache_data
def load_log_data(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as file:
            logs = json.load(file)
            if isinstance(logs, dict):
                logs = [logs]
            return pd.DataFrame(logs)
    except FileNotFoundError:
        st.error(f"File not found: {filepath}")
        return None
    except json.JSONDecodeError:
        st.error("Invalid JSON format. Please check the log file.")
        return None
    except Exception as e:
        st.error(f"Error loading file: {e}")
        return None
      
#sidebar config
st.sidebar.header("Data Source")
filename = st.sidebar.text_input("Enter path to JSON log file:", placeholder="/path/to/log.json")

if filename:
    df = load_log_data(filename)

    if df is not None and not df.empty:
        #SIEM metrics
        st.subheader("Key Indicators")
        col1, col2, col3 = st.columns(3)

        # Evaluate column lookups cleanly
        ip_col = 'source_ip' if 'source_ip' in df.columns else ('ip' if 'ip' in df.columns else None)
        port_col = 'dest_port' if 'dest_port' in df.columns else ('port' if 'port' in df.columns else None)

        with col1:
            st.metric(label="Total Logged Activity", value=len(df))
        with col2:
            unique_ips = df[ip_col].nunique() if ip_col else "N/A"
            st.metric(label="Unique Attacker IPs", value=unique_ips)
        with col3:
            top_port = df[port_col].mode()[0] if port_col and not df[port_col].isna().all() else "N/A"
            st.metric(label="Most Targeted Port/Service", value=str(top_port))

        st.markdown("----")


        #interactive filters and analysis

        if ip_col and port_col:
            st.subheader("Analytics")
            chart_col1, chart_col2 = st.columns(2)
            
            with chart_col1:
                # Top 5 IPs shown with horizontal bar chart
                top_attackers = df[ip_col].value_counts().head(5).iloc[::-1] # Reverse for top-down sorting
                
                fig_ip, ax_ip = plot.subplots(figsize=(6, 4))
                fig_ip.patch.set_facecolor('#0e1117') # Match Streamlit dark background tone
                ax_ip.set_facecolor('#1e2129')
                
                top_attackers.plot(kind='barh', ax=ax_ip, color='#d32f2f')
                ax_ip.set_title("Top 5 Attacker IPs", color='white', fontsize=12, pad=10)
                ax_ip.tick_params(colors='white')
                ax_ip.xaxis.grid(True, linestyle='--', alpha=0.6, color='gray')
                ax_ip.yaxis.grid(False)
                
                st.pyplot(fig_ip)
                plot.close(fig_ip) # Clean memory
                
            with chart_col2:
                # pie chart of port distribution
                port_counts = df[port_col].value_counts().head(5)
                
                fig_port, ax_port = plot.subplots(figsize=(6, 4))
                fig_port.patch.set_facecolor('#0e1117')
                
                # colors ranging from dark red to orange
                colors = ['#8b0000', '#b22222', '#cd5c5c', '#e9967a', '#f08080']
                
                wedges, texts, autotexts = ax_port.pie(
                    port_counts, 
                    labels=port_counts.index, 
                    autopct='%1.1f%%', 
                    startangle=140, 
                    colors=colors[:len(port_counts)],
                    textprops=dict(color="white")
                )
                ax_port.set_title("Target Port Distribution", color='white', fontsize=12, pad=10)
                
                st.pyplot(fig_port)
                plot.close(fig_port) # Clean memory again

       #another viewer
        st.subheader("Log Explorer")
        
        search_query = st.text_input("Quick Search (Filter logs by any keyword):")
        if search_query:
            mask = df.astype(str).apply(lambda x: x.str.contains(search_query, case=False)).any(axis=1)
            filtered_df = df[mask]
        else:
            filtered_df = df

        st.dataframe(filtered_df, use_container_width=True, hide_index=True)


    
    else:
        st.info("Log file is empty or could not be generated into a structured format.")
else:
    st.info("Please provide a valid JSON file path in the sidebar to load the SIEM dashboard.")
