import streamlit as st
import time
import asyncio
import os
import sys
import json

# MCP Imports
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Import backend services
from backend import llm_service

# Page Config
st.set_page_config(
    page_title="Snort MCP Agent (Groq Powered)",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=JetBrains+Mono&display=swap');

    .stApp {
        background: radial-gradient(circle at top right, #1a1f2e, #0d1117);
        color: #e6edf3;
        font-family: 'Inter', sans-serif;
    }
    
    .stTextInput > div > div > input {
        background: rgba(1, 4, 9, 0.7);
        backdrop-filter: blur(10px);
        color: #f78166;
        border: 1px solid rgba(48, 54, 61, 0.5);
        border-radius: 8px;
        font-family: 'JetBrains Mono', monospace;
    }
    
    div[data-testid="stSidebar"] {
        background: rgba(1, 4, 9, 0.95) !important;
        border-right: 1px solid rgba(48, 54, 61, 0.5);
    }
    
    h1, h2, h3 {
        color: #f78166 !important;
        font-weight: 700 !important;
    }
    
    .tool-call {
        background: rgba(31, 41, 55, 0.4);
        backdrop-filter: blur(12px);
        border: 1px solid rgba(16, 185, 129, 0.3);
        border-left: 5px solid #10b981;
        padding: 1.5rem;
        border-radius: 12px;
        margin-bottom: 1rem;
        box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    }
    
    .stDataFrame {
        background: rgba(1, 4, 9, 0.5);
        border-radius: 8px;
        border: 1px solid rgba(48, 54, 61, 0.3);
    }
    
    /* Better sidebar items */
    .sidebar-tool {
        background: rgba(247, 129, 102, 0.1);
        border-radius: 6px;
        padding: 4px 8px;
        margin-bottom: 4px;
        border: 1px solid rgba(247, 129, 102, 0.2);
    }
</style>
""", unsafe_allow_html=True)

# --- MCP Client Implementation ---
# ... (MCPAgent class remains the same)

class MCPAgent:
    def __init__(self):
        self.server_params = StdioServerParameters(
            command=sys.executable,
            args=["backend/mcp_server.py"],
            env=None
        )

    async def list_tools(self):
        async with stdio_client(self.server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                # List available tools
                result = await session.list_tools()
                # Convert to dict for easier handling
                return [
                   {
                       "name": tool.name, 
                       "description": tool.description, 
                       "inputSchema": tool.inputSchema
                   } 
                   for tool in result.tools
                ]

    async def execute_tool(self, tool_name: str, arguments: dict):
        async with stdio_client(self.server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool_name, arguments=arguments)
                return result.content[0].text

def run_sync(coro):
    return asyncio.run(coro)

# --- UI Logic ---

if "history" not in st.session_state:
    st.session_state.history = []

agent = MCPAgent()

# Sidebar
with st.sidebar:
    st.title("🛡️ System Config")
    st.info("Using configured Groq API Key")
    
    st.divider()
    
    st.markdown("### 🧰 Available Tools (Auto-Discovered)")
    try:
        tools = run_sync(agent.list_tools())
        for t in tools:
            st.code(t["name"], language="text")
    except Exception as e:
        st.error(f"Failed to fetch tools: {e}")
        tools = []

    st.divider()
    st.markdown("### 📝 History")
    for item in st.session_state.history[-5:]:
        st.caption(f"> {item['query'][:20]}...")

# Main Interface
st.title("Snort Agentic Interface")
st.caption("Powered by Groq + Official MCP Protocol")

# Input
query = st.chat_input("Ex: Check snort version or Run detailed sniffer on eth0...")

if query:
    # 1. Display User Message
    with st.chat_message("user", avatar="👤"):
        st.write(query)
    
    # 2. Process
    with st.chat_message("assistant", avatar="🛡️"):
        status_placeholder = st.empty()
        
        with status_placeholder.status("Reasoning...", expanded=True) as status:
            
            # Step 1: Consult LLM
            start_time = time.time()
            st.write("Thinking (Consulting Groq with Tool Schemas)...")
            
            response = llm_service.get_agent_response(query, tools)
            
            llm_latency = (time.time() - start_time) * 1000
            
            if response["type"] == "message":
                # LLM decided not to use a tool (or refused)
                status.update(label="Response Ready", state="complete", expanded= False)
                st.markdown(response["content"])
                st.session_state.history.append({"query": query, "response": response["content"]})
                
            elif response["type"] == "tool_call":
                # LLM wants to call a tool
                tool_name = response["name"]
                tool_args = response["arguments"]
                
                status.update(label=f"Executing Tool: {tool_name}", state="running", expanded=True)
                st.write(f"🛑 Decided to call tool: `{tool_name}`")
                st.write(f"Arguments: `{json.dumps(tool_args)}`")
                
                # Step 2: Execute Tool
                try:
                    tool_output = run_sync(agent.execute_tool(tool_name, tool_args))
                    st.write("✅ Execution Complete")
                except Exception as e:
                    tool_output = f"Error executing tool: {e}"
                    st.write("❌ Execution Failed")

                status.update(label="Task Complete", state="complete", expanded=False)
                
                # Show Final Output
                with st.container():
                    st.markdown(f"#### 🛠️ Tool Result: `{tool_name}`")
                    
                    try:
                        # Try to parse output as JSON for custom rendering
                        data = json.loads(tool_output)
                        
                        if isinstance(data, list) and len(data) > 0:
                            # Render list of rules as a table
                            import pandas as pd
                            df = pd.DataFrame(data)
                            # Reorder columns for readability if they exist
                            cols = ["Msg", "Action", "Proto", "Src", "Dir", "Dst", "SID"]
                            df_cols = [c for c in cols if c in df.columns]
                            if df_cols:
                                st.dataframe(df[df_cols], use_container_width=True, hide_index=True)
                            else:
                                st.dataframe(df, use_container_width=True, hide_index=True)
                        elif isinstance(data, dict) and "error" in data:
                            st.error(data["error"])
                        else:
                            st.json(data)
                            
                    except (json.JSONDecodeError, TypeError):
                        # Fallback to raw text if not JSON
                        st.markdown(f"<div class='tool-call'><pre>{tool_output}</pre></div>", unsafe_allow_html=True)
                
                st.session_state.history.append({"query": query, "tool": tool_name, "output": tool_output})
