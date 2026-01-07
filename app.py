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
    .stApp {
        background-color: #0d1117;
        color: #c9d1d9;
        font-family: 'Courier New', monospace;
    }
    .stTextInput > div > div > input {
        background-color: #010409;
        color: #f78166; /* Groq Orange-ish */
        border: 1px solid #30363d;
    }
    div[data-testid="stSidebar"] {
        background-color: #010409;
        border-right: 1px solid #30363d;
    }
    h1, h2, h3 {
        color: #f78166 !important;
    }
    div[data-testid="stStatusWidget"] {
        border-color: #f78166;
    }
    .tool-call {
        background-color: #1f2937;
        border-left: 5px solid #10b981;
        padding: 10px;
        border-radius: 4px;
        margin-bottom: 10px;
    }
</style>
""", unsafe_allow_html=True)

# --- MCP Client Implementation ---

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
                st.markdown(f"<div class='tool-call'><b>Tool Output ({tool_name}):</b><br><pre>{tool_output}</pre></div>", unsafe_allow_html=True)
                
                st.session_state.history.append({"query": query, "tool": tool_name, "output": tool_output})
