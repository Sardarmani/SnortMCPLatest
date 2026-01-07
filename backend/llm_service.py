import os
from dotenv import load_dotenv

load_dotenv()

# Securely load key
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

def get_agent_response(query: str, tools: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Decides whether to call a tool or answer directly.
    Returns:
       {"type": "tool_call", "name": "...", "arguments": {...}}
       OR
       {"type": "message", "content": "..."}
    """
    try:
        client = Groq(api_key=GROQ_API_KEY)
        model_name = "openai/gpt-oss-120b"
        
        # Construct system prompt with tool definitions
        tools_desc = json.dumps(tools, indent=2)
        
        system_prompt = f"""
        You are an intelligent security assistant with access to the following tools:
        {tools_desc}
        
        Your task is to help the user by EITHER:
        1. Calling a relevant tool to perform an action.
        2. Answering their question directly if no tool is needed.
        
        RESPONSE FORMAT (JSON ONLY):
        If calling a tool:
        {{
            "type": "tool_call",
            "name": "<tool_name>",
            "arguments": <json_object_of_args>
        }}
        
        If answering directly:
        {{
            "type": "message",
            "content": "<your_response>"
        }}
        
        IMPORTANT: Return ONLY the JSON object. No other text.
        """
        
        completion = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": query}
            ],
            response_format={"type": "json_object"} # Force JSON if supported, otherwise prompt handles it
        )
        
        content = completion.choices[0].message.content.strip()
        
        try:
            # Clean up potential markdown code blocks
            if content.startswith("```json"):
                content = content.replace("```json", "").replace("```", "").strip()
            elif content.startswith("```"):
                content = content.replace("```", "").strip()
                
            response_json = json.loads(content)
            return response_json
            
        except json.JSONDecodeError:
            return {
                "type": "message", 
                "content": f"Error parsing model response. Raw: {content}"
            }

    except Exception as e:
        return {
            "type": "message",
            "content": f"LLM Error: {str(e)}"
        }
