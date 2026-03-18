import json
import re
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
from config import LLM_MODEL

_llm_instance = None
_tokenizer_instance = None

def get_llm():
    global _llm_instance, _tokenizer_instance
    if _llm_instance is None:
        _tokenizer_instance = AutoTokenizer.from_pretrained(LLM_MODEL)
        
        # Load in half-precision (float16) - very safe for 1.5B models
        model = AutoModelForCausalLM.from_pretrained(
            LLM_MODEL,
            torch_dtype=torch.float16,
            device_map="auto"
        )
        
        _llm_instance = pipeline(
            "text-generation",
            model=model,
            tokenizer=_tokenizer_instance,
            max_new_tokens=512,
            return_full_text=False
        )
    return _llm_instance, _tokenizer_instance

def extract_json(text: str) -> str:
    match = re.search(r"(\{.*\})", text, re.DOTALL)
    return match.group(1) if match else text

def llm_analyze(system_prompt: str, user_content: str) -> dict:
    llm, tokenizer = get_llm()
    
    # Qwen uses a slightly different chat template, but pipeline handles it
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_content}
    ]
    prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    
    try:
        results = llm(prompt, do_sample=False) # Greedy search for better JSON
        output = results[0]["generated_text"].strip()
        
        print(f"\n--- QWEN RESPONSE ---\n{output}\n-------------------")
        
        return json.loads(extract_json(output))
    except Exception as e:
        return {"error": str(e), "llm_failed": True}