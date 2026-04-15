import pandas as pd
import time
from cti_analysis_agent import analyze_message

# 1. High-Contrast Test Cases
easy_scenarios = [
    {
        "label": "🔥 CLEAR THREAT", 
        "text": "Alert: Connection detected to known C2 server at 194.26.135.94."
    },
    {
        "label": "✅ CLEAR SAFE", 
        "text": "You can view the new company holiday calendar at https://internal.portal/hr."
    },
    {
        "label": "⚙️ SYSTEM ADMIN", 
        "text": "Server reboot scheduled for midnight to apply security patches. No downtime expected."
    }
]

results = []
print("Starting Easy Smoke Test...")

for test in easy_scenarios:
    print(f"Testing: {test['label']}...")
    start = time.time()
    
    # Run the agent
    response = analyze_message(test['text'])
    
    elapsed = round(time.time() - start, 2)
    
    # Store simplified results
    results.append({
        "Type": test['label'],
        "Seconds": elapsed,
        "Agent Verdict": response.get("patterns", {}).get("threat_classification", "No classification")
    })

# 2. Display as a clean table
pd.set_option('display.max_colwidth', 150)
display(pd.DataFrame(results))