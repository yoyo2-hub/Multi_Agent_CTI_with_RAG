# Multi-Agent CTI with RAG

A Cyber Threat Intelligence (CTI) analysis system that combines multi-agent reasoning, retrieval-augmented generation (RAG), MITRE ATT&CK mapping, and automated report generation.

The project is designed to process raw CTI messages and convert them into actionable intelligence by extracting entities, identifying malicious behaviors, searching relevant historical context, mapping attacks to ATT&CK techniques, and producing a consolidated report.

## Overview

This repository implements a practical CTI pipeline that can:

- analyze threat intelligence text and security reports
- extract IOCs and security-relevant entities
- detect malicious behaviors and patterns
- query a retrieval system for contextual CTI knowledge
- map findings to MITRE ATT&CK techniques
- score risk and prioritize remediation actions
- generate a dashboard and PDF report for decision makers

The project is especially useful for demonstrating how AI agents can support cyber defense workflows by automating intelligence correlation and triage.

## Key features

- Multi-agent CTI workflow
- Retrieval-Augmented Generation (RAG)
- MITRE ATT&CK technique mapping
- Severity scoring and prioritization
- Structured report generation
- Dashboard and PDF output
- Support for multiple CTI messages in a single pipeline run
- Interactive and batch execution modes

## Architecture

The system is built around a LangGraph orchestration pipeline:

1. CTI Analysis Agent
   - extracts entities, behaviors, and patterns from raw text
   - integrates retrieval context from the knowledge base

2. MITRE Mapping Agent
   - maps behaviors to ATT&CK techniques
   - calculates severity
   - recommends mitigations

3. Aggregation & Prioritization
   - combines all results into a single threat report
   - ranks actions by urgency and impact
   - produces executive summary

4. Reporting layer
   - generates visual dashboard
   - produces final PDF report

## Main execution flow

The main pipeline starts in `main.py` and calls the LangGraph graph defined in `graph.py`.

The flow is:

- CTI analysis
- MITRE mapping
- aggregation
- dashboard generation
- PDF generation

## Repository structure

```text
Multi_Agent_CTI_with_RAG/
├── README.md
├── main.py                       # entry point for the CTI pipeline
├── graph.py                      # LangGraph orchestration graph
├── cti_analysis_agent.py         # CTI analysis workflow
├── mitre_agent.py                # MITRE ATT&CK processing workflow
├── llm_helper.py                 # LLM setup helper
├── requirements.txt              # Python dependencies
├── darkgram_cti_final.jsonl     # CTI dataset / knowledge source
├── agent-cti.ipynb              # notebook used for experiments
├── app/
│   └── main.py                  # app-oriented CTI interface
├── src/
│   └── main.py                  # project source entry point
├── websearchagent/
├── notify_agent/
├── analyse_resultat/
├── .vscode/
└── ...
```

## Technologies and tools used

### AI and orchestration
- Python
- LangChain
- LangGraph
- LangChain Ollama
- Hugging Face Transformers
- sentence-transformers
- FAISS

### Security intelligence
- MITRE ATT&CK tools and mappings
- CTI extraction logic
- Behavior and pattern detection
- Threat scoring engine

### Data and visualization
- pandas
- numpy
- matplotlib
- seaborn
- fpdf2
- JSONL dataset processing

### Utilities
- requests
- tqdm
- python-dotenv

## Installation

Clone the repository:

```bash
git clone https://github.com/yoyo2-hub/Multi_Agent_CTI_with_RAG.git
cd Multi_Agent_CTI_with_RAG
```

Create a virtual environment and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate   # Linux / macOS
# or .venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

## Configuration

The project depends on AI and retrieval components. You may need to configure:

- local LLM providers such as Ollama
- environment variables in a `.env` file if required
- model and embedding settings
- data source or vector store paths

If a `.env.example` or local config file is used in your environment, copy it before running the project:

```bash
cp .env.example .env
```

## Usage

### Run the default example pipeline

```bash
python main.py
```

This runs the built-in sample CTI messages and generates the final report.

### Run with custom files

```bash
python main.py -f file1.txt file2.txt
```

### Interactive mode

```bash
python main.py -i
```

Then enter CTI messages line by line and finish with `done` when ready.

## Example workflow

An example CTI message may describe:

- ransomware activity
- phishing campaign
- malware payload behavior
- persistence mechanisms
- network indicators
- exfiltration techniques

The system then processes this information and produces structured outputs such as:

- extracted entities
- ATT&CK-linked behaviors
- risk scoring
- recommended actions
- PDF and dashboard outputs

## Outputs generated

The pipeline may generate:

- `final_report.json`
- `cti_report.pdf`
- dashboard image(s)
- structured CTI analysis results

## Notes

This repository is a research/prototype-oriented CTI project designed to demonstrate how AI-generated intelligence pipelines can support security operations. It combines multiple components and is modular enough to extend with additional agents, retrieval sources, or specialized intelligence feeds.

## Contributors

- Chayma Dallel
- Emna Ghorbel
- Ranim Bouguila

## Related concepts

- Cyber Threat Intelligence (CTI)
- Retrieval-Augmented Generation (RAG)
- Multi-agent AI systems
- MITRE ATT&CK
- Security operations automation

## License

This project does not currently declare a license in the repository metadata. Please check the repository settings before reuse or redistribution.
