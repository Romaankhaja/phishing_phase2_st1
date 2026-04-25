# Phishing Detection Pipeline Architecture

This flowchart outlines the architecture and data flow of the `phishing_ml` pipeline following the removal of legacy compatibility facades (`pipeline.py`, `comparison.py`, `shortlisting.py`). It details how `main_controller.py` orchestrates the process.

```mermaid
flowchart TD
    %% Define Styles
    classDef input fill:#f9d0c4,stroke:#333,stroke-width:2px,color:#000;
    classDef controller fill:#eceff1,stroke:#607d8b,stroke-width:2px,color:#000,stroke-dasharray: 5 5;
    classDef process fill:#e1f5fe,stroke:#0288d1,stroke-width:2px,color:#000;
    classDef subProcess fill:#b3e5fc,stroke:#0288d1,stroke-width:1px,color:#000;
    classDef decision fill:#fff9c4,stroke:#fbc02d,stroke-width:2px,color:#000;
    classDef output fill:#c8e6c9,stroke:#388e3c,stroke-width:2px,color:#000;
    classDef artifact fill:#d1c4e9,stroke:#512da8,stroke-width:2px,color:#000;
    classDef drop fill:#ffcdd2,stroke:#d32f2f,stroke-width:1px,color:#000,stroke-dasharray: 5 5;

    %% Input Data
    A1[Input Target URLs<br>Excel/CSV files]:::input
    A2[Whitelist Legitimate Domains<br>Excel file]:::input

    %% Orchestration
    Controller([main_controller.py<br>Pipeline Orchestrator]):::controller
    
    A1 --> Controller
    A2 -.-> Controller

    subgraph Step1 [Step 1: Hashing & Lexical Shortlisting]
        direction TB
        L1[_comparison_legacy.py<br>ray_runtime.py]:::process
        B1(URL Extraction & Normalization):::subProcess
        B2{Stage 0: Lexical Gate}:::decision
        B3[DNS Gate Pre-filtering]:::subProcess
        B4[Stage 1: HTTP Enrichment<br>RDAP, TLS, HTML]:::subProcess
        B5[Similarity Hashing<br>Favicon, SSL, Domain]:::process
        
        L1 -.-> B1
        B1 --> B2
        B2 -- "High Similarity<br>(Lexical Hit)" --> B3
        B3 -- "Resolves (IP found)" --> B4
        B4 --> B5
    end

    subgraph Step2 [Step 2: Classification & ML Pipeline]
        direction TB
        L2[_pipeline_legacy.py<br>ray_classify_runtime.py]:::process
        C1(Visual Extraction<br>Headless Browser Screenshots):::subProcess
        C2[OCR & Text-Visual<br>Consistency TVC]:::subProcess
        C3[Network / DNS / WHOIS Data]:::subProcess
        C4{XGBoost Models<br>Brand & Domain Scoring}:::decision
        
        L2 -.-> C1
        C1 --> C2
        C1 --> C3
        C2 --> C4
        C3 --> C4
    end

    subgraph Step3 [Step 3: Post-Processing & Output]
        direction TB
        L3[_pipeline_legacy.py<br>package_results]:::process
        D1[Generate Final Verdicts<br>Phishing, Suspected, Legitimate]:::subProcess
        D2[Evidence Packaging<br>Screenshots]:::subProcess
        D3[output_file.csv / filtered.csv]:::output
        D4[Zip Submission Archive]:::artifact
        
        L3 -.-> D1
        D1 --> D2
        D1 --> D3
        D2 --> D4
        D3 --> D4
    end

    %% Drop Node
    Drop1[Dropped / Filtered]:::drop
    B2 -- "Low Similarity<br>(Lexical Miss)" --> Drop1

    %% Connections
    Controller -->|Initiates| L1
    B5 -->|"Matched Candidates"| H[holdout.csv]:::artifact
    H -->|Input to Stage 2| L2
    Controller -->|Triggers Classify| L2
    C4 -->|Classifications| L3
    Controller -->|Triggers Packaging| L3
```
