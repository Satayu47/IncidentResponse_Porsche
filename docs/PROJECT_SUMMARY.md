# Project Summary

This repository contains an incident response capstone project focused on automated classification, extraction, and analysis of security-relevant artifacts from incident reports and logs. The work integrates NLP, vulnerability lookups, and a lightweight knowledge retrieval system to support research experiments and reproducible evaluation.

## Core Components

### Entity Extraction System
- extractor.py: Entity and indicator-of-compromise extraction using spaCy and rule-based matchers. Inputs are raw text segments or parsed logs; outputs are structured JSON with extracted entities and confidence scores.

### Vulnerability Integration  
- nvd.py: Integration with the NIST NVD API for automatic CVE lookups and enrichment of vulnerability evidence.

### Knowledge Retrieval
- lc_retriever.py: A local knowledge retrieval layer built with vector embeddings and a small FAISS-backed vector store for contextual evidence retrieval.

### Classification Engine
- classifier.py: A two-stage classifier combining a lightweight language model for intent/classification and deterministic fallbacks for high-precision categories. Produces labels with confidence metrics and optional explanation tokens.

### Demo Interface
- streamlit_app.py: An optional demo UI for interactive exploration and manual validation of classification and extraction results.

## Testing and Experiments

### Experimental Framework
- tests/baseline_test.py: Minimal, offline experiment that validates core extraction and classification routines without external API calls.
- tests/experimental_framework.py: Orchestrates controlled experiments, captures run metadata, and formats results for downstream analysis.
- analyze_experiments.py: Analysis utilities that compute performance metrics, generate plots, and synthesize summary text for the research journal.

### Four-tier Validation Framework
1. Baseline Testing: Quick validation framework for core functionality
2. Statistical Analysis Tools: Performance metrics and visualization  
3. Experimental Testing Suite: Comprehensive validation under controlled conditions
4. Academic Documentation: Research journal and methodology templates

## Project Data and Outputs

- experiment_data/: Raw inputs and intermediate outputs captured during experiments.
- results/: Aggregated metrics, CSV export of raw runs, and generated figures used in reporting.

## Design Goals

### Production-Ready System
- Fully functional incident classification pipeline with confidence scoring for human-AI collaboration

### Comprehensive Error Handling
- Graceful degradation under all failure conditions  

### Performance Optimization
- Sub-5 second response times for real-time use

### Scalable Architecture
- Modular design ready for organizational deployment

### Reliability Requirements
- 95%+ uptime with error rate limiting and fallback mechanisms

### Token Management
- Cost-optimized AI usage with intelligent truncation

### Hybrid Classification
- AI + rule-based fallback for maximum reliability

### Multi-Modal Integration
- Text, vulnerability data, and knowledge base fusion

### Phase-2 Ready Output
- Structured JSON for downstream automation systems

## Academic Deliverables

### Documentation Created
1. research_journal.md: Step-by-step experimental workflow guide  
2. PROJECT_SUMMARY.md: Quick project overview and usage steps
3. Comprehensive testing methodology templates

### Research Journal and Methodology Templates
- Reproducible Results: Version-controlled experiments and data collection
- Academic Documentation: Research journal with experiment logs, observations, and analysis notes
- Novel Contributions: Confidence-aware automation and hybrid AI classification
- Academic Value: Novel methodology for first comprehensive validation framework

## Success Metrics

### Achieved Objectives
- Component Validation: COMPLETE
- Data Collection Pipeline: READY  
- Analysis Tools: READY
- Documentation Framework: COMPLETE

### Ready for Automation
If you want me to further refine wording for an academic submission (tone, citations, or structure), say so and I will update this file to match your target venue and style.