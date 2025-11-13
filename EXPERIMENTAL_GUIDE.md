# Experimental Framework Guide for Capstone Project
## How to Conduct Systematic Testing of Your Incident Response System

### Overview
You now have a complete experimental framework to systematically test and validate your Phase-1 incident response system. This guide shows you how to use it for your academic capstone project.

---

## Experimental Tools Available

### 1. **Baseline Testing** (`baseline_test.py`)
- **Purpose**: Quick validation of core components
- **When to use**: Before major changes, initial setup verification  
- **Command**: `python baseline_test.py`
- **Output**: Component health check + sample Phase-2 JSON

### 2. **Comprehensive Experiments** (`experimental_framework.py`)  
- **Purpose**: Full system testing with statistical analysis
- **When to use**: Primary data collection for your capstone
- **Command**: `python experimental_framework.py`
- **Output**: Detailed JSON results for each test category

### 3. **Data Analysis** (`analyze_results.py`)
- **Purpose**: Statistical analysis and visualization
- **When to use**: After collecting experimental data
- **Command**: `python analyze_results.py`  
- **Output**: Performance plots + comprehensive analysis report

### 4. **Quick Summary** (`summary.py`)
- **Purpose**: Simple overview without complex analysis
- **When to use**: Daily progress checks
- **Command**: `python summary.py`
- **Output**: Clean text summary of current status

---

## How to Conduct Your Experiments

### Phase 1: Baseline Validation (COMPLETE)
```bash
python baseline_test.py
```
**What this tests:**
- Entity extraction functionality
- NVD API integration
- System integration pipeline
- Phase-2 JSON generation

**Status**: **PASSED** - All core components working

### Phase 2: Comprehensive Testing
```bash
python experimental_framework.py
```
**What this tests:**
- Classification accuracy across incident types
- Entity extraction precision/recall
- Response time performance
- System reliability under load

**Expected duration**: 5-10 minutes
**Output**: `experiment_data/experiment_YYYYMMDD_HHMMSS.json`

### Phase 3: Statistical Analysis
```bash
python analyze_results.py
```
**What this generates:**
- Performance visualization charts
- Statistical summaries
- Academic-ready data tables
- Research journal content

**Output**: Charts in `experiment_data/` + analysis report

---

## Journal Documentation Process

Your experimental framework automatically generates journal entries. Here's the workflow:

1. **Run Experiments**: Use `experimental_framework.py` for systematic data collection
2. **Analyze Results**: Use `analyze_results.py` for statistical analysis  
3. **Update Journal**: Framework generates formatted content for your research journal
4. **Document Findings**: Add your observations and conclusions

### Example Journal Entry Structure
```markdown
## Experiment Date: 2024-01-15

### Methodology
- Test cases: 25 diverse incident scenarios
- Metrics: Accuracy, response time, entity extraction F1
- Environment: Standard development setup

### Results
- Classification accuracy: 87.5% (21/24 correct)
- Average response time: 2.3 seconds 
- Entity extraction F1: 0.91

### Observations
[Your analysis of what the results mean]

### Next Steps
[What you plan to test or improve next]
```

---

## Experimental Scenarios for Your Capstone

### Core Testing Areas

#### 1. **Classification Accuracy Testing**
- Test diverse incident types (network, malware, social engineering, etc.)
- Measure prediction accuracy vs ground truth
- Analyze confidence scores and thresholds

#### 2. **Performance Benchmarking**  
- Response time under various loads
- Memory and CPU usage patterns
- Scalability testing with larger inputs

#### 3. **Entity Extraction Validation**
- Precision and recall for different entity types
- Performance on real vs synthetic incident reports
- Edge cases and unusual formatting

#### 4. **Integration Testing**
- NVD API reliability and error handling
- Knowledge retrieval accuracy
- End-to-end workflow validation

#### 5. **Robustness Testing**
- Malformed input handling
- API failure scenarios
- Resource constraints

### Advanced Experimental Scenarios

#### **A. Comparative Analysis**
Compare your system against baseline approaches:
- Rule-based classification
- Simple keyword matching
- Manual analyst performance

#### **B. Feature Ablation Studies**  
Test individual component contributions:
- Performance without entity extraction
- Classification without NVD data
- System without knowledge retrieval

#### **C. Real-World Data Testing**
If you have access to real incident data:
- Anonymized security logs
- Public incident reports
- Simulated attack scenarios

---

## Data Collection Strategy

### Quantitative Metrics
- **Accuracy**: Correct classifications / Total classifications
- **Precision**: True positives / (True positives + False positives)
- **Recall**: True positives / (True positives + False negatives)
- **F1-Score**: 2 * (Precision * Recall) / (Precision + Recall)
- **Response Time**: Time from input to complete analysis
- **Throughput**: Incidents processed per minute

### Qualitative Observations
- System usability and interface quality
- Analyst workflow integration potential
- Deployment and maintenance complexity
- Business value and cost-effectiveness

### Data Storage
Your framework automatically saves:
- Raw experimental results (JSON format)
- Processed analysis data (CSV/Excel compatible)
- Visualization charts (PNG format)
- Statistical summaries (Markdown format)

---

## Iterative Improvement Process

### 1. **Establish Baseline** (Week 1)
- Run initial experiments with current system
- Document performance benchmarks
- Identify obvious improvement areas

### 2. **Systematic Testing** (Weeks 2-3)
- Comprehensive test case development
- Multiple experimental runs for statistical validity
- Performance optimization based on bottlenecks

### 3. **Feature Enhancement** (Weeks 4-5)
- Implement improvements based on findings
- A/B testing of different approaches
- Validation of enhancement effectiveness

### 4. **Final Validation** (Week 6)
- Complete system testing with all improvements
- Comparison against initial baseline
- Documentation of final performance metrics

---

## Academic Deliverables

Your experimental framework supports these capstone deliverables:

### **Research Report Sections**
- **Methodology**: Systematic testing approach
- **Results**: Quantitative performance data
- **Analysis**: Statistical interpretation of findings
- **Validation**: Comparison with established benchmarks

### **Technical Appendices**
- Complete experimental data
- Source code for reproducibility
- Configuration and setup documentation
- Raw test results and analysis scripts

---

## Next Steps for Full Testing

### Immediate Actions (This Week)
1. **Run baseline validation**: `python baseline_test.py`
2. **Execute comprehensive tests**: `python experimental_framework.py`
3. **Generate initial analysis**: `python analyze_results.py`
4. **Document findings**: Update your research journal

### Medium-term Goals (Next 2-3 Weeks)
1. **Expand test cases**: Add more diverse incident scenarios
2. **Performance optimization**: Address any bottlenecks found
3. **Feature enhancements**: Implement improvements based on results
4. **Comparative analysis**: Test against alternative approaches

### Long-term Objectives (Final Month)
1. **Comprehensive evaluation**: Complete system assessment
2. **Academic documentation**: Finalize research report
3. **Presentation preparation**: Create demo and presentation materials
4. **Future work identification**: Document potential Phase-2 enhancements

---

**Your experimental framework is complete and ready for systematic capstone research!**

### Quick Reference Commands

```bash
# Quick validation
python baseline_test.py

# Full experimental run
python experimental_framework.py

# Statistical analysis
python analyze_results.py

# View experiment data
cd experiment_data/
ls -la *.json

# Generate visualizations
python analyze_results.py --charts-only
```

### Support and Troubleshooting

If you encounter issues:

1. **Check dependencies**: Ensure all required packages are installed
2. **Verify API access**: Test NVD API connectivity
3. **Review logs**: Check error messages in terminal output
4. **Validate data**: Ensure test case formats are correct
5. **Resource check**: Monitor memory and disk space usage

Remember: This framework is designed to give you comprehensive data for your capstone project while maintaining academic rigor and reproducibility.