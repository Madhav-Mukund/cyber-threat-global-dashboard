# TEAM-7 : Geopolitical Cyber Threat Intelligence Globe & Dashboard 

# Team Members:
  1. Bajrang Mishra
  2. Deepak Joshi
  3. Ishika Biswas
  4. Madhav Mukund
  5. Priyanshi Verma

## 🌐 Overview
The **[cyber-threat-global-dashboard](https://github.com/Madhav-Mukund/cyber-threat-global-dashboard)** is a data visualization and analysis project focused on mapping and understanding global cyber threats. Utilizing the EuRepoC (European Repository of Cyber Incidents) dataset, this project features comprehensive Exploratory Data Analysis (EDA), statistical hypothesis testing, and an interactive dashboard/globe to visualize geopolitical cyber activities.

## 📊 Key Features
* **Data Processing & Cleaning:** Automated scripts (`data_processing.py`) to clean and prepare raw cyber incident data.
* **Exploratory Data Analysis (EDA):** In-depth Jupyter Notebooks exploring statistical trends and patterns in cyber threats.
* **Hypothesis Testing:** Rigorous statistical testing (`Cybersecurity_Threat_Hypothesis_Testing.ipynb`) to validate threat intelligence theories.
* **Interactive Dashboard:** Visual representation of the data using charts and a global mapping interface.
* **Detailed Reports:** Pre-generated visualization reports for each dataset.

## 📁 Repository Structure
```text
├── charts/                                      # Chart visualization components
├── cleaned data/                                # Processed and ready-to-use datasets
├── dashboard/                                   # Frontend code for the interactive dashboard
├── original dataset/                            # Raw data files (including EuRepoC data)
├── reports/                                     # Generated visualization reports
├── Cybersecurity_Threat_Hypothesis_Testing.ipynb # Hypothesis testing notebook
├── EDA_statistical_analysis (1).ipynb           # General statistical analysis notebook
├── EuRepoC_Cyber_Incident_EDA.ipynb             # EDA specifically for the EuRepoC dataset
├── countries_centroids.csv                      # Mapping data for the globe visualization
├── data_processing.py                           # Python script for data wrangling
├── data_quality.json                            # Data quality logs/metrics
├── eurepoc_codebook_1_2.pdf                     # Data dictionary for EuRepoC
├── eurepoc_dataset_handbook_0_1.pdf             # Handbook for understanding the dataset
└── version_changelog.txt                        # Project version history
