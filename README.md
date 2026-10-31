# SOC Analisis & Priority Awareness Engine

[![Paper](https://img.shields.io/badge/Springer-Journal%20of%20King%20Saud%20University%20CIS%20(2026)-blue)](https://link.springer.com/article/10.1007/s44443-026-01172-w)
[![AHP Consistency](https://img.shields.io/badge/AHP%20CR-0.041%20%3C%200.10-success)](https://link.springer.com/article/10.1007/s44443-026-01172-w)
[![Noise Reduction](https://img.shields.io/badge/Noise%20Reduction%20Rate-72.0%25-cyan)](https://link.springer.com/article/10.1007/s44443-026-01172-w)
[![Recall](https://img.shields.io/badge/High--Risk%20Recall-0.94-brightgreen)](https://link.springer.com/article/10.1007/s44443-026-01172-w)

Platform intelijen analisis dan pengayaan alert keamanan (SOC Alert Triage & Dynamic Priority Awareness) end-to-end yang mengimplementasikan metodologi dari paper penelitian:
> **"Intelligent priority awareness method for alert data in SOC threat response"**  
> *Tianqi Guo, Yan Chen, Qiang Zhang, Weiguo Wang, Jian Wang, Shiyin Zhu*  
> *Journal of King Saud University – Computer and Information Sciences (2026) 38:776*

---

## 🛡️ Fitur Utama & Metodologi Inti

1. **Ingress & Triplet Normalization**:
   - Pemetaan multi-vendor (Wazuh, Splunk ES, CrowdStrike, Sentinel, Suricata, WAF) ke skema kanonis.
   - Pembentukan Triplet $g(a_i) = (src_i, dst_i, type_i)$ dan agregasi *hourly time series* $x_g(h)$.

2. **Hierarchical Alert Noise Reduction (Paper Bagian 4)**:
   - **FFT-PCC Branch**: Deteksi noise periodik dengan rasio puncak dominan $\rho_g \ge 3.0$, periode $p_g \in [2, 72\text{ jam}]$, dan korelasi Pearson antarsiklus $r_g > 0.85$.
   - **Conservative Risk Gate (Algoritma 1)**: Mencegah pembuangan alert periodik yang memiliki bukti IOC terkonfirmasi, asosiasi APT, CVE dengan exploit publik, aset bernilai *Core*, atau progres *kill-chain*.

3. **BERT-assisted Multi-Agent Evidence Orchestration (Paper Bagian 4.3)**:
   - **Master Agent**: Dekomposisi tugas deterministik.
   - **Knowledge Retrieval Agent**: Pencocokan rule lokal.
   - **Association Query Agent**: 6 plugin (IOC matching, IP reputation, NetFlow behavior, Whois, Asset GLPI, Vulnerability correlation).
   - **BERT Reasoning Agent**: Klasifikasi semantik teks alert (*true-alert probability*).
   - **Conservative Evidence Fusion**: Formula $S_{TA} = \sum_j \omega_j c_j y_j + \eta G$.

4. **Knowledge Layer & Semantic Integrity Verification (Algoritma 2)**:
   - Cybersecurity Knowledge Graph & Asset-Vulnerability Association Graph.
   - Verifikasi integritas: $C_S$ (Schema), $C_I$ (Canonical Identity), $C_R$ (Relations), $C_T$ (Temporal Freshness), $C_P$ (Provenance). Menghasilkan snapshot tervalidasi $G^* = G \setminus Q$.

5. **AHP Dynamic Risk Scoring (Paper Bagian 5.3)**:
   - 6 Kriteria AHP ($W_i$) dengan Consistency Ratio $CR = 0.041 < 0.10$.
   - 17 Sub-indikator ternormalisasi $[0, 1]$ (Tabel 4 & 5 dari paper).
   - Pengali lingkungan eksternal ($E_{ext}$) dan internal ($E_{int}$).
   - Klasifikasi prioritas: **High (80–100)**, **Medium (60–<80)**, dan **Low (0–<60)**.

6. **Workflow Case & Incident Management**:
   - Siklus hidup insiden: `New` $\rightarrow$ `Triage` $\rightarrow$ `Investigating` $\rightarrow$ `Resolved` $\rightarrow$ `Closed`.
   - Jejak audit persisten, triage notes, dan korelasi alert via `event_id`.

---

## 📁 Struktur Direktori Monorepo

```
d:/Mira/SOC/
├── apps/
│   ├── api/                     # Backend SOC API (Python + FastAPI)
│   │   └── app/
│   │       ├── api/v1/          # Endpoints: /alerts, /cases, /analytics, /graph
│   │       ├── core/            # App configuration & settings
│   │       ├── db/              # Transactional repository & seed data
│   │       └── main.py          # FastAPI app factory & static mount
│   └── web/                     # Frontend Console (React 18 + Vite + Tailwind)
│       ├── src/
│       │   ├── components/      # AHP Radar, TimeSeriesChart, Header, Sidebar
│       │   ├── features/        # DashboardView, AlertsView, CasesView, TopologyView
│       │   └── services/api.ts  # REST Client
│       └── dist/                # Production-ready compiled assets
├── services/
│   ├── engine/                  # Core Detection & Scoring Engine
│   │   ├── normalizer.py        # Triplet & ECS mapping
│   │   ├── fft_pcc.py           # FFT-PCC algorithm (Eq 4, 5, 6)
│   │   ├── risk_gate.py         # Conservative Risk Gate
│   │   ├── multi_agent.py       # Multi-Agent Evidence Orchestration (Eq 7)
│   │   ├── semantic_integrity.py# Algorithm 2 Closed-World Integrity Verification
│   │   ├── ahp_scorer.py        # Exact AHP Risk Scoring Engine (Eq 8, 9, 10)
│   │   └── pipeline.py          # Pipeline coordinator
│   └── rag_worker/              # Async RAG & ATT&CK Context
├── packages/contracts/          # Shared Pydantic data models
├── tests/                       # Unit tests (FFT-PCC, AHP, Risk Gate)
├── run_dev.py                   # One-click unified runner
├── docker-compose.yml           # Full stack container configuration
└── .env.example                 # Environment variable template
```

---

## 🚀 Cara Menjalankan

### 1. Menjalankan Langsung (Mode Development / Demo Cepat)

Karena frontend React telah di-compile ke dalam `apps/web/dist`, Anda dapat menjalankan satu perintah Python berikut:

```powershell
python run_dev.py
```

Buka browser Anda di:
- **Web Console SOC**: [http://localhost:8000](http://localhost:8000)
- **Interactive Swagger API Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)

### 2. Menjalankan Frontend Development Server (Live Reload)

Jika Anda ingin mengubah kode UI secara langsung dengan Hot Module Replacement (HMR):

```powershell
# Terminal 1 (Backend API)
python run_dev.py

# Terminal 2 (Vite Frontend)
npm run dev --prefix apps/web
```
Buka: [http://localhost:5173](http://localhost:5173)

### 3. Menjalankan dengan Docker Compose (Stack Enterprise Lengkap)

Untuk menjalankan seluruh stack (PostgreSQL, Redis Streams, Elasticsearch, Neo4j, Ollama, SOC API, dan Web Console):

```bash
docker-compose up -d
```

---

## 🧪 Menjalankan Unit Tests

Seluruh formula matematis (FFT dominant peak ratio $\rho_g \ge 3.0$, Pearson correlation $r_g > 0.85$, AHP Consistency Ratio $CR = 0.041$, dan Conservative Risk Gate) telah diverifikasi dengan unit test:

```powershell
python -m unittest discover tests
```

Output:
```
.......
Ran 7 tests in 0.025s
OK
```

---

## 📊 Hasil Evaluasi dari Paper (Tabel 14)

| Sistem / Platform | Mean Response Time (MTTR) | Throughput | Cognitive Load (NASA-TLX) | High-Risk Recall |
| :--- | :---: | :---: | :---: | :---: |
| Splunk ES Baseline | 12.0 min | 118 alerts/h | 68.4 | 0.86 |
| IBM QRadar | 11.4 min | 126 alerts/h | 65.7 | 0.85 |
| Elastic Security | 10.9 min | 132 alerts/h | 63.9 | 0.84 |
| Wazuh + Custom Rules | 13.2 min | 105 alerts/h | 70.1 | 0.81 |
| **Proposed Framework (Ours)** | **6.5 min (-45.2%)** | **240 alerts/h (+103%)** | **43.1 (-37%)** | **0.94** |
