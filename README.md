# PhishGuard AI

**NLP-Powered Email and SMS Phishing Detection**

PhishGuard AI is a small web application that reads the text of an email or SMS message and
estimates whether it is **phishing** or **legitimate**. It uses Natural Language Processing
(TF-IDF) and a supervised machine learning model (Logistic Regression), and adds simple, explainable
checks for suspicious phrases and risky-looking links.

> PhishGuard AI is an educational phishing-detection tool. Predictions are automated estimates and
> should not be treated as proof that a message is safe or malicious.

**Datasets used** (not included in this repository; download them yourself):
- **SMS:** [SMS Phishing Dataset for Machine Learning and Pattern Recognition](https://data.mendeley.com/datasets/f45bkkt8pr/1)
  (Mendeley Data, CC BY 4.0)
- **Email:** [Phishing Email Dataset](https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset)
  (Kaggle, CC BY-SA 4.0), only `Nazario.csv` and `SpamAssasin.csv`

See [section 8](#8-datasets-and-licensing) for how labels were mapped and the known limitations,
and [section 12](#12-dataset-placement) for download and placement steps.

---

## 1. Project overview

You paste a message into the app (or let it analyse as you type). The app then shows:

- the **model prediction** (potential phishing or legitimate),
- the **model score** (0 = legitimate, 1 = phishing) on an animated **risk dial**,
- an overall **risk level** (Low, Medium or High),
- the message with **suspicious phrases highlighted**,
- a **URL analysis** table with structural warning signs,
- a plain-language **explanation** and **recommended next steps**.

Everything runs locally on your computer. No paid services, API keys or internet lookups are used,
and links in your message are **never opened**.

## 2. Problem statement

Phishing messages trick people into clicking malicious links, sharing passwords or one-time
passwords (OTPs), or paying money. They often use urgent language ("your account will be blocked"),
fake rewards and disguised links. Checking every message by hand is hard, so this project explores
how well a simple, transparent NLP model can flag likely phishing text.

## 3. Objectives

1. Build a clean, honestly-labelled dataset of phishing and legitimate emails and SMS messages.
2. Preprocess text consistently for training and prediction.
3. Train a TF-IDF + Logistic Regression classifier and evaluate it on held-out data.
4. Add explainable indicators: suspicious phrases and URL structure checks.
5. Combine them into an understandable risk level with safety advice.
6. Present everything in a clear, interactive web interface.

## 4. Features

| Feature | How it works |
|---|---|
| Email and SMS analysis | One interface. Emails use an optional subject plus the body. |
| ML classification | TF-IDF features + Logistic Regression (the main classifier). |
| Model score | A number from 0 to 1. It is an *estimated score*, not a guaranteed probability. |
| Risk level | Low / Medium / High from the model score; extra indicators can raise it by one level. |
| Suspicious phrases | Editable list in `config/suspicious_phrases.json`, highlighted in the message. |
| URL analysis | Structure only: IP addresses, shorteners, long URLs, `@` tricks, many subdomains, look-alike characters, official-sounding words. |
| Explanation and advice | Generated from what was actually found. Nothing is invented. |
| Clear error handling | Empty input, text with no words, malformed URLs and a missing model are all handled. |
| Live analysis | Optionally re-analyses about half a second after you stop typing. |
| Risk dial | The Low / Medium / High bands at the real thresholds, the phishing cut-off, and a needle that swings to the score. |
| Message scan | A scan line sweeps the message and suspicious phrases light up as it passes. |
| Examples | Five demo messages that type themselves in and get analysed. |
| Light and dark themes | Follows the computer's setting, with a switch; the choice is remembered. |

## 5. Technology stack

| Purpose | Tool |
|---|---|
| Language | Python 3.12 |
| Web server / API | FastAPI, served by Uvicorn |
| Web interface | React 19, built with Vite 6 (needs Node.js 20 or newer) |
| Typeface | Schibsted Grotesk, bundled with the app (no font is downloaded at run time) |
| Data handling | Pandas, NumPy |
| Text features | scikit-learn `TfidfVectorizer` |
| Classifier | scikit-learn `LogisticRegression` |
| Evaluation | scikit-learn metrics, Matplotlib (confusion matrix image) |
| Saving the model | Joblib |
| Tests | pytest (including FastAPI's test client for the API) |

**Why NLTK is not used:** the brief allowed NLTK "where appropriate". Its usual steps (removing
stop-words, stemming) would delete phrases such as "your account" that are useful for detecting
phishing, so the simpler preprocessing in `src/preprocessing.py` was preferred and one dependency
was avoided.

**Why FastAPI and React:** the first version used Streamlit, which re-runs the whole script on
every click and leaves little room for animation or live feedback. The interface was rebuilt as a
small React app talking to a FastAPI server, so it can analyse while you type, animate the risk
dial and the message scan, and switch themes smoothly. All the analysis still happens in the same
Python code.

## 6. System workflow

```
Raw datasets ──> prepare_data.py ──> training_data.csv
                                          │
                                          ▼
                     train_model.py: 70/15/15 split ──> TF-IDF + Logistic Regression
                                          │                 (fitted on train only)
                                          ├──> thresholds chosen on validation set
                                          ▼
                     evaluate_model.py: metrics on train / validation / test (overall, email, SMS)

User message ──> React page (web/) ──> POST /api/analyse (api.py) ──> src/analysis.py
                              ├─ phishing_detector.py  (trained model -> prediction + score)
                              ├─ suspicious_phrases.py (phrase list -> matches + highlighting)
                              ├─ url_analyzer.py       (URL structure -> warnings)
                              └─ risk_assessment.py    (risk level + explanation + advice)
```

## 7. Project structure

```
PhishGuard-AI/
├── api.py                  FastAPI server: the JSON API and the built interface
├── prepare_data.py         Load, clean, de-duplicate and combine the datasets
├── train_model.py          Split data, train the model, choose risk thresholds
├── evaluate_model.py       Metrics, confusion matrices and reports
├── requirements.txt        Exact package versions
├── pytest.ini              Test settings
├── web/                    React interface (Vite project)
│   ├── src/App.jsx             Form state, live analysis, examples
│   ├── src/components/         Header, composer, risk dial, results, "How it works"
│   ├── src/styles.css          Both themes, layout and animations
│   └── dist/                   Built files served by api.py (created by npm run build)
├── config/
│   ├── datasets.json           Dataset paths, column names, label mappings
│   ├── settings.json           Seed, split sizes, risk and URL settings
│   ├── suspicious_phrases.json Editable phrase list
│   └── examples.json           The five demo messages shown in the app
├── src/
│   ├── config.py               All file paths (built with pathlib)
│   ├── preprocessing.py        Shared text cleaning
│   ├── phishing_detector.py    Loads the model and predicts
│   ├── url_analyzer.py         URL extraction and structure checks
│   ├── suspicious_phrases.py   Phrase detection and safe highlighting
│   ├── risk_assessment.py      Risk level, explanation, recommendations
│   └── analysis.py             Runs all checks for one message (used by api.py)
├── data/raw/               Downloaded datasets (not committed to Git)
├── data/processed/         Cleaned data and splits (created by the scripts)
├── models/                 Trained model + thresholds (created by train_model.py)
├── reports/                Evaluation results (created by evaluate_model.py)
└── tests/                  Automated tests
```

## 8. Datasets and licensing

The datasets are **not included** in this repository. Download them yourself (see section 12).

| Dataset | Used for | Licence |
|---|---|---|
| [SMS Phishing Dataset for Machine Learning and Pattern Recognition](https://data.mendeley.com/datasets/f45bkkt8pr/1) (Mishra & Soni, Mendeley Data, 2022, DOI 10.17632/f45bkkt8pr.1) | SMS | CC BY 4.0 |
| [Phishing Email Dataset](https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset) (Al-Subaiey et al., Kaggle, 2024): **only** `Nazario.csv` and `SpamAssasin.csv` | Email | CC BY-SA 4.0 (as listed on Kaggle) |

If you use these datasets, cite the original authors as requested on the dataset pages.

### How labels were mapped

| Source | Original label | Used as |
|---|---|---|
| Mendeley SMS | `ham` | legitimate |
| Mendeley SMS | `smishing` (any letter case) | phishing |
| Mendeley SMS | `spam` | **excluded** from training |
| Nazario.csv | `1` (all rows are phishing) | phishing |
| SpamAssasin.csv | `0` (ham) | legitimate |
| SpamAssasin.csv | `1` (generic spam: adverts, etc.) | **excluded** from training |

**Spam is not phishing.** Advertising spam is not the same as phishing, so it is kept in
`data/processed/all_labelled.csv` for reference but left out of the binary training data. Any
label not listed in `config/datasets.json` is dropped, never assumed to be legitimate.

The Kaggle dataset's combined file `phishing_email.csv` was **not used**, because its own
description calls the positive label "spam (phishing)", so it mixes spam into the phishing class.

### Cleaning steps (`prepare_data.py`)

1. Remove empty messages.
2. Remove exact duplicates (judged on the cleaned text).
3. Remove **near-duplicates**: messages that differ only in numbers, links or punctuation, such
   as the same scam template with different phone numbers. This stops the same template from
   appearing in both the training and test sets.
4. If the same text appears with two different labels, every copy is dropped.
5. Remove **collection artifacts**: the Nazario corpus contains its collector's address
   (`jose@monkey.org`) in many emails, and SpamAssassin emails contain the year 2002. An early
   version of the model learned these as "phishing" and "legitimate" clues, which is leakage, so
   they are removed through `remove_patterns` in `config/datasets.json`.

Result (run on 2026-10-23): 10,835 training messages:

| Channel | Legitimate | Phishing |
|---|---|---|
| Email | 4,075 | 1,524 |
| SMS | 4,827 | 409 |

### Known dataset limitations

- **Different sources and years for email.** Legitimate emails come from the SpamAssassin corpus
  (2002, many technical mailing lists), while phishing emails come from the Nazario corpus (about
  2016–2022). The model can partly learn "old mailing-list style vs. modern style" instead of
  "phishing vs. not phishing". Email test scores are therefore probably **more optimistic** than
  real-world performance.
- **"Smishing" is broad** in the SMS dataset: it includes prize and premium-rate call scams as well
  as credential theft. The authors' boundary between spam and smishing is also fuzzy: 34 messages
  appear with both labels (they were dropped).
- The SMS text was collected from screenshots and converted to text (OCR), so it contains typos.
- Much of the legitimate SMS text is short, informal personal chat ("ok lor", "see you"), so
  legitimate business or bank SMS messages are under-represented.

## 9. Installation (Windows)

1. Install **Python 3.12** from [python.org](https://www.python.org/downloads/) and tick
   "Add Python to PATH". Check it in a new terminal:
   ```
   python --version
   ```
2. Install **Node.js 20 or newer** (the LTS version) from [nodejs.org](https://nodejs.org/). It is
   only needed to build the web interface. Check it:
   ```
   node --version
   ```
3. Open the project folder in a terminal (PowerShell or Command Prompt):
   ```
   cd path\to\PhishGuard-AI
   ```

## 10. Virtual environment setup

```
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
```

If PowerShell blocks `activate`, run this once and try again:
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, or use Command Prompt instead.

Then build the web interface once (this downloads React and Vite into `web/node_modules`):

```
cd web
npm install
npm run build
cd ..
```

Run `npm run build` again whenever you change anything in `web/src`.

## 11. Configuration

- `config/datasets.json`: dataset file paths, column names, label mappings and artifact patterns.
- `config/settings.json`: random seed, split sizes, classification threshold, risk targets,
  borderline margin, URL settings (shortener list, length limits).
- `config/suspicious_phrases.json`: the phrase list. Add or remove phrases freely.
- `config/examples.json`: the demo messages shown under "Try an example".

**Changing the classification threshold requires retraining.** `classification_threshold` in
`config/settings.json` is read by `train_model.py`, which uses it to pick the risk thresholds and
saves all three values to `models/thresholds.json`. The app and `evaluate_model.py` read only
`models/thresholds.json`, so after changing the value run `python train_model.py` and then
`python evaluate_model.py`. Editing `models/thresholds.json` by hand is not recommended.
- `config/suspicious_phrases.json`: the phrase list. Add or remove phrases freely.

## 12. Dataset placement

**SMS (Mendeley):**
1. Open https://data.mendeley.com/datasets/f45bkkt8pr/1 and download `Dataset_5971.zip`.
2. Unzip it and put `Dataset_5971.csv` here: `data/raw/sms_mendeley/Dataset_5971.csv`

**Email (Kaggle, free account required):**
1. Open https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset
2. Download **`Nazario.csv`** and **`SpamAssasin.csv`** (the second name is misspelled on Kaggle; keep it as is).
3. Put them here: `data/raw/email/Nazario.csv` and `data/raw/email/SpamAssasin.csv`

Expected columns: SMS `LABEL, TEXT, URL, EMAIL, PHONE`; email `sender, receiver, date, subject, body, urls, label`.
If your files use different column names, change them in `config/datasets.json`.

## 13. Prepare the data

```
python prepare_data.py
```
This prints the number of messages in each class and writes `data/processed/training_data.csv`.
If a file is missing, it prints which one and where to download it.

## 14. Train the model

```
python train_model.py
```
This splits the data 70% train / 15% validation / 15% test (stratified by label **and** channel,
random seed 42), fits the vectorizer and classifier on the **training set only**, chooses the risk
thresholds on the **validation set**, and saves:
- `models/phishguard_pipeline.joblib`: the trained pipeline (preprocessing + TF-IDF + classifier)
- `models/thresholds.json`: classification and risk thresholds

You only need to train once. The app loads the saved model.

## 15. Evaluate the model

```
python evaluate_model.py
```
This writes `reports/evaluation.json`, `reports/evaluation_summary.md` and
`reports/confusion_matrix_test.png`.

### Results (actual output, run on 2026-10-23)

Only the **test** rows describe performance on unseen data. Phishing is the positive class.

| Split | Group | Messages (phishing) | Precision | Recall | F1 | False positives | False negatives |
|---|---|---|---|---|---|---|---|
| Train | Overall | 7,583 (1,353) | 0.981 | 0.999 | 0.990 | 26 | 1 |
| Validation | Overall | 1,626 (290) | 0.959 | 0.966 | 0.962 | 12 | 10 |
| **Test** | **Overall** | 1,626 (290) | **0.966** | **0.966** | **0.966** | 10 | 10 |
| **Test** | **Email** | 841 (229) | **0.991** | **0.983** | **0.987** | 2 | 4 |
| **Test** | **SMS** | 785 (61) | **0.873** | **0.902** | **0.887** | 8 | 6 |

How to read these results:
- **SMS is harder than email** for this model, and the SMS test set has only 61 phishing messages,
  so a few mistakes change the numbers a lot.
- **Email results are likely inflated** by the source and time-period differences described in
  section 8.
- These numbers describe these datasets only. They are **not proof of real-world accuracy**.
- Your numbers should match if you use the same data, versions and seed. The latest results are
  always in `reports/evaluation_summary.md`.

### Is the model score a probability?

No calibration step was applied, so the app calls it a **model score**. `evaluate_model.py`
compares scores with the actual phishing rate on the validation set (see the summary file).
Scores are roughly in line, but not exact (e.g. messages scoring 0.6–0.8 were phishing 94% of
the time).

## 16. Run the tests

```
python -m pytest -q
```
122 tests cover preprocessing, data preparation and splitting (including a check that no
near-duplicates are shared between splits), predictions with a small toy model, the real model,
URL analysis, phrase detection, risk rules, and the web API (via FastAPI's test client: every
endpoint, input errors, a missing model, and the verdict wording). Tests that need the real trained
model are skipped until `train_model.py` has run.
The ML model's predictions are tested separately from the rule-based checks, and no test assumes
that a keyword alone makes a message phishing.

## 17. Launch the application

```
python -m uvicorn api:app --port 8000
```
Then open **http://localhost:8000** in your browser. The server only listens on your own computer
(`localhost`). Stop it with `Ctrl + C` in the terminal.

If the model has not been trained yet, the page shows the exact commands to run instead of results.
If the interface has not been built yet, the page tells you to run `npm run build` in `web/`.

**Developing the interface** (optional, live reload): run the server above in one terminal, and in
a second terminal run `cd web` then `npm run dev`, and open http://localhost:5173. The development
page forwards its API calls to the server on port 8000.

### Full command sequence (Windows)

```
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python prepare_data.py
python train_model.py
python evaluate_model.py
cd web
npm install
npm run build
cd ..
python -m pytest -q
python -m uvicorn api:app --port 8000
```

## 18. Example inputs for demonstration

These are made-up examples for demonstrating the app, not training data. Results below are what
this model produced on 2026-10-23.

All five are built into the app: click one under **"Try an example"** and it types itself in and
gets analysed. You can also open one directly by address, which is handy for a demo:
`http://localhost:8000/?example=suspended-email` (other keys: `slides-email`, `kyc-sms`,
`late-sms`, `otp-sms`).

| Type | Message | Result |
|---|---|---|
| Email | Subject: *Action required: account suspended*. Body: *Your account has been suspended due to unusual login activity. Click here to verify your account within 24 hours: http://secure-login.example-bank.co/verify* | Potential phishing, score 0.9963, **High** risk; 6 phrases; URL flagged for "login, secure" |
| Email | Subject: *Slides for Thursday*. Body: *Hi team, the slides for Thursday's review are on the shared drive. Let me know if anything is missing. Thanks, Priya* | Legitimate, score 0.1785, **Low** risk |
| SMS | *Dear customer, your KYC is pending. Update your KYC now at bit.ly/kyc-upd8 or your account will be blocked.* | Potential phishing, score 0.9708, **High** risk; URL shortener flagged |
| SMS | *Running 10 mins late, order me a coffee pls* | Legitimate, score 0.0898, **Low** risk |
| SMS | *Your OTP for login is 482913. Do not share it with anyone.* | Legitimate (use caution), score 0.4253, **Medium** risk: not phishing, but in the Medium-risk range (a known weakness, see section 20) |

## 19. Understanding the metrics and the risk level

- **Precision (phishing):** of the messages flagged as phishing, how many really were phishing.
- **Recall (phishing):** of all real phishing messages, how many were caught.
- **F1-score:** a single number that balances precision and recall.
- **Accuracy:** share of all messages classified correctly. This can look high even for a poor
  model, because most messages are legitimate.
- **Confusion matrix:** a 2×2 table of true/false positives and negatives.

**False positive vs. false negative**
- A **false positive** is a legitimate message flagged as phishing. It is annoying, and the user may
  start ignoring warnings.
- A **false negative** is a phishing message marked legitimate. It is more dangerous, because the user may
  trust it. This is why phishing **recall** matters so much.

**Two separate kinds of threshold** (all saved in `models/thresholds.json`):

| Threshold | Value | Decides |
|---|---|---|
| Classification | 0.5000 | Prediction: phishing if score ≥ 0.5000, otherwise legitimate |
| Medium risk | 0.2886 | Risk is at least Medium from this score |
| High risk | 0.6006 | Risk is High from this score |

The two risk thresholds were chosen on the validation set: the Medium threshold catches at least
99% of validation phishing messages (99.3%), and at the High threshold at least 98% of flagged
validation messages were phishing (98.6%).

The app shows scores with 4 decimals, cut off rather than rounded (0.49996 shows as 0.4999), so a
displayed score never appears to cross a threshold it has not reached. All decisions use the
original, unrounded score.

**Risk levels:**
1. The model score sets the starting level: **Low** below 0.2886, **Medium** from 0.2886,
   **High** from 0.6006.
2. A message predicted as phishing (score ≥ 0.5000) is **never Low**.
3. A URL structural warning, or **two or more** suspicious phrases, can raise the level by **one**
   step: Low → Medium, or Medium → High only if the model itself predicted phishing.
4. Extra indicators never lower the risk and never override the model's prediction.

**Why a "legitimate" message can still be Medium risk.** The prediction card says which case applies:
- **Legitimate (borderline):** the score is within 0.05 below the phishing threshold
  (`borderline_margin` in `config/settings.json`; this only changes the wording).
- **Legitimate (use caution):** the score is in the Medium range (for example 0.29) but not
  close to the phishing threshold.
- **Legitimate, with raised risk:** the score was Low, but a URL warning or suspicious
  phrases raised the risk to Medium.

## 20. Limitations

- The model only knows patterns in its training data. New scam styles, other languages and
  very short messages may be misclassified.
- Email test results are likely optimistic because of the source and time-period gap (section 8).
- Genuine messages that resemble scams (for example, real bank OTP or delivery messages) can be
  flagged as risky.
- Only the message text is analysed. Sender addresses, email headers and attachments are not.
- URL checks look at structure only. There is no domain reputation lookup, so a clean-looking
  malicious link will not be flagged, and some legitimate links (e.g. `accounts.example.com`) will
  get a warning.
- The suspicious-phrase list is short and in English only.
- The score is not a calibrated probability.

## 21. Future improvements

- Use a more recent, independently labelled legitimate-email corpus to reduce source bias.
- Probability calibration (e.g. scikit-learn `CalibratedClassifierCV`) validated on held-out data.
- Show which words pushed the score up or down (the model's top weighted terms for the message).
- Support more languages, including Indian-language SMS.
- Analyse sender details and email headers when available.
- Optional, privacy-respecting URL reputation checks.

## Privacy and safety

- The app never opens, visits or sends submitted URLs anywhere.
- Message content is not saved or logged. HTML inside a message is shown as plain text and never executed.
- Datasets and trained models are excluded from Git (`.gitignore`).
