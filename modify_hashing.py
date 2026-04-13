import re
import os

fp = r'c:\Users\SATWIK\Documents\Phishing\phishing_pipeline\hashing_legit_domains.py'

with open(fp, 'r', encoding='utf-8') as f:
    text = f.read()

new_load_excel = r'''###############################################
# LOAD EXCEL
###############################################

BASE_DIR = os.path.dirname(__file__)
ROOT_DIR = os.path.dirname(BASE_DIR)

def clean_domain(url):
    import pandas as pd
    if pd.isna(url):
        return None
    url = str(url).strip()
    if not url.startswith("http"):
        url = "https://" + url
    from urllib.parse import urlparse
    return urlparse(url).netloc.lower()

df_list = []
import os
import pandas as pd

# File 1 (Stage 2)
EXCEL_PATH = os.path.join(ROOT_DIR, "data", "Stage_2_Legitimate_Domains.xlsx")
if os.path.exists(EXCEL_PATH):
    df1 = pd.read_excel(EXCEL_PATH)
    if "CSE Name" in df1.columns:
        df1["CSE Name"] = df1["CSE Name"].ffill()
        df1 = df1.rename(columns={"CSE Name": "entity", "Legitimate Domains/URLs": "raw_url"})
        df_list.append(df1[["entity", "raw_url"]])

# File 2 (Public URL)
NEW_EXCEL_PATH = os.path.join(ROOT_DIR, "data", "whitelists", "Public URL & IPs-09-04-2026.xlsx")
if os.path.exists(NEW_EXCEL_PATH):
    df2 = pd.read_excel(NEW_EXCEL_PATH)
    if "Application Name" in df2.columns:
        df2["Application Name"] = df2["Application Name"].ffill()
        df2 = df2.rename(columns={"Application Name": "entity", "Public URL": "raw_url"})
        df_list.append(df2[["entity", "raw_url"]])

if df_list:
    df = pd.concat(df_list, ignore_index=True)
else:
    df = pd.DataFrame(columns=["entity", "raw_url"])

df["domain"] = df["raw_url"].apply(clean_domain)
df = df.dropna(subset=["domain"])
df["entity"] = df["entity"].astype(str).str.strip()

# Load Existing DB to skip processed domains
DB_PATH = os.path.join(ROOT_DIR, "data", "entity_hash_db.json")
existing_db = {}
import json
if os.path.exists(DB_PATH):
    try:
        with open(DB_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            for k, v in data.items():
                if k == "_meta": continue
                existing_db[k] = v
    except Exception:
        pass'''

text = re.sub(r'###############################################\s*# LOAD EXCEL\s*###############################################.*?df = df\.dropna\(subset=\[\"domain\"\]\)', new_load_excel, text, flags=re.DOTALL)

text = re.sub(r'entity_db = \{\}', 'entity_db = existing_db.copy()', text)

old_group = r'''        for entity, group in df\.groupby\(\"CSE Name\"\):

            entity_db\[entity\] = \{
                \"domains\": \[\],
                \"domain_simhashes\": \[\],
                \"page_phashes\": \[\],
                \"favicon_phashes\": \[\],
                \"ssl_simhashes\": \[\],
                \"keywords\": \[\]
            \}

            for domain in group\[\"domain\"\]:
                all_tasks\.append\(
                    _scan_domain\(domain, entity, context, semaphore, aio_session, lock\)
                \)'''

new_group = r'''        for entity, group in df.groupby("entity"):
            if entity not in entity_db:
                entity_db[entity] = {
                    "domains": [],
                    "domain_simhashes": [],
                    "page_phashes": [],
                    "favicon_phashes": [],
                    "ssl_simhashes": [],
                    "keywords": []
                }

            processed = set(entity_db[entity].get("domains", []))

            for domain in group["domain"]:
                if domain not in processed:
                    all_tasks.append(
                        _scan_domain(domain, entity, context, semaphore, aio_session, lock)
                    )
                    processed.add(domain)'''

text = re.sub(old_group, new_group, text, flags=re.DOTALL)

old_run = r'''###############################################
# RUN
###############################################

asyncio.run\(generate_hashes\(\)\)


###############################################
# SAVE
###############################################

output_payload = \{
    \"_meta\": \{
        \"hash_schema_version\": 2,
    \},
    \*\*entity_db,
\}

with open\(os.path.join\(os.path.dirname\(BASE_DIR\), \"data\", \"entity_hash_db.json\"\), \"w\", encoding=\"utf-8\"\) as f:
    json.dump\(output_payload, f, indent=4\)'''

new_run = r'''###############################################
# RUN
###############################################

if __name__ == "__main__":
    asyncio.run(generate_hashes())

    ###############################################
    # SAVE
    ###############################################

    output_payload = {
        "_meta": {
            "hash_schema_version": 2,
        },
        **entity_db,
    }

    with open(DB_PATH, "w", encoding="utf-8") as f:
        json.dump(output_payload, f, indent=4)'''

text = re.sub(old_run, new_run, text, flags=re.DOTALL)

with open(fp, 'w', encoding='utf-8') as f:
    f.write(text)

print("Modification complete")
