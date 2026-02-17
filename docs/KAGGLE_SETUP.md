# How to Use This Repository in Kaggle

To use this repository in a Kaggle notebook, follow these steps to clone the code, install dependencies, and add the modules to your Python path.

## Step 1: Clone the Repository directly into the Working Directory

In a Kaggle notebook cell, run the following commands. This clones the repository into the current working directory (`/kaggle/working`).

```python
# Clone the repository
!git clone https://github.com/kuchurisatwik/phishing_ml.git

# (Optional) Pull latest changes if you already cloned it
# %cd phishing_ml
# !git pull
# %cd ..
```

## Step 2: Install Dependencies

Install the required Python packages listed in `requirements.txt`.

```python
# Install dependencies from the cloned repo
!pip install -r phishing_ml/requirements.txt
```

## Step 3: Add to Python Path

To import modules like `phishing_pipeline` or `utils` from the cloned repository, you need to add the repository folder to your system path.

```python
import sys
import os

# Add the repository to the system path
repo_path = '/kaggle/working/phishing_ml'
if repo_path not in sys.path:
    sys.path.append(repo_path)

# Verify imports work
try:
    from phishing_pipeline import pipeline
    print("✅ Successfully imported phishing_pipeline!")
except ImportError as e:
    print(f"❌ Import failed: {e}")
```

## Step 4: Run the Pipeline

Now you can use the code as if you were running it locally.

```python
import asyncio
from phishing_pipeline.pipeline import run_pipeline

# Example usage
# Ensure you have your input files uploaded to Kaggle (e.g., in /kaggle/input/...)
async def main():
    await run_pipeline(
        holdout_folder="/kaggle/input/your-dataset-folder", 
        ps02_whitelist_file="/kaggle/input/your-whitelist-file.xlsx"
    )

# Run the async main function
# await main() 
```

## Troubleshooting

### FileNotFoundError

If you see errors like `FileNotFoundError: [Errno 2] No such file or directory`, it means the paths to your data files are incorrect.

1. **Use Absolute Paths**: Always use paths starting with `/`.
    * Input data (uploaded datasets): `/kaggle/input/...`
    * Repo data (cloned code): `/kaggle/working/phishing_ml/...`

2. **Find Your Files**: Run this snippet in a cell to locate your files:

    ```python
    import os
    print("Searching for xlsx files...")
    for root, dirs, files in os.walk("/kaggle"):
        for file in files:
            if file.endswith("CSEs.xlsx"):
                print("FOUND:", os.path.join(root, file))
    ```

3. **Missing `target_urls.txt`**:
    * You might see a warning: `WARNING - File not found: .../target_urls.txt`.
    * This is optional. You can safely ignore it, or create an empty file if it bothers you.
