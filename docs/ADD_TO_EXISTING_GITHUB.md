# Add this three-week project to your EXISTING local repository

Your cloned GitHub repository already exists. **Do not run `git init` again.**
Do not replace or delete its `.git` directory or `LICENSE`.

1. In Git Bash:

   ```bash
   cd ~/Documents/GitHub/aws-cloudformation-security-scanner
   pwd
   git status
   git remote -v
   ```

2. Download and extract the ZIP OUTSIDE your repository (e.g. Downloads).
   Open the extracted `aws-cfn-weeks-1-3` folder and COPY ITS CONTENTS into
   the existing repository folder using Windows File Explorer.
   **Do not copy the extracted folder as an extra nested folder.**
   If your repository has an existing nonempty `scanner/parser.py`,
   `tests/test_parser.py`, `README.md` or `.gitignore`, first compare and back
   up your own changes. You can merge the documentation instead of overwriting.
   Never copy a `.git` directory from anywhere else.

3. In Git Bash, still inside your repository:

   ```bash
   ls scanner tests samples docs
   git status
   ```

4. Install and run locally before uploading anything:

   ```bash
   py -m venv .venv
   ./.venv/Scripts/python.exe -m pip install -r requirements.txt
   ./.venv/Scripts/python.exe -m pytest -q
   ./.venv/Scripts/python.exe -m scanner samples/02_insecure_ssh.yaml
   ```

   The insecure sample intentionally exits with code 1 to signal a detected
   violation; that does not mean the application crashed.

5. Only after checking file changes and tests:

   ```bash
   git status
   git add scanner tests samples docs requirements.txt README.md .gitignore
   git diff --cached --stat
   git commit -m "Add weeks 1-3 CloudFormation parser and SSH rule prototype"
   git push -u origin main
   ```

   Review `git diff --cached` before committing to ensure no secrets or local
   environments are being tracked. If an existing README or `.gitignore` was
   intentionally left unchanged, the add command still works.

## A note about your thesis

This package is a **generated starting point**. Learn, test, and independently
improve it; do not fabricate weekly commits or represent generated source as
solely authored by you. Academic policies may require acknowledgement of AI
assistance. Genuine development history comes from the improvements you make.
