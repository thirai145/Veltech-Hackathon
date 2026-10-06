import re

with open("script.js", "r", encoding="utf-8") as f:
    content = f.read()

pattern = re.compile(r"document\.getElementById\('custom-google-btn'\)\.addEventListener\('click', \(\) => \{\s*if \(codeClient\) \{\s*codeClient\.requestCode\(\);\s*\}\s*\}\);", re.DOTALL)
replacement = """document.getElementById('custom-google-btn').addEventListener('click', () => {
    handleGoogleAuthCode({code: "dummy_code"});
  });"""

new_content = pattern.sub(replacement, content)

with open("script.js", "w", encoding="utf-8") as f:
    f.write(new_content)
