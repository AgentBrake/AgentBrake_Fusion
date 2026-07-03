from pathlib import Path


def check(repo):
    text = Path(repo, 'src/login.js').read_text()
    return 'button.onclick = () => submit();' in text
