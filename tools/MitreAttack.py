from bs4 import BeautifulSoup
import requests
    
def get_techinique_infos(techinique_id: str) -> dict[str, str]:

    techinique_id = techinique_id.upper()
    techinique_url = f"https://attack.mitre.org/techniques/{techinique_id.replace('.', '/')}"

    resp = requests.get(techinique_url)

    if resp.status_code != 200:
        return None

    soup = BeautifulSoup(resp.content, "html.parser")
    title = soup.find("h1", {"class": ""}).text

    title = " ".join(title.replace("\n", "").split())
    
    tactics = []
    for tactic in soup.find("div", {"id": "card-tactics"}).find_all("a"):
        tactics.append(
            {
                "name": tactic.text,
                "reference": f'https://attack.mitre.org/tactics{tactic["href"]}',
                "id": tactic["href"].split("/")[-1]
            }
        )

    return {
        "id": techinique_id,
        "name": title,
        "reference": techinique_url,
        "tactics": tactics
    }
