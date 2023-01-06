import tweepy
import requests
import xml.etree.ElementTree as ET
import os
import sys
from dotenv import load_dotenv

load_dotenv()

def main():
    client = tweepy.Client(
        consumer_key=os.getenv("API_KEY"),
        consumer_secret=os.getenv("SECRET_KEY"),
        access_token=os.getenv("ACCESS_TOKEN"),
        access_token_secret=os.getenv("ACCESS_SECRET")
    )

    previous_atom = requests.get("https://squ1rrel.dev/atom.xml", allow_redirects=True).text
    try:
        prev_links_to_items = {i.find("link").text.strip(): i for i in ET.fromstring(previous_atom)[0].findall('item')}
        current_links_to_items = {i.find("link").text.strip(): i for i in ET.parse('_site/atom.xml').getroot()[0].findall('item')}
    except AttributeError as inst:
        print("Field missing: ", inst)
        sys.exit(1)

    new_articles = { k : current_links_to_items[k] for k in set(current_links_to_items) - set(prev_links_to_items) }

    if len(new_articles) > 0:
        if len(new_articles) == 1:
            try:
                link = list(new_articles.keys())[0]
                author = list(new_articles.values())[0].find("author").find("name").text
                tag = list(new_articles.values())[0].findall("category")[1].attrib['term']
                client.create_tweet(text=f'New {tag} writeup from {author}!\nhttps://squ1rrel.dev{link}')
            except AttributeError as inst:
                    print("Field missing: ", inst)
                    sys.exit(1)
            except Exception as inst:
                print(f"Tweet for {list(new_articles.keys())[0]} not posted: {inst}")
        else:
            tweet_text = "New writeup!"
            for i in list(new_articles.keys()):
                try:
                    link = i
                    author = new_articles[i].find("author").find("name").text
                    tag = new_articles[i].findall("category")[1].attrib['term']
                    client.create_tweet(text=f'New {tag} writeup from {author}!\nhttps://squ1rrel.dev{i}')
                except AttributeError as inst:
                    print("Field missing: ", inst)
                    sys.exit(1)
                except Exception as inst:
                    print(f"Tweet for {i} not posted: {inst} {type(inst)}")

if __name__== "__main__":
    main()
