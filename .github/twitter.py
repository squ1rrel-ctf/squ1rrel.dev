import tweepy
import requests
import xml.etree.ElementTree as ET
import os
import sys

def main():
    client = tweepy.Client(
        consumer_key=os.environ("API_KEY"),
        consumer_secret=os.environ("SECRET_KEY"),
        access_token=os.environ("ACCESS_TOKEN"),
        access_token_secret=os.environ("ACCESS_SECRET")
    )

    previous_atom = requests.get("https://squ1rrel.dev/atom.xml", allow_redirects=True).text
    prev_links_to_items = {i.find("link").text.strip(): i for i in ET.fromstring(previous_atom)[0].findall('item')}
    current_links_to_items = {i.find("link").text.strip(): i for i in ET.parse('_site/atom.xml').getroot()[0].findall('item')}

    new_articles = { k : current_links_to_items[k] for k in set(current_links_to_items) - set(prev_links_to_items) }

    if len(new_articles) > 0:
        if len(new_articles) == 1:
            link = list(new_articles.keys())[0]
            author = list(new_articles.values())[0].find("author").find("name").text
            tag = list(new_articles.values())[0].findall("category")[1].attrib['term'].replace(" ", "")
            ctf = list(new_articles.values())[0].findall("category")[0].attrib['term'].replace(" ", "")
            client.create_tweet(text=f'New #{tag} writeup from {author}! #{ctf}\nhttps://squ1rrel.dev{link}')
        else:
            for i in list(new_articles.keys()):
                link = i
                author = new_articles[i].find("author").find("name").text
                tag = new_articles[i].findall("category")[1].attrib['term'].replace(" ", "")
                ctf = new_articles[i].findall("category")[0].attrib['term'].replace(" ", "")
                client.create_tweet(text=f'New #{tag} writeup from {author}! #{ctf}\nhttps://squ1rrel.dev{i}')

if __name__== "__main__":
    main()
