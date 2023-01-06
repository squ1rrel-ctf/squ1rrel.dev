import tweepy
import requests
import xml.etree.ElementTree as ET
import os

print(os.environ)

def main():
    client = tweepy.Client(
        consumer_key=os.getenv("API_KEY"),
        consumer_secret=os.getenv("SECRET_KEY"),
        access_token=os.getenv("ACCESS_TOKEN"),
        access_token_secret=os.getenv("ACCESS_SECRET")
    )

    previous_atom = requests.get("https://squ1rrel.dev/atom.xml", allow_redirects=True).text
    previous_links = [i.find("link").text.strip() for i in ET.fromstring(previous_atom)[0].findall('item')]
    current_links = [i.find("link").text.strip() for i in ET.parse('_site/atom.xml').getroot()[0].findall('item')]

    new_articles = list(set(current_links) - set(previous_links))

    if len(new_articles) > 0:
        if len(new_articles) == 1:
            tweet_text = f'New writeup!\nhttps://squ1rrel.dev{new_articles[0]}'
        else:
            tweet_text = "New writeups!"
            for i in new_articles:
                tweet_text += "\nhttps://squ1rrel.dev" + i
        if len(tweet_text) > 280:
            tweet_text = "New writeups at https://squ1rrel.dev!"
        client.create_tweet(text=tweet_text)

if __name__== "__main__":
    main()
