import tweepy
import requests
import xml.etree.ElementTree as ET
import os


def main():
    # Set up Twitter client
    client = tweepy.Client(
        consumer_key=os.environ["API_KEY"],
        consumer_secret=os.environ["SECRET_KEY"],
        access_token=os.environ["ACCESS_TOKEN"],
        access_token_secret=os.environ["ACCESS_SECRET"],
    )

    # Get XML tree of previous site to get articles published previously
    previous_atom = requests.get(
        "https://squ1rrel.dev/atom.xml", allow_redirects=True
    ).text
    # Get links of previos sites (example: "/graphql-bash")
    # This key will map to the value that is the item in the XML tree
    prev_links_to_items = {
        i.find("link").text.strip(): i
        for i in ET.fromstring(previous_atom)[0].findall("item")
    }

    # Get links of current sites (including new sites)
    # This key will map to the value that is the item in the XML tree
    current_links_to_items = {
        i.find("link").text.strip(): i
        for i in ET.parse("_site/atom.xml").getroot()[0].findall("item")
    }

    # Get a dictionary of items that are present in current articles, but not in previous articles
    # The key is the link (ex, "/graphql-bash") and the value is the item in the XML tree
    # ie, find all new articles
    new_articles = {
        k: current_links_to_items[k]
        for k in set(current_links_to_items) - set(prev_links_to_items)
    }

    # Tweet new articles!
    for link, article in new_articles.items():
        author = article.find("author").find("name").text
        tag = article.findall("category")[1].attrib["term"]
        ctf = article.findall("category")[0].attrib["term"]
        # Create tweet
        client.create_tweet(
            text=f'New {tag} writeup from {ctf} by {author}! \nhttps://squ1rrel.dev{link} #{tag.replace(" ", "")} #{ctf.replace(" ", "")}'
        )


if __name__ == "__main__":
    main()
