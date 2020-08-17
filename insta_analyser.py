import pandas as pd
import numpy as np
import re
import json
import datetime
from instagram_parser import *

session = InstaSession()
session.load_session('bedanatic')
data_source = JSONDataSourceProxy(InstaDataSource(session))
insta_action = InstaAction(session)

def get_who_not_follow_user(username):
    user = data_source.get_user(username)
    followings = data_source.get_followings_username(user.id, user.followings_count)
    followers = data_source.get_followers_username(user.id, user.followers_count)
    res = set(followings) - set(followers)
    [print(u) for u in res]
    return res

def get_followers_who_dont_like_last_posts(username, last_posts_count):
    user = data_source.get_user(username)
    followers = data_source.get_followers_username(user.id, user.followers_count)
    shortcodes = data_source.get_users_medias_shortcodes(user.id, last_posts_count)
    likers = []
    for shortcode in shortcodes:
        likers.extend(data_source.get_media_likers_usernames(shortcode, 500))

    return set(followers) - set(likers)

def get_extract_tagnames(caption):
    reg = re.compile('#[a-zA-Z0-9_а-яА-Я.]+')
    return reg.findall(caption)

def get_related_tag_by_recently_used(username, last_posts_count):
    user = data_source.get_user(username)
    shortcodes = data_source.get_users_medias_shortcodes(user.id, last_posts_count)
    posts = [data_source.get_media(shortcode) for shortcode in shortcodes]
    used_tagnames = set()
    for post in posts:
        used_tagnames.update(extract_tagnames(post.caption))
    
    tags_relations = {}
    for tagname in used_tagnames:
        tag = data_source.get_tag(tagname[1:])
        tags_relations['#'+tag.name] = {'count':tag.count, 'similars':[]}
        similar_tagnames = data_source.get_related_tagnames(tag.name)
        similar_tags = [data_source.get_tag(similar_tagname) for similar_tagname in similar_tagnames]
        for similar_tag in similar_tags:
            tags_relations[tag.name]['similars'].append({'tag':'#'+similar_tag.name, 'count':similar_tag.count})
    return tags_relations

class UsersFollowersDump():
    def __init__(self, owner_username, followers):
        self.date_of_create = datetime.datetime.now()
        self.owner_username = owner_username
        self.followers = followers

    def get_unfollowers(self, new_dump):
        return set(self.followers) - set(old_dump.follower)

    def get_new_followers(self, new_dump):
        return set(old_dump.follower) - set(self.followers)
