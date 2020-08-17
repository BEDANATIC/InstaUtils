from abc import abstractmethod
from dataclasses import dataclass, asdict
from requests import request, Session
from tinydb import TinyDB, Query
import json
import time
import pickle
import logging
import random
import exceptions

format = '%(asctime)s %(funcName)s %(message)s'
date_format = '%d/%m/%Y %I:%M:%S %p'
logging.basicConfig(filename='logging.log', level=logging.DEBUG, format=format, datefmt= date_format)

def get_value_by_key(dictionary, target_node):
    result = None
    if isinstance(dictionary, dict):
        for key in dictionary:
            if key == target_node:
                result = dictionary[key]
            else:
                result = result or get_value_by_key(dictionary[key], target_node)
    return result

def get_value_list_by_key(structure, target_node):
    result = []
    if isinstance(structure, list):
        for el in structure:
            result.extend(get_value_list_by_key(el, target_node))
    elif isinstance(structure, dict):
        for key in structure:
            if key == target_node:
                result.append(structure[key])
            else:
                result.extend(get_value_list_by_key(structure[key], target_node))
    return result


@dataclass
class UserTransferObject():
    id: int = 0
    username: str = ''
    biography: str = ''
    business_category_name: str = ''
    full_name: str = ''
    blocked_by_viewer: bool = False
    followed_by_viewer: bool = False
    follows_viewer: bool = False
    external_url: str = ''
    has_channel: bool = False
    has_requested_viewer: bool = False
    requested_by_viewer: bool = False
    is_business_account: bool = False
    is_private: bool = False
    is_verified: bool = False
    profile_pic_url: str = ''
    followings_count: int = 0
    followers_count: int = 0
    mutual_users_count: int = 0
    posts_count: int = 0
 
    def __repr__(self):
        return f'<User: {self.username} with name "{self.full_name}">'


@dataclass
class PostTransferObject():
    id: int = 0
    shortcode: str = ''
    owner: str = ''
    caption: str = ''
    likes_count: int = 0
    comments_count: int = 0
    caption_is_edited: bool = False
    has_ranked_comments: bool = False
    taken_at_timestamp: str = ''
    viewer_has_liked: bool = False
    viewer_has_saved: bool = False
    viewer_can_reshare: bool = False
    gating_info: str = ''
    fact_check_overall_rating: any = ''
    fact_check_information: any = ''
    comments_disabled: bool = False
    is_ad: bool = False
    display_url: str = ''
    accessibility_caption: str = ''
    viewer_in_photo_of_you: bool = False

    def __repr__(self):
        return f'<Post with id {self.id}>'


@dataclass
class TagTransferObject():
    id: int = 0
    name: str = ''
    is_following: bool = False
    allow_following: bool = False
    count: int = 0
        
    def __repr__(self):
        return f'<{self.name} with id {self.id}>'


@dataclass
class LocationTransferObject():
    id: int = 0
    name: str = ''
    has_public_page: bool = False
    slug: str = ''
    website: str = ''
    blurb: str = ''
    phone: str = ''
    primary_alias_on_fb: str = ''
    lat: any = ''
    lng: any = ''
    street: str = ''
    zip_code: str = ''
    posts_count: int = 0
    country: str = ''
    city: str = ''
        
    def __repr__(self):
        return f'<{self.name} with id {self.id}>'


@dataclass
class CommentTransferObject():
    id: int = 0
    owner: str = ''
    text: str = ''
    created_at: str = ''
    viewer_has_liked: bool = False
    like_count: int = ''
 

@dataclass
class StoryTransferObject():
    id: int = 0
    can_reply: bool = False
    can_reshare: bool = False
    taken_at_timestamp: int = 0
    expiring_at_timestamp: int = 0
    display_url: str = ''


class InstaSession(Session):
    def __init__(self, username=None, password=None):
        super().__init__()
        logging.info('InstaSession initialized')
        self.__request_count = 0
        self.__last_request_time = time.time()
        self.__logged_user = None
        self.__create_default_session()
        logging.info('Default session created')

        if username and password is not None:
            self.login(username, password)
            self.__logged_user = username
            logging.info(f'{username} authenticated')

    def __create_default_session(self):
        default_headers = {
                'authority': 'www.instagram.com',
                'origin': 'https://www.instagram.com/',
                'x-ig-www-claim': 'hmac.AR36IPRJfr73424ue2ZSk-zrEPGPYMeS9MAmUUyHmWWBNp71',
                'x-instagram-ajax': 'a51d664a936c',
                'content-type': 'application/x-www-form-urlencoded',
                'accept': '*/*',
                'x-requested-with': 'XMLHttpRequest',
                'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 YaBrowser/19.12.3.332 (beta) Yowser/2.5 Safari/537.36',
                'x-csrftoken': '',
                'dnt': '1',
                'x-ig-app-id': '936619743392459',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-mode': 'cors',
                'referer': '',
                'accept-encoding': 'gzip, deflate, br',
                'accept-language': 'ru,en;q=0.9,la;q=0.8'
            }

        self.headers.update(default_headers)
        response = self.get('https://www.instagram.com/data/shared_data/')
        shared_data = json.loads(response.text)
        self.headers['x-csrftoken'] = shared_data['config']['csrf_token']

    def __ban_protection_trigger(self):
        self.__request_count += 1
        current_request_time = time.time()
        time_delta = (current_request_time - self.__last_request_time)

        timeout_per_request = 0.5
        if (time_delta < timeout_per_request):
            time.sleep(timeout_per_request - time_delta)
            logging.info('Sleeping by request')

        if (self.__request_count % random.randint(3, 6) == 0):
            time.sleep(random.randint(5, 10))
            logging.info('Sleeping by bigger')

        if (self.__request_count % 201 == 0):
            time.sleep(random.randint(10, 15))
            logging.info('Max sleep')

        self.__last_request_time = time.time()

    def request(self, method, url, **request_args):
        self.__ban_protection_trigger()
        response = super().request(method, url, **request_args)
        response.raise_for_status()
        return response

    def save_session(self, filename=''):
        with open(f"{filename or 'users'}_session.pkl", 'wb') as output_file:
            pickle.dump(self.__dict__, output_file)

    def load_session(self, filename=''):
        with open(f'{filename or "users"}_session.pkl', 'rb') as input_file:
            self.__dict__ = pickle.load(input_file)

    def get_logged_user(self):
        return self.__logged_user

    def login(self, username, password):
        auth_data = {
            'username': username,
            'password': password,
            'queryParams': '{"source":"private_profile"}',
            'optIntoOneTap': 'False'
        }
        response = self.post('https://www.instagram.com/accounts/login/ajax/', data=auth_data)
        logging.debug(response.text)
        response_json = json.loads(response.text)
        if response_json['authenticated'] == False:
            raise exceptions.InvalidLoginOrPassword(
                'Could not authenticate. Username or password is wrong')

    def logout(self):
        if self.get_logged_user != None:
            self.post('https://www.instagram.com/accounts/logout/ajax/')
            self.__create_default_session


class InstaDataSource():
    def __init__(self, session):
        self.__session = session
        logging.info('InstaDataSource initialized')

    def get_deserialized_json(self, url, params=None):
        response = self.__session.get(url, params=params)

        try:
            return json.loads(response.text)
        except AttributeError:
            return None

    def get_response_generator(self, query_hash, **variables):
        GRAPHQL_URL = 'https://instagram.com/graphql/query/'
        MAX_ENTITY_PER_REQUEST = 150
 
        has_next_page = True
        while has_next_page:
            variables['first'] = MAX_ENTITY_PER_REQUEST
            params = {'query_hash': query_hash, 'variables': json.dumps(variables)}
            response = self.get_deserialized_json(GRAPHQL_URL, params=params)
            variables['after'] = get_value_by_key(response, 'end_cursor')
            has_next_page = get_value_by_key(response, 'has_next_page')
            yield response

    def get_user(self, username):
        response = self.get_deserialized_json(f'https://instagram.com/{username}/?__a=1')
        user_info_node = response['graphql']['user']
        user_transfer_object = UserTransferObject(
            id=user_info_node['id'],
            username=user_info_node['username'],
            biography=user_info_node['biography'],
            business_category_name=user_info_node['business_category_name'],
            full_name=user_info_node['full_name'],
            blocked_by_viewer=user_info_node['blocked_by_viewer'],
            followed_by_viewer=user_info_node['followed_by_viewer'],
            follows_viewer=user_info_node['follows_viewer'],
            external_url=user_info_node['external_url'],
            has_channel=user_info_node['has_channel'],
            has_requested_viewer=user_info_node['has_requested_viewer'],
            requested_by_viewer=user_info_node['requested_by_viewer'],
            is_business_account=user_info_node['is_business_account'],
            is_private=user_info_node['is_private'],
            is_verified=user_info_node['is_verified'],
            profile_pic_url=user_info_node['profile_pic_url_hd'],
            followings_count=user_info_node['edge_follow']['count'],
            followers_count=user_info_node['edge_followed_by']['count'],
            mutual_users_count=user_info_node['edge_mutual_followed_by']['count'],
            posts_count=user_info_node['edge_owner_to_timeline_media']['count']
            )
        return user_transfer_object

    def get_media(self, shortcode):
        response = self.get_deserialized_json(f'https://instagram.com/p/{shortcode}/?__a=1')
        media_info_node = response['graphql']['shortcode_media']
        caption_node = media_info_node['edge_media_to_caption']['edges']
        caption = caption_node[0]['node']['text'] if (len(caption_node) > 0) else ""
        post_transfer_object = PostTransferObject(
            id=media_info_node['id'],
            shortcode=media_info_node['shortcode'],
            owner=media_info_node['owner']['username'],
            caption=caption,
            likes_count=media_info_node['edge_media_preview_like']['count'],
            comments_count=media_info_node['edge_media_preview_comment']['count'],
            caption_is_edited=media_info_node['caption_is_edited'],
            has_ranked_comments=media_info_node['has_ranked_comments'],
            taken_at_timestamp=media_info_node['taken_at_timestamp'],
            viewer_has_liked=media_info_node['viewer_has_liked'],
            viewer_has_saved=media_info_node['viewer_has_saved'],
            viewer_can_reshare=media_info_node['viewer_can_reshare'],
            gating_info=media_info_node['gating_info'],
            fact_check_overall_rating=media_info_node['fact_check_overall_rating'],
            fact_check_information=media_info_node['fact_check_information'],
            comments_disabled=media_info_node['comments_disabled'],
            is_ad=media_info_node['is_ad'],
            display_url=media_info_node['display_url'],
            viewer_in_photo_of_you=media_info_node['viewer_in_photo_of_you']
            )
        return post_transfer_object

    def get_tag(self, tagname):
        response = self.get_deserialized_json(f'https://instagram.com/explore/tags/{tagname}/?__a=1')
        tag_info_node = response['graphql']['hashtag']
        tag_transfer_object = TagTransferObject(
           name=tag_info_node['name'],
           is_following=tag_info_node['is_following'],
           allow_following=tag_info_node['allow_following'],
           count=tag_info_node['edge_hashtag_to_media']['count']
           )
        return tag_transfer_object

    def get_location(self, location_id):
        response = self.get_deserialized_json(f'https://instagram.com/explore/locations/{location_id}/?__a=1')
        location_info_node = response['graphql']['location']
        address_node = json.loads(location_info_node['address_json'])
        location_transfer_object = LocationTransferObject(
            id=location_info_node['id'],
            name=location_info_node['name'],
            has_public_page=location_info_node['has_public_page'],
            slug=location_info_node['slug'],
            website=location_info_node['website'],
            blurb=location_info_node['blurb'],
            phone=location_info_node['phone'],
            primary_alias_on_fb=location_info_node['primary_alias_on_fb'],
            lat=location_info_node['lat'],
            lng=location_info_node['lng'],
            street=address_node['street_address'],
            zip_code=address_node['zip_code'],
            posts_count=location_info_node['edge_location_to_media']['count'],
            country=location_info_node['directory']['country']['name'],
            city=location_info_node['directory']['city']['name']
            )
        return location_transfer_object

    def get_stories(self, user_id='', tag_name='', location_id='', highlight_id=''):
        prepared_variables = {
            "reel_ids":[user_id],
            "tag_names":[tag_name],
            "location_ids":[location_id],
            "highlight_reel_ids":[highlight_id],
            "precomposed_overlay":False,
            "show_story_viewer_list":True,
            "story_viewer_fetch_count":50,
            "story_viewer_cursor":"",
            "stories_video_dash_manifest":True
            }
        params = {
            'query_hash': 'f5dc1457da7a4d3f88762dae127e0238',
            'variables': json.loads(prepared_variables)
            }
        response = self.get_deserialized_json('https://www.instagram.com/graphql/query/', params=params)
        stories_info_nodes = response['data']['reels_media'][0]['items']
        stories = []
        for story_info_node in stories_info_nodes:
            story_transfer_object = StoryTransferObject(
                id=story_info_node['id'],
                can_reply=response['data']['reels_media']['can_reply'],
                can_reshare=response['data']['reels_media']['can_reshare'],
                taken_at_timestamp=story_info_node['taken_at_timestamp'],
                expiring_at_timestamp=story_info_node['expiring_at_timestamp'],
                display_url=story_info_node['display_url']
                )
            stories.append(story_transfer_object)
        return stories

    def get_comments(self, shortcode, count):
        query_hash = 'bc3296d1ce80a24b1b6e40b1e72903f5'
        response_generator = self.get_response_generator(query_hash, shortcode=shortcode)
        for response in response_generator:
            edges = response['data']['shortcode_media']['edge_media_to_parent_comment']['edges']
            comments = []
            for edge in edges: 
                comments.append(
                    CommentTransferObject(
                        id=edge['node']['id'],
                        text=edge['node']['text'],
                        created_at=edge['node']['created_at'],
                        viewer_has_liked=edge['node']['viewer_has_liked'],
                        like_count=edge['node']['edge_liked_by']['count'])
                )

            if len(comments) >= count:
                break
    
        return comments[:count]

    def get_followings_username(self, user_id, count):
        query_hash = 'd04b0a864b4b54837c0d870b0e77e076'
        response_generator = self.get_response_generator(query_hash, id=user_id)
        usernames = []
        for response in response_generator:
            edges = response['data']['user']['edge_follow']
            usernames.extend(get_value_list_by_key(edges, 'username'))
            if len(usernames) >= count:
                break

        return usernames[:count]
            
    def get_followers_username(self, user_id, count):
        query_hash = 'c76146de99bb02f6415203be841dd25a'
        response_generator = self.get_response_generator(query_hash, id=user_id)
        usernames = []
        for response in response_generator:
            edges = response['data']['user']['edge_followed_by']
            usernames.extend(get_value_list_by_key(edges, 'username'))
            if len(usernames) >= count:
                break

        return usernames[:count]
    
    def get_users_medias_shortcodes(self, user_id, count):
        query_hash = '9dcf6e1a98bc7f6e92953d5a61027b98'
        response_generator = self.get_response_generator(query_hash, id=user_id)
        shortcodes = []
        for response in response_generator:
            edges = response['data']['user']['edge_owner_to_timeline_media']['edges']
            shortcodes.extend(get_value_list_by_key(edges, 'shortcode'))
            if len(shortcodes) >= count:
                break
            
        return shortcodes[:count]

    def get_mentioned_medias_shortcodes(self, user_id, count):
        query_hash = 'ff260833edf142911047af6024eb634a'
        response_generator = self.get_response_generator(query_hash, id=user_id)
        shortcodes = []
        for response in response_generator:
            edges = response['data']['user']['edge_user_to_photos_of_you']
            shortcodes.extend(get_value_list_by_key(edges, 'shortcode'))
            if len(shortcodes) >= count:
                break

        return shortcodes[:count]

    def get_replies(self, comment_id, count):
        query_hash = "1ee91c32fc020d44158a3192eda98247"
        response_generator = self.get_response_generator(query_hash, id=comment_id)
        for response in response_generator:
            edges = response['data']['comment']['edge_threaded_comments']['edges']
            comments = []
            for edge in edges: 
                comments.append(
                    CommentTransferObject(
                        id=edge['node']['id'],
                        text=edge['node']['text'],
                        created_at=edge['node']['created_at'],
                        viewer_has_liked=edge['node']['viewer_has_liked'],
                        like_count=edge['node']['edge_liked_by']['count'])
                )

            if len(comments) >= count:
                break

        return comments[:count]

    def get_mutual_usernames(self, user_id):
        prepared_variables = {
            "id":user_id,
            "include_reel":True,
            "fetch_mutual":True,
            "first":150
            }
        params = {
            'query_hash': 'c76146de99bb02f6415203be841dd25a',
            'variables': json.loads(prepared_variables)
            }
        response = self.get_deserialized_json('https://www.instagram.com/graphql/query/', params=params)
        edges = response['data']['user']['edge_mutual_followed_by']
        return get_value_list_by_key(edges, 'username')

    def get_chaining_usernames(self, user_id):
        prepared_variables = {
            "user_id":user_id,
            "include_chaining":True,
            "include_reel":True,
            "include_suggested_users":True,
            "include_logged_out_extras":True,
            "include_highlight_reels":True,
            "include_related_profiles":True
            }
        params = {
            'query_hash': 'ad99dd9d3646cc3c0dda65debcd266a7',
            'variables': json.loads(prepared_variables)
            }
        response = self.get_deserialized_json('https://www.instagram.com/graphql/query/', params=params)
        edges = response['data']['user']['edge_chaining']
        return get_value_list_by_key(edges, 'username')

    def get_media_likers_usernames(self, shortcode, count):
        query_hash = 'd5d763b1e2acf209d62d22d184488e57'
        response_generator = self.get_response_generator(query_hash, shortcode=shortcode)
        usernames = []
        for response in response_generator:
            edges = response['data']['shortcode_media']['edge_liked_by']
            usernames.extend(get_value_list_by_key(edges, 'username'))
            if len(usernames) >= count:
                break

        return usernames[:count]

    def get_related_tagnames(self, tagname):
        response = self.get_deserialized_json(f'https://instagram.com/explore/tags/{tagname}/?__a=1')
        edges = response['graphql']['hashtag']['edge_hashtag_to_related_tags']['edges']
        return get_value_list_by_key(edges, 'name')

    def get_comment_likers_usernames(self, comment_id, count):
        query_hash = '5f0b1f6281e72053cbc07909c8d154ae'
        response_generator = self.get_response_generator(query_hash, id=comment_id)
        usernames = []
        for response in response_generator:
            edges = response['data']['comment']['edge_liked_by']
            usernames.extend(get_value_list_by_key(edges, 'username'))
            if len(usernames) >= count:
                break

        return usernames[:count]

    def get_recent_medias_shortcodes_from_tag(self, tagname, count):
        query_hash = '7dabc71d3e758b1ec19ffb85639e427b'
        response_generator = self.get_response_generator(query_hash, tag_name=tagname)
        shortcodes = []
        for response in response_generator:
            edges = response['data']['hashtag']['edge_hashtag_to_media']
            shortcodes.extend(get_value_list_by_key(edges, 'shortcode'))
            if len(shortcodes) >= count:
                break

        return shortcodes[:count]

    def get_recent_medias_shortcodes_from_location(self, location_id, count):
        query_hash = '36bd0f2bf5911908de389b8ceaa3be6d'
        response_generator = self.get_response_generator(query_hash, id=location_id)
        shortcodes = []
        for response in response_generator:
            edges = response['data']['location']['edge_location_to_media']
            shortcodes.extend(get_value_list_by_key(edges, 'shortcode'))
            if len(shortcodes) >= count:
                break

        return shortcodes[:count]

    def get_top_medias_shortcodes_from_tag(self, tagname):
        response = self.get_deserialized_json(f'https://instagram.com/explore/tags/{tagname}/?__a=1')
        edges = response['graphql']['hashtag']['edge_hashtag_to_top_posts']
        return get_value_list_by_key(edges, 'shortcode')

    def get_top_medias_shortcodes_from_location(self, location_id):
        response = self.get_deserialized_json(f'https://instagram.com/explore/locations/{location_id}/?__a=1')
        edges = response['graphql']['location']['edge_location_to_top_posts']
        return get_value_list_by_key(edges, 'shortcode')


class JSONDataSourceProxy():
    def __init__(self, data_source=None, filename=None):
        self.__data_source = data_source
        self.__db = TinyDB(filename or './parsed_data.json')
        self.__is_ge = lambda node, count: len(node) >= count-1
        logging.info('JSONDataSourceProxy initialized')

    def get_user(self, username):
        table = self.__db.table('users')
        user = table.get(Query().username==username)
        if user != None:
            user_transfer_object = UserTransferObject(**user)
            logging.debug(f'Get user({username}) from local storage')
        elif self.__data_source != None:
            user_transfer_object = self.__data_source.get_user(username)
            table.upsert(asdict(user_transfer_object), Query().username==username)
            logging.debug('Get user({username}) from external storage')
        else:
            user_transfer_object = None

        return user_transfer_object

    def get_followers_username(self, user_id, count):
        table = self.__db.table('followers')
        followers = table.get(Query()[user_id])
        usernames = followers[user_id] if (followers != None) else []
        if (len(usernames) < count) and (self.__data_source != None):
            usernames = self.__data_source.get_followers_username(user_id, count)
            table.upsert({user_id:usernames}, Query()[user_id])

        return usernames[:count]

    def get_followings_username(self, user_id, count):
        table = self.__db.table('followings')
        followings = table.get(Query()[user_id])
        usernames = followings[user_id] if (followings != None) else []
        if (len(usernames) < count) and (self.__data_source != None):
            usernames = self.__data_source.get_followings_username(user_id, count)
            table.upsert({user_id:usernames}, Query()[user_id])

        return usernames[:count]

    def get_users_medias_shortcodes(self, user_id, count):
        table = self.__db.table('user_posts')
        user_posts = table.get(Query()[user_id])
        shortcodes = user_posts[user_id] if (user_posts != None) else []
        if (len(user_posts) < count) and (self.__data_source != None):
            shortcodes = self.__data_source.get_users_medias_shortcodes(user_id, count)
            table.upsert({user_id:shortcodes}, Query()[user_id])

        return shortcodes[:count]

    def get_mentioned_medias_shortcodes(self, user_id, count):
        table = self.__db.table('tagged_posts')
        tagged_posts = table.get(Query()[user_id])
        shortcodes = tagged_posts[user_id] if (tagged_posts != None) else []
        if (len(shortcodes) < count) and (self.__data_source != None):
            shortcodes = self.__data_source.get_mentioned_posts(user_id, count)
            table.upsert({user_id:shortcodes}, Query()[user_id])

        return shortcodes[:count]

    def get_mutual_usernames(self, user_id, count):
        table = self.__db.table('mutuals')
        mutuals = table.get(Query()[user_id])
        usernames = mutuals[user_id] if (mutuals != None) else []
        if (len(usernames) < count) and (self.__data_source != None):
            usernames = self.__data_source.get_mutual_usernames(user_id, count)
            table.upsert({user_id:usernames}, Query()[user_id])

        return usernames[:count]

    def get_chaining_usernames(self, user_id):
        table = self.__db.table('chainings')
        chainings = table.get(Query()[user_id])
        usernames = chainings[user_id] if (chainings != None) else []
        if (len(usernames) == 0) and (self.__data_source != None):
            usernames = self.__data_source.get_chaining_usernames(user_id)
            table.upsert({user_id:usernames}, Query()[user_id])

        return usernames

    def get_media(self, shortcode):
        table = self.__db.table('posts')
        post_info = table.get(Query().shortcode==shortcode)
        if post_info != None:
            post_transfer_object = PostTransferObject(**post_info)
        elif self.__data_source != None:
            post_transfer_object = self.__data_source.get_media(shortcode)
            table.upsert(asdict(post_transfer_object), Query().shortcode==shortcode)
        else:
            post_transfer_object = None

        return post_transfer_object

    def get_comments(self, shortcode, count):
        table = self.__db.table('comment_post')
        comment_post = table.get(Query()[shortcode])
        comments = comment_post[shortcode] if (comment_post != None) else []
        if (len(comments) < count) and (self.__data_source != None):
            comment_transfer_objects = self.__data_source.get_comments(shortcode, count)
            comments = [asdict(comment) for comment in comment_transfer_objects]
            table.upsert({shortcode:comments}, Query()[shortcode])
        else:
            comment_transfer_objects = [CommentTransferObject(**comment) for comment in comments[:count]]

        return comment_transfer_objects

    def get_media_likers_usernames(self, shortcode, count):
        table = self.__db.table('post_likes')
        post_likes = table.get(Query()[shortcode])
        usernames = post_likes[shortcode] if (post_likes != None) else []
        if (len(usernames) < count) and (self.__data_source != None):
            usernames = self.__data_source.get_media_likers_usernames(shortcode, count)
            table.upsert({shortcode:usernames}, Query()[shortcode])

        return usernames[:count]

    def get_tag(self, tagname):
        table = self.__db.table('tags')
        tag = table.get(Query().name==tagname)
        if tag != None:
            tag_transfer_object = TagTransferObject(**tag)
        elif self.__data_source != None:
            tag_transfer_object = self.__data_source.get_tag(tagname)
            table.upsert(asdict(tag_transfer_object), Query().name==tagname)
        else:
            tag_transfer_object = None

        return tag_transfer_object

    def get_top_medias_shortcodes_from_tag(self, tagname):
        table = self.__db.table('top_tag_post')
        top_tag_post = table.get(Query()[tagname])
        shortcodes = top_tag_post[tagname] if (top_tag_post != None) else []
        if (len(shortcodes) == 0) and (self.__data_source != None):
            shortcodes = self.__data_source.get_top_medias_shortcodes_from_tag(tagname)
            table.upsert({tagname:shortcodes}, Query()[tagname])

        return shortcodes

    def get_related_tagnames(self, tagname):
        table = self.__db.table('related_tags')
        related_tags = table.get(Query()[tagname])
        tagnames = related_tags[tagname] if (related_tags != None) else []
        if (len(tagnames) == 0) and (self.__data_source != None):
            tagnames = self.__data_source.get_related_tagnames(tagname)
            table.upsert({tagname:tagnames}, Query()[tagname])

        return tagnames

    def get_recent_medias_shortcodes_from_tag(self, tagname, count):
        table = self.__db.table('recent_post_tag')
        recent_post_tag = table.get(Query()[tagname])
        shortcodes = recent_post_tag[tagname]
        if (len(shortcodes) < count) and (self.__data_source != None):
            shortcodes = self.__data_source.get_recent_medias_shortcodes_from_tag(tagname, count)
            table.upsert({tagname:shortcodes}, Query()[tagname])

        return shortcodes[:count]

    def get_location(self, location_id):
        table = self.__db.table('locations')
        location = table.get(Query().id==location_id)
        if location != None:
            location_transfer_object = LocationTransferObject(**location)
        elif self.__data_source != None:
            location_transfer_object = self.__data_source.get_location(location_id)
            table.upsert(asdict(location_transfer_object), Query().id==location_id)
        else:
            location_transfer_object = None

        return location_transfer_object

    def get_top_medias_shortcodes_from_location(self, location_id):
        table = self.__db.table('top_location_post')
        top_location_post = table.get(Query()[location_id])
        shortcodes = top_location_post[location_id] if (top_location_post != None) else [] 
        if (len(shortcodes) == 0) and (self.__data_source != None):
            shortcodes = self.__data_source.get_top_medias_shortcodes_from_location(location_id)
            table.upsert({location_id:shortcodes}, Query()[location_id])

        return shortcodes

    def get_recent_medias_shortcodes_from_location(self, location_id, count):
        table = self.__db.table('recent_post_location')
        recent_post_location = table.get(Query()[location_id])
        shortcodes = recent_post_location[location_id] if (recent_post_location != None) else []
        if (len(shortcodes) < count) and (self.__data_source != None):
            shortcodes = self.__data_source.get_recent_medias_shortcodes_from_location(location_id, count)
            table.upsert({location_id:shortcodes}, Query()[location_id])

        return shortcodes[:count]

    def get_replies(self, comment_id, count):
        table = self.__db.table('comment_reply')
        comment_reply = table.get(Query()[comment_id])
        comments = comment_reply[comment_id] if (comment_reply != None) else []
        if (len(comments) < count) and (self.__data_source != None):
            comment_transfer_objects = self.__data_source.get_replies(comment_id, count)
            comments = [asdict(comment) for comment in comment_transfer_objects]
            table.upsert({comment_id:comments}, Query()[comment_id])
        else:
            comment_transfer_objects = [CommentTransferObject(**comment) for comment in comments[:count]]

        return comment_transfer_objects

    def get_comment_likers_usernames(self, comment_id, count):
        table = self.__db.table('comment_likes')
        comment_likes = table.get(Query()[comment_id])
        usernames = comment_likes[comment_id] if (comment_likes != None) else []
        if (len(usernames) < count) and (self.__data_source != None):
            usernames = self.__data_source.get_comment_likers_usernames(comment_id, count)
            table.upsert({comment_id:usernames}, Query()[comment_id])

        return usernames[:count]


class InstaAction():
    def __init__(self, session):
        self.__session = session
        logging.info('InstaAction initialized')

    def like(self, post):
        self.__session.post('https://instagram.com/web/likes/{shorcode}/like/')

    def unlike(self, post):
        self.__session.post('https://instagram.com/web/likes/{media_id}/unlike/')

    def add_to_bookmark(self, post):
        self.__session.post('https://instagram.com/web/save/{media_id}/save/')

    def follow(self, user):
        self.__session.post('https://instagram.com/web/friendships/{user_id}/follow/')

    def unfollow(self, user):
        self.__session.post('https://instagram.com/web/friendships/{user_id}/unfollow/')

    def leave_comment(self, post, comment_text):
        self.__session.post('https://instagram.com/web/comments/{media_id}/add/')

    def download_media(self, url):
        with open(''+url[25:]+'.jpg', 'wb') as handle:
            response = self.__session.get(url)
    
            if response.ok:
                for block in response.iter_content(1024):
                    handle.write(block)
            else:
                print(response)

    def restrict(self, user_id):
        self.__session.post('https://www.instagram.com/web/restrict_action/restrict/', params={'target_user_id':user_id})

    def unrestrict(self, user_id):
        self.__session.post('https://www.instagram.com/web/restrict_action/unrestrict/', params={'target_user_id':user_id})

    def delete_post(self, post_id):
        self.__session.post(f'https://www.instagram.com/create/{post_id}/delete/')

    def edit_profile(self, firstname=None, email=None, username=None, 
                    phone_number=None, biography=None, external_url=None, chainig_enabled=None):
        params = {
            'first_name': firstname,
            'email': email,
            'username': username,
            'phone_number': phone_number,
            'biography': biography,
            'external_url': external_url,
            'chaining_enabled': chainig_enabled}

        self.__session.get('https://www.instagram.com/accounts/edit/', params=params)
 