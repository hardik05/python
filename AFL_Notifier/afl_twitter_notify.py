#AFL twitter notifier -> sends a DM on specified twitter account when
#a new crash or new hang is found.
#it monitors the directory and checks for new file at specified intervals
#hardik shah, hardik05.wordpress.com

import os, time,twitter,json


# Load credentials from json file
with open("settings.json", "r") as file:
    creds = json.load(file)

consumer_key = creds['CONSUMER_KEY']  
consumer_secret = creds['CONSUMER_SECRET']
access_token_key = creds['ACCESS_TOKEN']
access_token_secret = creds['ACCESS_SECRET']
#afl specific settings
crash_path_to_watch = creds['CRASH_PATH']
hang_path_to_watch = creds['HANG_PATH'] 
#script settings
mon_time = int(creds['MONITOR_TIME']) 
#twitter handle you want to receive DMs.
twitter_handle = creds['TWITTER_HANDLE'] 


crash_before = dict ([(f, None) for f in os.listdir (crash_path_to_watch)])
hang_before = dict ([(f, None) for f in os.listdir (hang_path_to_watch)])
ping_time = 3600
check_time = 0
api = twitter.Api(
    consumer_key=consumer_key,
    consumer_secret=consumer_secret,
    access_token_key=access_token_key,
    access_token_secret=access_token_secret)

while 1:
  check_time = check_time + 10
  time.sleep (mon_time)
  crash_after = dict ([(f, None) for f in os.listdir (crash_path_to_watch)])
  hang_after = dict ([(f, None) for f in os.listdir (hang_path_to_watch)])

  crash_added = [f for f in crash_after if not f in crash_before]
  hang_added = [f for f in hang_after if not f in hang_before]
  
  if crash_added:
    print "new crash found: ", ", ".join (crash_added)
    # Get current time
    t = time.strftime("%d-%m-%Y %H:%M:%S", time.localtime())
    msg = "Alert !! new unique crash detected at " + t

    # Send Direct Message to official Twitter handle
    try:
        send_msg = api.PostDirectMessage(msg, user_id=None, screen_name=twitter_handle)
    except:
        print "couldn't send message"
  if hang_added:
    print "new hang found: ", ", ".join (hang_added)
    # Get current time
    t = time.strftime("%d-%m-%Y %H:%M:%S", time.localtime())
    msg = "Alert !! new unique hang detected at " + t

    # Send Direct Message to official Twitter handle
    try:
        send_msg = api.PostDirectMessage(msg, user_id=None, screen_name=twitter_handle)
    except:
        print "couldn't send message"
	  if check_time == 3600:
      t = time.strftime("%d-%m-%Y %H:%M:%S", time.localtime())
      msg = "ping pong: " + t
      check_time = 0
      # Send Direct Message to official Twitter handle
      try:
        send_msg = api.PostDirectMessage(msg, user_id=None, screen_name=twitter_handle)
      except:
        print "couldn't send message"
  crash_before = crash_after
  hang_before = hang_after
